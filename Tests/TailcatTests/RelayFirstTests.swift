import XCTest
@testable import Tailcat

#if canImport(Glibc)
private actor DiscoveryGate {
    private var blocked = true
    private var waiters = [CheckedContinuation<Void, Never>]()
    private(set) var calls = 0
    func wait() async {
        calls += 1
        if blocked { await withCheckedContinuation { waiters.append($0) } }
    }
    func release() {
        blocked = false
        let pending = waiters; waiters.removeAll()
        for waiter in pending { waiter.resume() }
    }
    func block() { blocked = true }
}

private actor SocketCapture {
    private(set) var socket: UDPChannel?
    private(set) var sockets = [UDPChannel]()
    func set(_ value: UDPChannel) { socket = value; sockets.append(value) }
}

private final class DiscoveryPacketFilter: @unchecked Sendable {
    private let lock = NSLock()
    private var blocked = false
    func setBlocked(_ value: Bool) { lock.lock(); blocked = value; lock.unlock() }
    func drops(_ packet: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return blocked && Discovery.isPacket(packet)
    }
}

final class RelayFirstTests: XCTestCase {
    private func within<T: Sendable>(_ seconds: Double = 10, _ operation: @escaping @Sendable () async throws -> T) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask { try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000)); throw TailcatError.timedOut }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    private func eventually(_ predicate: @escaping @Sendable () async -> Bool) async throws {
        try await within {
            while !(await predicate()) { try await Task.sleep(nanoseconds: 20_000_000) }
        }
    }

    private func gatedDiscovery(_ gate: DiscoveryGate, base: DirectDiscovery? = nil) -> DirectDiscovery {
        var discovery = base ?? loopbackDiscovery()
        discovery.open = { receive in
            await gate.wait()
            return try UDPChannel(receive: receive)
        }
        return discovery
    }

    private func loopbackDiscovery() -> DirectDiscovery {
        var discovery = DirectDiscovery()
        // Keep fixtures independent of the host's VPN/container interface count.
        discovery.interfaces = { [DiscoveryEndpoint(host: "127.0.0.1", port: $0.port)] }
        return discovery
    }

    private func exchange(_ client: TailcatConnection, _ server: TailcatConnection, _ text: String) async throws {
        try await within {
            let data = Data(text.utf8)
            try await client.write(data)
            let received = try await server.read()
            XCTAssertEqual(received, data)
            try await server.write(received)
            let response = try await client.read()
            XCTAssertEqual(response, data)
        }
    }

    func testRelayFirstClientWithDefaultServerPreservesEncryptedStream() async throws {
        try await exerciseStream(relayFirstServer: false)
    }

    func testRelayFirstServerWithDefaultClientPreservesEncryptedStream() async throws {
        try await exerciseStream(relayFirstServer: true)
    }

    func testMultipleCandidatesKeepStreamUsableDuringDiscovery() async throws {
        var discovery = loopbackDiscovery()
        discovery.interfaces = { socket in
            ["127.0.0.1", "::1", "127.0.0.2", "127.0.0.3"].map { DiscoveryEndpoint(host: $0, port: socket.port) }
        }
        try await exerciseStream(relayFirstServer: false, discovery: discovery)
    }

    func testHostInterfacesStreamSmoke() async throws {
        guard ProcessInfo.processInfo.environment["TAILCAT_TEST_HOST_INTERFACES"] == "1" else {
            throw XCTSkip("Set TAILCAT_TEST_HOST_INTERFACES=1 for the host VPN/container interface smoke test")
        }
        try await exerciseStream(relayFirstServer: false, discovery: DirectDiscovery())
    }

    private func exerciseStream(relayFirstServer: Bool, discovery supplied: DirectDiscovery? = nil) async throws {
        let fixture = try LocalRelay()
        defer { fixture.close() }
        let gate = DiscoveryGate()
        let discovery = supplied ?? loopbackDiscovery()
        var serverConfiguration = TailcatServer.Configuration()
        serverConfiguration.directDiscovery = discovery
        serverConfiguration.region = DERPRegion(regionID: 1, nodes: [fixture.node])
        serverConfiguration.relayFirst = relayFirstServer
        if relayFirstServer { serverConfiguration.directDiscovery = gatedDiscovery(gate, base: discovery) }
        let server = TailcatServer(configuration: serverConfiguration)
        var client: TailcatClient?
        var stage = "startup"
        do {
            let listener = try await within { try await server.listen(port: 8080) }
            let address = try await server.address
            var clientConfiguration = TailcatClient.Configuration()
            clientConfiguration.directDiscovery = discovery
            clientConfiguration.relayFirst = !relayFirstServer
            if !relayFirstServer { clientConfiguration.directDiscovery = gatedDiscovery(gate, base: discovery) }
            let config = clientConfiguration
            let connected = try await within { try await TailcatClient.connect(to: address, configuration: config) }
            client = connected
            let initialPath = await connected.path
            XCTAssertEqual(initialPath, .relay)
            let stream = try await within { try await connected.openTCP(port: 8080) }
            let accepted = try await within { try await listener.accept() }
            try await exchange(stream, accepted, "encrypted before UDP discovery returns")
            let calls = await gate.calls
            XCTAssertEqual(calls, 1)

            await gate.release()
            stage = "first direct upgrade"
            try await within(15) {
                var consecutiveDirect = 0
                while consecutiveDirect < 20 {
                    try await self.exchange(stream, accepted, "continuous traffic during initial promotion")
                    if case .direct = await connected.path,
                       case .direct = try? await server.path(to: connected.publicKey) {
                        consecutiveDirect += 1
                    } else { consecutiveDirect = 0 }
                    try await Task.sleep(nanoseconds: 50_000_000)
                }
            }
            let oldPath = await connected.path
            stage = "direct traffic and voluntary reprobe"
            try await exchange(stream, accepted, "same TCP stream after direct upgrade")
            await connected.retryDirect()
            await server.retryDirect(to: connected.publicKey)
            let afterRetry = await connected.path
            XCTAssertEqual(afterRetry, oldPath, "Voluntary reprobe must not discard the live path")

            fixture.setAvailable(false)
            stage = "relay outage while direct"
            try await exchange(stream, accepted, "direct works while DERP is unavailable")
            fixture.setAvailable(true)

            await gate.block()
            stage = "network change"
            await connected.notifyNetworkChanged()
            await server.notifyNetworkChanged()
            let resetPath = await connected.path
            XCTAssertEqual(resetPath, .relay)
            try await exchange(stream, accepted, "same encrypted stream after socket invalidation")
            fixture.dropConnections()
            stage = "relay reconnect"
            try await exchange(stream, accepted, "same encrypted stream after DERP reconnect")
            await gate.release()
            stage = "new network direct upgrade"
            try await eventually {
                if case .direct = await connected.path { return true }; return false
            }
            try await exchange(stream, accepted, "same TCP stream after new network upgrade")
            stage = "one-sided socket rebind"
            await connected.notifyNetworkChanged()
            try await exchange(stream, accepted, "same TCP stream after only the client changes networks")
            await connected.close(); await server.close()
        } catch {
            XCTFail("Failed during \(stage): \(error)")
            await gate.release(); await client?.close(); await server.close(); throw error
        }
    }

    func testDefaultStillWaitsForUDPButRelayFirstDoesNot() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let gate = DiscoveryGate()
        let transport = NetworkTransport(privateKey: NaClBox.random(32), discoPrivateKey: NaClBox.random(32),
                                         relayNodes: [fixture.node], relayFirst: false, discovery: gatedDiscovery(gate))
        let started = expectation(description: "default start waits for UDP")
        started.isInverted = true
        let pending = Task { try await transport.start(); started.fulfill() }
        try await eventually { await gate.calls == 1 }
        await fulfillment(of: [started], timeout: 0.1)
        // Close never waits for an uninterruptible OS discovery operation.
        await transport.close()
        await gate.release()
        do { try await pending.value; XCTFail("Closed startup succeeded") } catch {}
    }

    func testNetworkChangesCoalesceAndRejectLateSocketAfterClose() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let gate = DiscoveryGate()
        let transport = NetworkTransport(privateKey: NaClBox.random(32), discoPrivateKey: NaClBox.random(32),
                                         relayNodes: [fixture.node], relayFirst: true, discovery: gatedDiscovery(gate))
        try await within { try await transport.start() }
        try await eventually { await gate.calls == 1 }
        for _ in 0..<100 {
            await transport.notifyNetworkChanged()
            await transport.retryDirect()
        }
        let calls = await gate.calls
        XCTAssertEqual(calls, 1, "Only one blocked OS discovery worker may exist")
        await transport.close()
        await gate.release()
        try await Task.sleep(nanoseconds: 100_000_000)
        let endpoints = await transport.localEndpoints()
        XCTAssertTrue(endpoints.isEmpty)
        do { try await transport.start(); XCTFail("Closed transport restarted") } catch {}
    }

    func testUDPFailureDoesNotFailRelayFirstAndCanBeRetried() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let attempts = DiscoveryGate()
        await attempts.release()
        var discovery = loopbackDiscovery()
        discovery.open = { receive in
            await attempts.wait()
            if await attempts.calls == 1 { throw TransportError.connectionFailed("simulated UDP unavailable") }
            return try UDPChannel(receive: receive)
        }
        let transport = NetworkTransport(privateKey: NaClBox.random(32), discoPrivateKey: NaClBox.random(32),
                                         relayNodes: [fixture.node], relayFirst: true, discovery: discovery)
        try await within { try await transport.start() }
        try await eventually { await attempts.calls == 1 }
        await transport.retryDirect()
        try await eventually { !(await transport.localEndpoints()).isEmpty }
        await transport.close()
    }

    func testDirectSendErrorFallsBackWithoutClosingRelay() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let capture = SocketCapture()
        var discovery = loopbackDiscovery()
        discovery.open = { receive in
            let socket = try UDPChannel(receive: receive)
            await capture.set(socket)
            return socket
        }
        let aKey = NaClBox.random(32), bKey = NaClBox.random(32)
        let aDisco = NaClBox.random(32), bDisco = NaClBox.random(32)
        let aPublic = try NaClBox.publicKey(for: aKey), bPublic = try NaClBox.publicKey(for: bKey)
        let a = NetworkTransport(privateKey: aKey, discoPrivateKey: aDisco, relayNodes: [fixture.node], relayFirst: true, discovery: discovery)
        let b = NetworkTransport(privateKey: bKey, discoPrivateKey: bDisco, relayNodes: [fixture.node], relayFirst: false, discovery: loopbackDiscovery())
        do {
            try await a.start(); try await b.start()
            try await a.configurePeer(nodeKey: bPublic, discoKey: NaClBox.publicKey(for: bDisco), endpoints: b.localEndpoints())
            try await b.configurePeer(nodeKey: aPublic, discoKey: NaClBox.publicKey(for: aDisco), endpoints: a.localEndpoints())
            try await eventually { if case .direct = await a.path(to: bPublic) { return true }; return false }
            let receiver = Data(repeating: 7, count: 4)
            await a.observeAuthenticatedTransport(from: bPublic, viaRelay: false, receiver: receiver, counter: 2, allowFallback: true)
            await a.observeAuthenticatedTransport(from: bPublic, viaRelay: true, receiver: receiver, counter: 1, allowFallback: false)
            await a.observeAuthenticatedTransport(from: bPublic, viaRelay: true, receiver: receiver, counter: 3, allowFallback: false)
            let afterOldAndEmptyFrames = await a.path(to: bPublic)
            guard case .direct = afterOldAndEmptyFrames else { XCTFail("Older or ordinary relay frames changed the route"); throw TransportError.closed }
            await capture.socket?.close()
            let payload = Data("fallback on failed local UDP socket".utf8)
            let received = Task {
                for try await packet in b.packets where packet.payload == payload { return packet }
                throw TransportError.closed
            }
            try await a.send(to: bPublic, packet: payload)
            let packet = try await within { try await received.value }
            XCTAssertTrue(packet.viaRelay)
            let path = await a.path(to: bPublic)
            XCTAssertEqual(path, .relay)
            received.cancel()
            await a.close(); await b.close()
        } catch { await a.close(); await b.close(); throw error }
    }

    func testBlockedSTUNDoesNotDelayEncryptedRelaySession() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let gate = DiscoveryGate()
        var node = fixture.node
        node.stunPort = 3478
        var configuration = TailcatServer.Configuration()
        configuration.directDiscovery = loopbackDiscovery()
        configuration.region = DERPRegion(regionID: 1, nodes: [node])
        configuration.relayFirst = true
        configuration.directDiscovery.resolve = { _, _ in await gate.wait(); return [] }
        let server = TailcatServer(configuration: configuration)
        var client: TailcatClient?
        do {
            let listener = try await within { try await server.listen(port: 8081) }
            try await eventually { await gate.calls > 0 }
            let address = try await server.address
            var clientConfiguration = TailcatClient.Configuration()
            clientConfiguration.directDiscovery = loopbackDiscovery()
            let config = clientConfiguration
            let connected = try await within { try await TailcatClient.connect(to: address, configuration: config) }
            client = connected
            let stream = try await within { try await connected.openTCP(port: 8081) }
            let accepted = try await within { try await listener.accept() }
            try await exchange(stream, accepted, "WireGuard and TCP do not wait for STUN DNS")
            await server.close(); await connected.close(); await gate.release()
        } catch { await server.close(); await client?.close(); await gate.release(); throw error }
    }

    func testFastUDPStillBootstrapsWireGuardOverRelay() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        var configuration = TailcatServer.Configuration()
        configuration.directDiscovery = loopbackDiscovery()
        configuration.region = DERPRegion(regionID: 1, nodes: [fixture.node])
        configuration.relayFirst = true
        let server = TailcatServer(configuration: configuration)
        var client: TailcatClient?
        do {
            try await server.start()
            let address = try await server.address
            var clientConfiguration = TailcatClient.Configuration()
            clientConfiguration.directDiscovery = loopbackDiscovery()
            clientConfiguration.relayFirst = true
            let connected = try await TailcatClient.connect(to: address, configuration: clientConfiguration)
            client = connected
            try await eventually { if case .direct = await connected.path { return true }; return false }
            XCTAssertTrue(fixture.relayedInitialHandshakeAndConfirmation)
            await connected.close(); await server.close()
        } catch { await client?.close(); await server.close(); throw error }
    }

    func testStaleSocketCompletionCannotInstallIntoNewNetworkGeneration() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let gate = DiscoveryGate(), capture = SocketCapture()
        var discovery = loopbackDiscovery()
        discovery.open = { receive in
            await gate.wait()
            let socket = try UDPChannel(receive: receive)
            await capture.set(socket)
            return socket
        }
        let transport = NetworkTransport(privateKey: NaClBox.random(32), discoPrivateKey: NaClBox.random(32),
                                         relayNodes: [fixture.node], relayFirst: true, discovery: discovery)
        try await transport.start()
        try await eventually { await gate.calls == 1 }
        await transport.notifyNetworkChanged()
        await transport.notifyNetworkChanged()
        await gate.release()
        try await eventually {
            let calls = await gate.calls, endpoints = await transport.localEndpoints()
            return calls >= 2 && !endpoints.isEmpty
        }
        let sockets = await capture.sockets
        XCTAssertGreaterThanOrEqual(sockets.count, 2)
        let latest = try XCTUnwrap(sockets.last)
        let endpoints = await transport.localEndpoints()
        XCTAssertTrue(try endpoints.allSatisfy { try DiscoveryEndpoint($0).port == latest.port })
        for socket in sockets.dropLast() {
            do {
                try await socket.send(Data([1]), to: DiscoveryEndpoint(host: "127.0.0.1", port: latest.port))
                XCTFail("Stale socket was not closed")
            } catch {}
        }
        await transport.close()
    }

    func testCloseCancelsPendingEncryptedRelayMarker() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let gate = DiscoveryGate()
        let remote = try NaClBox.publicKey(for: NaClBox.random(32))
        let transport = NetworkTransport(privateKey: NaClBox.random(32), discoPrivateKey: NaClBox.random(32),
                                         relayNodes: [fixture.node], relayFirst: true, discovery: loopbackDiscovery())
        try await transport.start()
        try await transport.configurePeer(nodeKey: remote, discoKey: NaClBox.publicKey(for: NaClBox.random(32)))
        await transport.setRelayMarkerProvider { _ in
            await gate.wait()
            return Data(repeating: 0, count: 32)
        }
        await transport.notifyNetworkChanged()
        try await eventually { await gate.calls == 1 }
        let sending = Task { try await transport.send(to: remote, packet: Data([4, 0, 0, 0])) }
        await transport.close()
        await gate.release()
        do { try await within { try await sending.value }; XCTFail("Closed marker wait allowed an application send") }
        catch {}
        let endpoints = await transport.localEndpoints()
        XCTAssertTrue(endpoints.isEmpty)
    }

    func testNotificationDuringStartupIsAppliedOnceReady() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let gate = DiscoveryGate()
        let transport = NetworkTransport(privateKey: NaClBox.random(32), discoPrivateKey: NaClBox.random(32),
                                         relayNodes: [fixture.node], relayFirst: false, discovery: gatedDiscovery(gate))
        let starting = Task { try await transport.start() }
        try await eventually { await gate.calls == 1 }
        await transport.notifyNetworkChanged()
        await gate.release()
        try await starting.value
        try await eventually { await gate.calls == 2 }
        await transport.close()
    }

    func testFreshInvitationInsideThrottleWindowIsNotDropped() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let localKey = NaClBox.random(32), localDisco = NaClBox.random(32)
        let remoteKey = NaClBox.random(32), remoteDisco = NaClBox.random(32)
        let localPublic = try NaClBox.publicKey(for: localKey)
        let remotePublic = try NaClBox.publicKey(for: remoteKey)
        let localDiscoPublic = try NaClBox.publicKey(for: localDisco)
        let transport = NetworkTransport(privateKey: localKey, discoPrivateKey: localDisco,
                                         relayNodes: [fixture.node], relayFirst: true, discovery: loopbackDiscovery())
        let relay = DERPTransport(node: fixture.node, privateKey: remoteKey)
        var continuation: AsyncStream<(Data, DiscoveryEndpoint)>.Continuation!
        let received = AsyncStream<(Data, DiscoveryEndpoint)> { continuation = $0 }
        let output = continuation!
        let socket = try UDPChannel { packet, endpoint in output.yield((packet, endpoint)) }
        let endpoint = DiscoveryEndpoint(host: "127.0.0.1", port: socket.port)
        let responder = Task {
            for await (packet, source) in received {
                guard let opened = try? Discovery.open(packet, privateKey: remoteDisco),
                      case let .ping(transaction, _) = opened.message else { continue }
                let pong = try Discovery.seal(.pong(transaction: transaction, observed: source), to: localDiscoPublic, privateKey: remoteDisco)
                try await socket.send(pong, to: source)
            }
        }
        defer { responder.cancel(); output.finish(); socket.close() }
        do {
            try await transport.start(); try await relay.connect()
            try await transport.configurePeer(nodeKey: remotePublic, discoKey: NaClBox.publicKey(for: remoteDisco))
            // Socket discovery can first advertise nothing, then fresh addresses
            // a few milliseconds later. The second invitation must be retained.
            for endpoints in [[], [endpoint]] {
                let packet = try Discovery.seal(.callMeMaybe(endpoints), to: localDiscoPublic, privateKey: remoteDisco)
                try await relay.send(to: localPublic, packet: packet)
            }
            try await within(3) {
                while await transport.path(to: remotePublic) == .relay { try await Task.sleep(nanoseconds: 20_000_000) }
            }
            await transport.close(); await relay.close()
        } catch { await transport.close(); await relay.close(); throw error }
    }

    func testWithdrawnInvitationInvalidatesPendingPongWhileAlreadyOnRelay() async throws {
        try await exerciseRetiredChallenge(resetMarker: false)
    }

    func testResetMarkerInvalidatesPendingPongWhileAlreadyOnRelay() async throws {
        try await exerciseRetiredChallenge(resetMarker: true)
    }

    private func exerciseRetiredChallenge(resetMarker: Bool) async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let localKey = NaClBox.random(32), localDisco = NaClBox.random(32)
        let remoteKey = NaClBox.random(32), remoteDisco = NaClBox.random(32)
        let localPublic = try NaClBox.publicKey(for: localKey)
        let remotePublic = try NaClBox.publicKey(for: remoteKey)
        let localDiscoPublic = try NaClBox.publicKey(for: localDisco)
        let transport = NetworkTransport(privateKey: localKey, discoPrivateKey: localDisco,
                                         relayNodes: [fixture.node], relayFirst: true, discovery: loopbackDiscovery())
        let relay = DERPTransport(node: fixture.node, privateKey: remoteKey)
        let oldPackets = AsyncStream<(Data, DiscoveryEndpoint)>.makeStream()
        let newPackets = AsyncStream<(Data, DiscoveryEndpoint)>.makeStream()
        let oldSocket = try UDPChannel { oldPackets.continuation.yield(($0, $1)) }
        let newSocket = try UDPChannel { newPackets.continuation.yield(($0, $1)) }
        let oldEndpoint = DiscoveryEndpoint(host: "127.0.0.1", port: oldSocket.port)
        let newEndpoint = DiscoveryEndpoint(host: "127.0.0.1", port: newSocket.port)
        let oldPing = Task {
            for await (packet, source) in oldPackets.stream {
                if let opened = try? Discovery.open(packet, privateKey: remoteDisco),
                   case let .ping(transaction, _) = opened.message { return (transaction, source) }
            }
            throw TransportError.closed
        }
        let newPing = Task {
            for await (packet, source) in newPackets.stream {
                if let opened = try? Discovery.open(packet, privateKey: remoteDisco),
                   case let .ping(transaction, _) = opened.message { return (transaction, source) }
            }
            throw TransportError.closed
        }
        defer {
            oldPing.cancel(); newPing.cancel()
            oldPackets.continuation.finish(); newPackets.continuation.finish()
            oldSocket.close(); newSocket.close()
        }
        do {
            try await transport.start(); try await relay.connect()
            try await transport.configurePeer(nodeKey: remotePublic, discoKey: NaClBox.publicKey(for: remoteDisco))
            let oldHint = try Discovery.seal(.callMeMaybe([oldEndpoint]), to: localDiscoPublic, privateKey: remoteDisco)
            try await relay.send(to: localPublic, packet: oldHint)
            let (transaction, source) = try await within { try await oldPing.value }
            let oldPong = try Discovery.seal(.pong(transaction: transaction, observed: source), to: localDiscoPublic, privateKey: remoteDisco)
            if resetMarker {
                await transport.observeAuthenticatedTransport(from: remotePublic, viaRelay: true,
                                                              receiver: Data(repeating: 9, count: 4),
                                                              counter: 1, allowFallback: true)
                try await oldSocket.send(oldPong, to: source)
                try await Task.sleep(nanoseconds: 200_000_000)
                let afterMarker = await transport.path(to: remotePublic)
                XCTAssertEqual(afterMarker, .relay, "A reset marker retires pending challenges even while already on relay")
            }
            let newHint = try Discovery.seal(.callMeMaybe([newEndpoint]), to: localDiscoPublic, privateKey: remoteDisco)
            try await relay.send(to: localPublic, packet: newHint)
            _ = try await within { try await newPing.value }
            try await oldSocket.send(oldPong, to: source)
            try await Task.sleep(nanoseconds: 200_000_000)
            let path = await transport.path(to: remotePublic)
            XCTAssertEqual(path, .relay, "A withdrawn endpoint's earlier challenge cannot restore direct")
            await transport.close(); await relay.close()
        } catch { await transport.close(); await relay.close(); throw error }
    }

    func testChangedInvitationKeepsStreamOnRelayWhileNewPongsAreBlocked() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let filter = DiscoveryPacketFilter()
        var serverConfig = TailcatServer.Configuration()
        serverConfig.relayFirst = true
        serverConfig.region = DERPRegion(regionID: 1, nodes: [fixture.node])
        serverConfig.directDiscovery = loopbackDiscovery()
        let server = TailcatServer(configuration: serverConfig)
        var client: TailcatClient?
        do {
            let listener = try await server.listen(port: 8082)
            var config = TailcatClient.Configuration()
            config.relayFirst = true; config.directDiscovery = loopbackDiscovery()
            config.directDiscovery.open = { receive in
                try UDPChannel { packet, endpoint in
                    if !filter.drops(packet) { receive(packet, endpoint) }
                }
            }
            let connected = try await TailcatClient.connect(to: server.address, configuration: config)
            client = connected
            let stream = try await connected.openTCP(port: 8082)
            let accepted = try await listener.accept()
            try await eventually {
                if case .direct = await connected.path,
                   case .direct = try? await server.path(to: connected.publicKey) { return true }
                return false
            }
            try await exchange(stream, accepted, "established before peer migration")
            filter.setBlocked(true)
            await connected.notifyNetworkChanged()
            try await eventually { (try? await server.path(to: connected.publicKey)) == .relay }
            try await exchange(stream, accepted, "new discovery blocked; same stream must use relay")
            let blockedPath = await connected.path
            XCTAssertEqual(blockedPath, .relay)
            filter.setBlocked(false)
            await connected.retryDirect(); await server.retryDirect()
            try await eventually {
                if case .direct = await connected.path { return true }; return false
            }
            try await exchange(stream, accepted, "upgrade only after fresh challenge succeeds")
            await connected.close(); await server.close()
        } catch { await client?.close(); await server.close(); throw error }
    }

    func testAuthenticatedRelayDataRecoversBeforeAnyNewUDPOrEndpointHint() async throws {
        let fixture = try LocalRelay(); defer { fixture.close() }
        let gate = DiscoveryGate(); await gate.release()
        var serverConfig = TailcatServer.Configuration()
        serverConfig.relayFirst = true
        serverConfig.region = DERPRegion(regionID: 1, nodes: [fixture.node])
        serverConfig.directDiscovery = loopbackDiscovery()
        let server = TailcatServer(configuration: serverConfig)
        var client: TailcatClient?
        var stage = "connect"
        do {
            let listener = try await server.listen(port: 8083)
            var config = TailcatClient.Configuration()
            config.relayFirst = true; config.directDiscovery = gatedDiscovery(gate)
            let connected = try await TailcatClient.connect(to: server.address, configuration: config)
            client = connected
            let stream = try await connected.openTCP(port: 8083)
            let accepted = try await listener.accept()
            stage = "initial direct"
            try await eventually {
                if case .direct = await connected.path,
                   case .direct = try? await server.path(to: connected.publicKey) { return true }
                return false
            }
            try await exchange(stream, accepted, "working direct stream")
            stage = "first blocked-discovery reset"
            await gate.block()
            await connected.notifyNetworkChanged()
            // There is no new UDP socket, address announcement or matching Pong.
            // The ordered encrypted reset marker must make replies use DERP.
            try await exchange(stream, accepted, "relay traffic before any new endpoint hint")
            let responsePath = try await server.path(to: connected.publicKey)
            XCTAssertEqual(responsePath, .relay)
            await gate.release(); await connected.retryDirect(); await server.retryDirect()
            stage = "first revalidation"
            try await eventually {
                if case .direct = await connected.path,
                   case .direct = try? await server.path(to: connected.publicKey) { return true }
                return false
            }
            // A rapid second asymmetric change must still recover, even with
            // all new UDP/endpoint hints blocked.
            await gate.block()
            await connected.notifyNetworkChanged()
            stage = "rapid second reset"
            try await within(5) {
                try await self.exchange(stream, accepted, "another rapid rebind without discovery")
            }
            let settlingResponsePath = try await server.path(to: connected.publicKey)
            XCTAssertEqual(settlingResponsePath, .relay)
            await gate.release(); await connected.retryDirect(); await server.retryDirect()
            stage = "continuous revalidation"
            try await within(15) {
                var consecutiveDirect = 0
                while consecutiveDirect < 60 {
                    try await self.exchange(stream, accepted, "traffic continues throughout direct recovery")
                    if case .direct = await connected.path,
                       case .direct = try? await server.path(to: connected.publicKey) {
                        consecutiveDirect += 1
                    } else { consecutiveDirect = 0 }
                    try await Task.sleep(nanoseconds: 50_000_000)
                }
            }
            let sourceKey = await connected.publicKey.rawValue
            stage = "invalid markers"
            let marker = try XCTUnwrap(fixture.lastKeepalive(from: sourceKey))
            let destination = try await server.address.serverPublicKey.rawValue
            try fixture.inject(marker, from: sourceKey, to: destination)
            var forged = marker
            forged[8] ^= 0x40; forged[31] ^= 0x01
            try fixture.inject(forged, from: sourceKey, to: destination)
            try await Task.sleep(nanoseconds: 200_000_000)
            let afterInvalidMarkers = try await server.path(to: connected.publicKey)
            guard case .direct = afterInvalidMarkers else {
                XCTFail("Replayed or forged encrypted reset marker changed a healthy route")
                throw TransportError.closed
            }
            await gate.block()
            await connected.notifyNetworkChanged()
            stage = "third reset"
            try await exchange(stream, accepted, "a later one-sided rebind still falls back")
            let repeatedResponsePath = try await server.path(to: connected.publicKey)
            XCTAssertEqual(repeatedResponsePath, .relay)
            await gate.release()
            await connected.close(); await server.close()
        } catch {
            XCTFail("Marker recovery failed during \(stage): \(error)")
            await gate.release(); await client?.close(); await server.close(); throw error
        }
    }
}
#endif