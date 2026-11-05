import XCTest
@testable import Tailcat

final class StartupTraceTests: XCTestCase {
    func testRecorderIsBoundedOrderedAndClientLocal() async throws {
        let trace = StartupTrace(), other = StartupTrace()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<8 {
                group.addTask {
                    for _ in 0..<100 { trace.record(String(repeating: "x", count: 100), detail: String(repeating: "y", count: 200)) }
                }
            }
        }
        let events = trace.snapshot()
        XCTAssertEqual(events.count, StartupTrace.capacity)
        XCTAssertTrue(events.allSatisfy { $0.name.count == 64 && $0.detail?.count == 128 })
        XCTAssertEqual(events.first?.elapsedMs, 0)
        XCTAssertEqual(events.map(\.elapsedMs), events.map(\.elapsedMs).sorted())
        XCTAssertTrue(other.snapshot().isEmpty)
        XCTAssertNotEqual(trace.id, other.id)
    }

    #if canImport(Glibc)
    func testEventWaiterCancellationDeadlineAndCloseDoNotLeaveStaleWaiters() async throws {
        let fixture = try LocalRelay()
        defer { fixture.close() }
        var serverConfiguration = TailcatServer.Configuration()
        serverConfiguration.region = DERPRegion(regionID: 1, nodes: [fixture.node])
        serverConfiguration.relayFirst = true
        serverConfiguration.allowClient = { _ in false }
        let server = TailcatServer(configuration: serverConfiguration)
        try await server.start()
        let address = try await server.address
        let trace = StartupTrace()
        let engine = try TailcatEngine(key: .generate(), address: address, server: false,
                                       configuration: serverConfiguration, startupTrace: trace)
        do {
            try await engine.start()
            let cancelled = Task { try await engine.connect(timeout: 10) }
            try await waitForInstalledWaiters(1, trace: trace)
            cancelled.cancel()
            do { try await cancelled.value; XCTFail("waiter must cancel") }
            catch is CancellationError {}
            catch { XCTFail("unexpected cancellation: \(error)") }
            do { try await engine.connect(timeout: 0.03); XCTFail("waiter must time out") }
            catch { XCTAssertEqual(error as? TailcatError, .timedOut) }
            let closing = Task { try await engine.connect(timeout: 10) }
            try await waitForInstalledWaiters(3, trace: trace)
            await engine.close(); await engine.close()
            do { try await closing.value; XCTFail("close must wake waiter") }
            catch { XCTAssertEqual(error as? TailcatError, .closed) }
            XCTAssertEqual(trace.snapshot().filter { $0.name == "connectionWaiterResolved" }.count, 3)
            await server.close()
        } catch { await engine.close(); await server.close(); throw error }
    }

    private func waitForInstalledWaiters(_ count: Int, trace: StartupTrace) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 3
        while trace.snapshot().filter({ $0.name == "connectionWaiterInstalled" }).count < count {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw TailcatError.timedOut }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
    }

    func testFailedAndCancelledSecondConnectLeaveFirstUsable() async throws {
        let fixture = try LocalRelay()
        defer { fixture.close() }
        let key = try NodePrivateKey.generate(), allowedKey = try key.publicKey
        var discovery = DirectDiscovery()
        discovery.interfaces = { [DiscoveryEndpoint(host: "127.0.0.1", port: $0.port)] }
        var serverConfiguration = TailcatServer.Configuration()
        serverConfiguration.region = DERPRegion(regionID: 1, nodes: [fixture.node])
        serverConfiguration.relayFirst = true
        serverConfiguration.directDiscovery = discovery
        serverConfiguration.allowClient = { $0 == allowedKey }
        let server = TailcatServer(configuration: serverConfiguration)
        var first: TailcatClient?
        do {
            let listener = try await server.listen(port: 8080)
            let address = try await server.address
            var configuration = TailcatClient.Configuration()
            configuration.privateKey = key
            configuration.directDiscovery = discovery
            configuration.relayFirst = true
            let retained = try await TailcatClient.connect(to: address, configuration: configuration)
            first = retained
            let stream = try await retained.openTCP(port: 8080)
            let accepted = try await listener.accept()
            let echoTask = Task {
                while let bytes = try? await accepted.read(), !bytes.isEmpty { try? await accepted.write(bytes) }
            }
            defer { echoTask.cancel() }
            configuration.privateKey = nil
            configuration.connectTimeout = 0.2
            do {
                let unexpected = try await TailcatClient.connect(to: address, configuration: configuration)
                await unexpected.close(); XCTFail("unapproved identity must not connect")
            } catch { XCTAssertEqual(error as? TailcatError, .timedOut) }
            try await echo(stream, "first survives a second client's timeout")

            let trace = StartupTrace()
            configuration.connectTimeout = 10
            configuration.startupTrace = trace
            let pendingConfiguration = configuration
            let pending = Task { try await TailcatClient.connect(to: address, configuration: pendingConfiguration) }
            let deadline = ProcessInfo.processInfo.systemUptime + 3
            while !trace.snapshot().contains(where: { $0.name == "meowWritten" }),
                  ProcessInfo.processInfo.systemUptime < deadline {
                try await Task.sleep(nanoseconds: 10_000_000)
            }
            XCTAssertTrue(trace.snapshot().contains { $0.name == "meowWritten" })
            pending.cancel()
            do { let unexpected = try await pending.value; await unexpected.close(); XCTFail("second connect must cancel") }
            catch is CancellationError {}
            catch { XCTFail("unexpected cancellation error: \(error)") }
            try await echo(stream, "first survives a second client's cancellation")
            await retained.close(); await server.close()
            await accepted.close(); _ = await echoTask.result
        } catch { await first?.close(); await server.close(); throw error }
    }

    func testIndependentClientsKeepOwnSocketsAndSurviveOtherResetAndClose() async throws {
        let fixture = try LocalRelay()
        defer { fixture.close() }
        var discovery = DirectDiscovery()
        discovery.interfaces = { [DiscoveryEndpoint(host: "127.0.0.1", port: $0.port)] }
        var serverConfiguration = TailcatServer.Configuration()
        serverConfiguration.region = DERPRegion(regionID: 1, nodes: [fixture.node])
        serverConfiguration.relayFirst = true
        serverConfiguration.directDiscovery = discovery
        serverConfiguration.onTCP = { _ in { stream in
            do {
                while true {
                    let bytes = try await stream.read()
                    if bytes.isEmpty { break }
                    try await stream.write(bytes)
                }
            } catch {}
            await stream.close()
        } }
        let server = TailcatServer(configuration: serverConfiguration)
        var clients = [TailcatClient]()
        do {
            try await server.start()
            let address = try await server.address
            let firstTrace = StartupTrace(), secondTrace = StartupTrace()
            var configuration = TailcatClient.Configuration()
            configuration.relayFirst = true
            configuration.directDiscovery = discovery
            configuration.startupTrace = firstTrace
            let first = try await TailcatClient.connect(to: address, configuration: configuration)
            clients.append(first)
            let firstStream = try await first.openTCP(port: 8080)
            try await echo(firstStream, "first remains open")
            configuration.startupTrace = secondTrace
            let second = try await TailcatClient.connect(to: address, configuration: configuration)
            clients.append(second)
            let secondStream = try await second.openTCP(port: 8080)
            let firstKey = await first.publicKey, secondKey = await second.publicKey
            XCTAssertNotEqual(firstKey, secondKey)
            let firstDisco = try await first.discoveryPublicKey, secondDisco = try await second.discoveryPublicKey
            XCTAssertNotEqual(firstDisco, secondDisco)
            async let one: Void = echo(firstStream, "first independent flow")
            async let two: Void = echo(secondStream, "second independent flow")
            try await one; try await two
            let deadline = ProcessInfo.processInfo.systemUptime + 3
            while secondTrace.snapshot().first(where: { $0.name == "udpBound" }) == nil,
                  ProcessInfo.processInfo.systemUptime < deadline {
                try await Task.sleep(nanoseconds: 10_000_000)
            }
            let firstEvents = firstTrace.snapshot(), secondEvents = secondTrace.snapshot()
            let firstPort = try XCTUnwrap(firstEvents.first(where: { $0.name == "udpBound" })?.detail)
            let secondPort = try XCTUnwrap(secondEvents.first(where: { $0.name == "udpBound" })?.detail)
            XCTAssertNotEqual(firstPort, secondPort)
            let firstRelay = try XCTUnwrap(firstEvents.first(where: { $0.name == "relayConnectionCreated" })?.detail)
            let secondRelay = try XCTUnwrap(secondEvents.first(where: { $0.name == "relayConnectionCreated" })?.detail)
            XCTAssertNotEqual(firstRelay, secondRelay)
            for events in [firstEvents, secondEvents] {
                let names = events.map(\.name)
                XCTAssertLessThan(try XCTUnwrap(names.firstIndex(of: "serverInfoVerified")), try XCTUnwrap(names.firstIndex(of: "wireGuardEstablished")))
                XCTAssertLessThan(try XCTUnwrap(names.firstIndex(of: "wireGuardEstablished")), try XCTUnwrap(names.firstIndex(of: "connectReturned")))
            }
            await second.notifyNetworkChanged()
            try await echo(firstStream, "first survives another client's reset")
            try await echo(secondStream, "second keeps its own flow across reset")
            await first.close()
            try await echo(secondStream, "second survives first close")
            await second.close(); await server.close()
        } catch {
            for client in clients { await client.close() }
            await server.close(); throw error
        }
    }

    private func echo(_ stream: TailcatConnection, _ text: String) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                let sent = Data(text.utf8)
                try await stream.write(sent)
                var received = Data()
                while received.count < sent.count {
                    let bytes = try await stream.read(maximumBytes: sent.count - received.count)
                    guard !bytes.isEmpty else { throw TailcatError.closed }
                    received.append(bytes)
                }
                XCTAssertEqual(sent, received)
            }
            group.addTask { try await Task.sleep(nanoseconds: 10_000_000_000); throw TailcatError.timedOut }
            defer { group.cancelAll() }
            _ = try await group.next()
        }
    }
    #endif
}