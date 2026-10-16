import XCTest
@testable import Tailcat

private actor AdmissionGate {
    var entered = false
    private var released = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        entered = true
        if released { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func release() { released = true; let pending = waiters; waiters.removeAll(); pending.forEach { $0.resume() } }
}

private final class FlowPolicy: @unchecked Sendable {
    private let lock = NSLock()
    private var allowed = true
    private var count = 0
    func select() -> Bool { lock.lock(); defer { lock.unlock() }; count += 1; return allowed }
    func deny() { lock.lock(); allowed = false; lock.unlock() }
    var calls: Int { lock.lock(); defer { lock.unlock() }; return count }
}

final class LibraryTests: XCTestCase {
    func testSelectorsRunForEveryNewFlowAndCanRevokeAccess() async throws {
        var config = try configuration()
        let tcpPolicy = FlowPolicy(); let udpPolicy = FlowPolicy()
        config.onTCP = { _ in tcpPolicy.select() ? Self.echoTCP : nil }
        config.onUDP = { _ in udpPolicy.select() ? Self.echoUDP : nil }
        let server = TailcatServer(configuration: config)
        try await server.start()
        let client = try await TailcatClient.connect(to: server.address)
        do {
            for _ in 0..<2 {
                try await roundTrip(client.openTCP(port: 80), data: Data([7]))
                let udp = try await client.openUDP(port: 53)
                try await udp.write(Data([8])); let data = try await udp.read(); XCTAssertEqual(data, Data([8])); await udp.close()
            }
            XCTAssertEqual(tcpPolicy.calls, 2); XCTAssertEqual(udpPolicy.calls, 2)
            tcpPolicy.deny(); udpPolicy.deny()
            do { _ = try await client.openTCP(port: 80); XCTFail("revoked TCP callback admitted a new flow") }
            catch { XCTAssertEqual(error as? TailcatTransportError, .connectionRefused) }
            let udp = try await client.openUDP(port: 53); try await udp.write(Data([9]))
            for _ in 0..<100 { if udpPolicy.calls == 3 { break }; try await Task.sleep(nanoseconds: 10_000_000) }
            XCTAssertEqual(tcpPolicy.calls, 3); XCTAssertEqual(udpPolicy.calls, 3)
            await udp.close(); await client.close(); await server.close()
        } catch { await client.close(); await server.close(); throw error }
    }

    private func configuration() throws -> TailcatServer.Configuration {
        guard let port = ProcessInfo.processInfo.environment["TAILCAT_TEST_DERP_PORT"].flatMap(Int.init) else { throw XCTSkip("Set TAILCAT_TEST_DERP_PORT to a loopback plaintext DERP fixture") }
        var result = TailcatServer.Configuration()
        result.region = DERPRegion(regionID: 1, nodes: [DERPNode(hostName: "127.0.0.1", ipv4: "127.0.0.1", ipv6: "none", stunPort: -1, derpPort: port, insecureForTests: true)])
        return result
    }
    private static let echoTCP: TailcatTCPHandler = { stream in
        do {
            while true { let data = try await stream.read(); if data.isEmpty { break }; try await stream.write(data) }
            try await stream.closeWrite()
        } catch {}
        await stream.close()
    }
    private static let echoUDP: TailcatUDPHandler = { flow in
        do { while true { let data = try await flow.read(); try await flow.write(data) } } catch {}
        await flow.close()
    }
    private func roundTrip(_ stream: TailcatConnection, data: Data) async throws {
        let writer = Task { try await stream.write(data); try await stream.closeWrite() }
        var received = Data()
        while true { let bytes = try await stream.read(); if bytes.isEmpty { break }; received.append(bytes) }
        try await writer.value
        XCTAssertEqual(received, data); await stream.close()
    }
    func testForwardingIPv4IPv6CallbacksAndNetworkReset() async throws {
        var config = try configuration()
        config.onTCP = { _ in Self.echoTCP }; config.onUDP = { _ in Self.echoUDP }
        config.onTCPForward = { _ in Self.echoTCP }; config.onUDPForward = { _ in Self.echoUDP }
        config.allowProxy = { $0.port == 7000 }
        let server = TailcatServer(configuration: config)
        try await server.start()
        let client = try await TailcatClient.connect(to: server.address)
        do {
            try await roundTrip(client.openTCP(port: 80), data: Data(repeating: 42, count: 131_072))
            for host in ["192.0.2.9", "2001:db8::9"] {
                let target = try TailcatEndpoint(ipAddress: host, port: 7000)
                XCTAssertEqual(target.ipAddress, host)
                try await roundTrip(client.openTCP(to: target), data: Data(repeating: 17, count: 65_537))
                let udp = try await client.openUDP(to: target)
                for count in [0, 1232] {
                    let data = Data(repeating: 31, count: count)
                    try await udp.write(data); let received = try await udp.read(); XCTAssertEqual(received, data)
                }
                await udp.close()
            }
            await client.resetNetworkPaths(); await server.resetNetworkPaths()
            let path = await client.path; XCTAssertEqual(path, .relay)
            try await roundTrip(client.openTCP(port: 80), data: Data("after path reset".utf8))
            await client.close(); await server.close()
        } catch { await client.close(); await server.close(); throw error }
    }

    func testSlowAdmissionDoesNotBlockEstablishedTraffic() async throws {
        var config = try configuration(); config.onTCP = { _ in Self.echoTCP }
        let slowKey = try NodePrivateKey.generate(); let slowPublic = try slowKey.publicKey
        let gate = AdmissionGate()
        config.allowClient = { key in if key == slowPublic { await gate.wait() }; return true }
        let server = TailcatServer(configuration: config)
        try await server.start()
        let address = try await server.address
        let normal = try await TailcatClient.connect(to: address)
        var slowConfig = TailcatClient.Configuration(); slowConfig.privateKey = slowKey
        let slow = Task { try await TailcatClient.connect(to: address, configuration: slowConfig) }
        do {
            for _ in 0..<100 { if await gate.entered { break }; try await Task.sleep(nanoseconds: 20_000_000) }
            let entered = await gate.entered; XCTAssertTrue(entered)
            try await roundTrip(normal.openTCP(port: 80), data: Data(repeating: 1, count: 65_536))
            await gate.release()
            let connected = try await slow.value; await connected.close(); await normal.close(); await server.close()
        } catch { await gate.release(); slow.cancel(); await normal.close(); await server.close(); throw error }
    }

    func testListenerCancellationCloseAndWrongPSK() async throws {
        let config = try configuration()
        let server = TailcatServer(configuration: config)
        let listener = try await server.listen(port: 80)
        let waiting = Task { try await listener.accept() }
        waiting.cancel()
        do { _ = try await waiting.value; XCTFail("accept should cancel") } catch is CancellationError {} catch { XCTFail("unexpected \(error)") }
        var badAddress = try await server.address; badAddress.presharedKey = try .generate()
        var clientConfig = TailcatClient.Configuration(); clientConfig.connectTimeout = 0.4
        do { _ = try await TailcatClient.connect(to: badAddress, configuration: clientConfig); XCTFail("wrong PSK accepted") }
        catch { XCTAssertEqual(error as? TailcatError, .timedOut) }
        let closedAccept = Task { try await listener.accept() }
        await server.close()
        do { _ = try await closedAccept.value; XCTFail("close should wake accept") } catch {}
    }
}