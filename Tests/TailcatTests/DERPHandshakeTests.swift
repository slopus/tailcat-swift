import XCTest
@testable import Tailcat

final class DERPHandshakeTests: XCTestCase {
    func testTLSMetadataRequiresExactKeyAndPositiveBoundedVersion() throws {
        let key = try NaClBox.publicKey(for: NaClBox.random(32))
        let name = "derpkey" + key.tailcatHex
        XCTAssertEqual(DERPHandshake.metadataServerKey(commonName: name, serialNumber: Data([2])), key)
        XCTAssertEqual(DERPHandshake.metadataServerKey(commonName: name, serialNumber: Data([0, 255])), key)
        for serial in [Data(), Data([0]), Data([128]), Data([0, 2]), Data([1, 0]), Data([0, 1, 0])] {
            XCTAssertNil(DERPHandshake.metadataServerKey(commonName: name, serialNumber: serial))
        }
        for invalid in ["", "derpkey", "other" + key.tailcatHex, name + "0", name.dropLast() + "g", "derpkey" + String(repeating: "0", count: 64)] {
            XCTAssertNil(DERPHandshake.metadataServerKey(commonName: invalid, serialNumber: Data([2])))
        }
    }

    func testFastStartKeyNeedsExactlyOneMetadataCertificate() throws {
        let key = try NaClBox.publicKey(for: NaClBox.random(32)), other = try NaClBox.publicKey(for: NaClBox.random(32))
        let leaf = (commonName: "derp1.tailscale.com", serialNumber: Data([3, 1, 4]))
        let meta = (commonName: "derpkey" + key.tailcatHex, serialNumber: Data([2]))
        XCTAssertEqual(DERPHandshake.fastStartKey(peerCertificates: [leaf, meta]), key)
        XCTAssertNil(DERPHandshake.fastStartKey(peerCertificates: []))
        XCTAssertNil(DERPHandshake.fastStartKey(peerCertificates: [leaf]))
        XCTAssertNil(DERPHandshake.fastStartKey(peerCertificates: [leaf, meta, meta]))
        XCTAssertNil(DERPHandshake.fastStartKey(peerCertificates: [meta, ("derpkey" + other.tailcatHex, Data([2]))]))
    }

    func testGreetingChecksMagicBoundsAndMetadataKey() throws {
        let key = NaClBox.random(32), greeting = Data("DERP🔑".utf8) + key
        XCTAssertEqual(try DERPHandshake.serverKey(greeting: greeting, expected: key), key)
        XCTAssertThrowsError(try DERPHandshake.serverKey(greeting: greeting, expected: NaClBox.random(32)))
        XCTAssertThrowsError(try DERPHandshake.serverKey(greeting: Data(greeting.dropLast())))
        XCTAssertThrowsError(try DERPHandshake.serverKey(greeting: Data(repeating: 0, count: 40)))
        XCTAssertThrowsError(try DERPHandshake.serverKey(greeting: greeting + Data(repeating: 0, count: 1024)))
        // An unexpected HTTP 101 cannot become a giant DERP allocation/read.
        XCTAssertThrowsError(try DERPFrame.header(Data("HTTP/".utf8)))
    }

    func testClientInfoUsesFreshNonceAndAuthenticatesNewIdentity() throws {
        let client = NaClBox.random(32), server = NaClBox.random(32)
        let serverKey = try NaClBox.publicKey(for: server)
        let first = try DERPHandshake.clientInfo(privateKey: client, serverKey: serverKey)
        let second = try DERPHandshake.clientInfo(privateKey: client, serverKey: serverKey)
        XCTAssertNotEqual(first, second)
        let header = try DERPFrame.header(Data(first.prefix(5)))
        XCTAssertEqual(header.type, 2)
        let payload = Data(first.dropFirst(5)), publicKey = Data(payload.prefix(32))
        XCTAssertEqual(publicKey, try NaClBox.publicKey(for: client))
        let json = try NaClBox.open(Data(payload.dropFirst(56)), nonce: Data(payload[32..<56]), publicKey: publicKey, privateKey: server)
        XCTAssertEqual(String(decoding: json, as: UTF8.self), "{\"version\":2,\"CanAckPings\":true}")
    }

    #if canImport(Glibc) && DEBUG
    func testFastStartAuthenticatesCoalescedFramesWithoutOrdinaryRetry() async throws {
        let fixture = try LocalRelay()
        defer { fixture.close() }
        let trace = StartupTrace()
        let transport = DERPTransport(nodes: [fixture.node], privateKey: NaClBox.random(32), startupTrace: trace)
        try await transport.useFastStartKeyForTesting(fixture.serverPublicKey)
        do { try await transport.connect() } catch { await transport.close(); throw error }
        XCTAssertEqual(fixture.fastStartCount, 1)
        let names = trace.snapshot().map(\.name)
        XCTAssertTrue(names.contains("serverInfoVerified"))
        XCTAssertFalse(names.contains("derpFastStartFallback"))
        XCTAssertLessThan(try XCTUnwrap(names.firstIndex(of: "clientInfoWritten")), try XCTUnwrap(names.firstIndex(of: "httpUpgradeAndGreetingReceived")))
        await transport.close()
    }

    func testUnreadableFastStartKeyUsesOrdinaryHandshake() async throws {
        // The loopback stream, like a TLS handshake whose certificates could
        // not be read, reports no key: the first attempt is already ordinary.
        let fixture = try LocalRelay()
        defer { fixture.close() }
        let trace = StartupTrace()
        let transport = DERPTransport(nodes: [fixture.node], privateKey: NaClBox.random(32), startupTrace: trace)
        do { try await transport.connect() } catch { await transport.close(); throw error }
        let names = trace.snapshot().map(\.name)
        XCTAssertEqual(fixture.fastStartCount, 0)
        XCTAssertEqual(names.filter { $0 == "relayConnectionCreated" }.count, 1)
        XCTAssertFalse(names.contains("derpFastStartSelected"))
        XCTAssertFalse(names.contains("derpFastStartFallback"))
        XCTAssertTrue(names.contains("serverInfoVerified"))
        XCTAssertLessThan(try XCTUnwrap(names.firstIndex(of: "httpUpgradeAndGreetingReceived")), try XCTUnwrap(names.firstIndex(of: "clientInfoWritten")))
        await transport.close()
    }

    func testUnexpectedHTTPAndMismatchedKeyRetryOrdinarilyOnce() async throws {
        for behavior in [LocalRelay.FastStartBehavior.ignored, .mismatchedGreeting] {
            let fixture = try LocalRelay(fastStartBehavior: behavior)
            let trace = StartupTrace()
            let transport = DERPTransport(nodes: [fixture.node], privateKey: NaClBox.random(32), startupTrace: trace)
            try await transport.useFastStartKeyForTesting(fixture.serverPublicKey)
            do { try await transport.connect() } catch { await transport.close(); fixture.close(); throw error }
            let names = trace.snapshot().map(\.name)
            XCTAssertEqual(fixture.fastStartCount, 1)
            XCTAssertEqual(names.filter { $0 == "relayConnectionCreated" }.count, 2)
            XCTAssertEqual(names.filter { $0 == "derpFastStartFallback" }.count, 1)
            XCTAssertEqual(names.filter { $0 == "serverInfoVerified" }.count, 1)
            XCTAssertEqual(fixture.authenticationNonces.count, 2)
            XCTAssertNotEqual(fixture.authenticationNonces.first, fixture.authenticationNonces.last)
            await transport.notifyNetworkChanged()
            try await transport.connect()
            XCTAssertEqual(fixture.fastStartCount, 1, "a bad capability stays disabled for this transport")
            await transport.close(); fixture.close()
        }
    }

    func testBadServerInfoCannotAuthenticateOnFastOrFallbackPath() async throws {
        let fixture = try LocalRelay(fastStartBehavior: .corruptServerInfo)
        defer { fixture.close() }
        let trace = StartupTrace()
        let transport = DERPTransport(nodes: [fixture.node], privateKey: NaClBox.random(32), startupTrace: trace)
        try await transport.useFastStartKeyForTesting(fixture.serverPublicKey)
        do { try await transport.connect(); XCTFail("corrupt authentication accepted") } catch {}
        XCTAssertEqual(fixture.fastStartCount, 1)
        XCTAssertFalse(trace.snapshot().contains { $0.name == "serverInfoVerified" })
        await transport.close()
    }

    func testCancellingStalledFastStartLeavesAnotherRelayClientAlive() async throws {
        let fixture = try LocalRelay(fastStartBehavior: .stalled)
        defer { fixture.close() }
        let firstKey = NaClBox.random(32)
        let first = DERPTransport(node: fixture.node, privateKey: firstKey)
        try await first.connect()
        let trace = StartupTrace()
        let second = DERPTransport(nodes: [fixture.node], privateKey: NaClBox.random(32), startupTrace: trace)
        try await second.useFastStartKeyForTesting(fixture.serverPublicKey)
        let pending = Task { try await second.connect() }
        let deadline = ProcessInfo.processInfo.systemUptime + 3
        while !trace.snapshot().contains(where: { $0.name == "clientInfoWritten" }), ProcessInfo.processInfo.systemUptime < deadline {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertTrue(trace.snapshot().contains { $0.name == "clientInfoWritten" })
        pending.cancel()
        do { try await pending.value; XCTFail("cancelled fast start succeeded") } catch {}
        XCTAssertFalse(trace.snapshot().contains { $0.name == "derpFastStartFallback" })
        try await first.send(to: NaClBox.publicKey(for: firstKey), packet: Data("first relay remains independent".utf8))
        var packets = first.packets.makeAsyncIterator()
        let received = try await packets.next()
        XCTAssertEqual(received?.payload, Data("first relay remains independent".utf8))
        await second.close(); await first.close()
    }
    #endif
}