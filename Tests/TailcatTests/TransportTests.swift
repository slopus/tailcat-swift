import XCTest
@testable import Tailcat

final class TransportTests: XCTestCase {
    private func hex(_ string: String) -> Data {
        let bytes = Array(string.utf8)
        return Data(stride(from: 0, to: bytes.count, by: 2).map {
            UInt8(String(bytes: bytes[$0..<($0 + 2)], encoding: .utf8)!, radix: 16)!
        })
    }

    func testNaClGoCompatibilityAndTamperRejection() throws {
        // Generated independently with golang.org/x/crypto/nacl/box.
        let sender = hex("0002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f60")
        let receiver = hex("2022232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
        let nonce = hex("000102030405060708090a0b0c0d0e0f1011121314151617")
        let message = Data("{\"version\":2,\"CanAckPings\":true}".utf8)
        let expected = hex("176bdffac6239dc06abd2678210731e169d7ad3c284e14bd97d07b31d36052dc1b4b776d33dac1529db871ecd021683e")
        let receiverPublic = try NaClBox.publicKey(for: receiver)
        let senderPublic = try NaClBox.publicKey(for: sender)
        XCTAssertEqual(try NaClBox.seal(message, nonce: nonce, publicKey: receiverPublic, privateKey: sender), expected)
        XCTAssertEqual(try NaClBox.open(expected, nonce: nonce, publicKey: senderPublic, privateKey: receiver), message)
        for index in [0,15,16,expected.count - 1] {
            var corrupt = expected; corrupt[index] ^= 1
            XCTAssertThrowsError(try NaClBox.open(corrupt, nonce: nonce, publicKey: senderPublic, privateKey: receiver))
        }
        XCTAssertThrowsError(try NaClBox.open(expected, nonce: Data(repeating: 0, count: 24), publicKey: senderPublic, privateKey: receiver))
        XCTAssertThrowsError(try NaClBox.seal(message, nonce: nonce, publicKey: Data(repeating: 0, count: 32), privateKey: sender))
    }

    func testNaClBoundariesAndDiscoveryWire() throws {
        let sender = Data((0..<32).map(UInt8.init)), receiver = Data((32..<64).map(UInt8.init))
        let receiverPublic = try NaClBox.publicKey(for: receiver), senderPublic = try NaClBox.publicKey(for: sender)
        let nonce = Data(repeating: 0xa5, count: 24)
        for count in [0,1,15,16,17,31,32,33,63,64,65,1024,65536] {
            let message = Data((0..<count).map { UInt8(truncatingIfNeeded: $0) })
            let encrypted = try NaClBox.seal(message, nonce: nonce, publicKey: receiverPublic, privateKey: sender)
            XCTAssertEqual(try NaClBox.open(encrypted, nonce: nonce, publicKey: senderPublic, privateKey: receiver), message)
        }
        let id = Data(repeating: 0x5a, count: 12)
        let v4 = try DiscoveryEndpoint("192.0.2.7:41641")
        let v6 = try DiscoveryEndpoint("[2001:db8::1]:41641")
        let messages: [DiscoveryMessage] = [.ping(transaction: id, nodeKey: senderPublic),
            .pong(transaction: id, observed: v4), .pong(transaction: id, observed: v6), .callMeMaybe([v4,v6])]
        for message in messages {
            let packet = try Discovery.seal(message, to: receiverPublic, privateKey: sender)
            let decoded = try Discovery.open(packet, privateKey: receiver)
            XCTAssertEqual(decoded.source, senderPublic); XCTAssertEqual(decoded.message, message)
        }
        XCTAssertEqual(try DiscoveryMessage.pong(transaction: id, observed: v4).encode().suffix(18),
                       hex("00000000000000000000ffffc0000207a2a9"))
        XCTAssertThrowsError(try DiscoveryMessage(encoded: Data([2,0,1])))
        XCTAssertThrowsError(try DiscoveryMessage(encoded: Data([3,0,1])))
        XCTAssertThrowsError(try DiscoveryEndpoint("127.0.0.1:0"))
        XCTAssertThrowsError(try Discovery.open(Data("TS💬".utf8), privateKey: receiver))
    }

    func testRFC5769STUNXORMappedAddress() throws {
        // RFC 5769 section 2.2, including padded attributes and MESSAGE-INTEGRITY.
        let response = hex("0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a147e112a643000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004c07d4c96")
        let transaction = hex("b7e7a701bc34d686fa87dfae")
        XCTAssertEqual(try STUN.response(response, transaction: transaction), try DiscoveryEndpoint("192.0.2.1:32853"))
        XCTAssertThrowsError(try STUN.response(response, transaction: Data(repeating: 0, count: 12)))
        XCTAssertThrowsError(try STUN.response(Data(response.dropLast()), transaction: transaction))
    }

    func testFrameLengthLimitsAndNetworkByteOrder() throws {
        let payload = Data(repeating: 0x9a, count: 513)
        let encoded = try DERPFrame.encode(type: 4, payload: payload)
        XCTAssertEqual(encoded.prefix(5), Data([4,0,0,2,1]))
        let header = try DERPFrame.header(Data(encoded.prefix(5)))
        XCTAssertEqual(header.type, 4); XCTAssertEqual(header.length, 513)
        XCTAssertThrowsError(try DERPFrame.header(Data([5,0xff,0xff,0xff,0xff])))
        XCTAssertThrowsError(try DERPFrame.header(Data([5,0,0,0])))
    }

    func testUnauthenticatedUDPIngressIsBoundedBeforeActorDelivery() async throws {
        let ingress = UDPIngress()
        let source = try DiscoveryEndpoint("192.0.2.1:1234")
        XCTAssertEqual(ingress.offer(Data(repeating: 0, count: UDPIngress.maximumDatagramSize + 1), from: source), .rejected)
        var dropped = 0
        for index in 0..<1000 {
            let packet = Data([UInt8(index >> 8),UInt8(truncatingIfNeeded: index)])
            if ingress.offer(packet, from: source) == .overflow { dropped += 1 }
        }
        XCTAssertEqual(dropped, 1000 - UDPIngress.capacity)
        ingress.finish()
        var delivered = [Int]()
        for await packet in ingress.packets {
            XCTAssertEqual(packet.source, source)
            delivered.append(Int(packet.payload[0]) << 8 | Int(packet.payload[1]))
        }
        XCTAssertEqual(delivered, Array((1000 - UDPIngress.capacity)..<1000))
        XCTAssertEqual(ingress.offer(Data([1]), from: source), .rejected)
    }

    func testLiveDERPRoundTrip() async throws {
        guard let host = ProcessInfo.processInfo.environment["TAILCAT_TEST_DERP_HOST"] else {
            throw XCTSkip("Set TAILCAT_TEST_DERP_HOST to run a real authenticated relay exchange")
        }
        let environment = ProcessInfo.processInfo.environment
        let node = DERPNode(hostName: host, derpPort: Int(environment["TAILCAT_TEST_DERP_PORT"] ?? "0") ?? 0,
                            insecureForTests: environment["TAILCAT_TEST_DERP_INSECURE"] == "1")
        let aKey = NaClBox.random(32), bKey = NaClBox.random(32)
        let badNode = DERPNode(hostName: "127.0.0.1", derpPort: 1, insecureForTests: true)
        // Also exercise failover from a refused endpoint to the working relay.
        let a = DERPTransport(nodes: [badNode,node], privateKey: aKey), b = DERPTransport(node: node, privateKey: bKey)
        do {
            try await a.connect(); try await b.connect()
            let expectedSource = try NaClBox.publicKey(for: aKey)
            let received = expectation(description: "DERP packet delivered")
            let receive = Task {
                for try await packet in b.packets {
                    XCTAssertEqual(packet.source, expectedSource)
                    XCTAssertEqual(packet.payload, Data("Swift DERP interoperability".utf8))
                    received.fulfill(); break
                }
            }
            try await a.send(to: NaClBox.publicKey(for: bKey), packet: Data("Swift DERP interoperability".utf8))
            await fulfillment(of: [received], timeout: 10)
            receive.cancel()
            await a.close(); await b.close()
        } catch { await a.close(); await b.close(); throw error }
    }

    func testLiveUDPDiscoverySelectsDirectPath() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let host = environment["TAILCAT_TEST_DERP_HOST"] else {
            throw XCTSkip("Set TAILCAT_TEST_DERP_HOST to test UDP discovery with a real relay")
        }
        let node = DERPNode(hostName: host, stunPort: -1,
                            derpPort: Int(environment["TAILCAT_TEST_DERP_PORT"] ?? "0") ?? 0,
                            insecureForTests: environment["TAILCAT_TEST_DERP_INSECURE"] == "1")
        let aKey = NaClBox.random(32), bKey = NaClBox.random(32)
        let aDisco = NaClBox.random(32), bDisco = NaClBox.random(32)
        let a = NetworkTransport(privateKey: aKey, discoPrivateKey: aDisco, relayNode: node)
        let b = NetworkTransport(privateKey: bKey, discoPrivateKey: bDisco, relayNode: node)
        do {
            try await a.start(); try await b.start()
            let aEndpoints = await a.localEndpoints(), bEndpoints = await b.localEndpoints()
            XCTAssertFalse(aEndpoints.isEmpty); XCTAssertFalse(bEndpoints.isEmpty)
            let aPublic = try NaClBox.publicKey(for: aKey), bPublic = try NaClBox.publicKey(for: bKey)
            try await a.configurePeer(nodeKey: bPublic, discoKey: NaClBox.publicKey(for: bDisco), endpoints: bEndpoints)
            try await b.configurePeer(nodeKey: aPublic, discoKey: NaClBox.publicKey(for: aDisco), endpoints: aEndpoints)
            let meow = expectation(description: "Meow stays on the authenticated relay")
            let direct = expectation(description: "Authenticated discovery selected a direct UDP path")
            let fallback = expectation(description: "Packets fall back to DERP after UDP path invalidation")
            let receive = Task {
                var sawDirect = false
                for try await packet in b.packets {
                    if packet.payload == Data("relay fallback".utf8) {
                        XCTAssertTrue(packet.viaRelay); fallback.fulfill(); break
                    }
                    if packet.payload == Data("meow\u{02}".utf8) {
                        XCTAssertTrue(packet.viaRelay); meow.fulfill()
                        await a.invalidateDirectPath(to: bPublic)
                        let path = await a.path(to: bPublic)
                        XCTAssertEqual(path, .relay)
                        try await a.send(to: bPublic, packet: Data("relay fallback".utf8))
                        continue
                    }
                    guard !packet.viaRelay, !sawDirect else { continue }
                    sawDirect = true
                    XCTAssertEqual(packet.source, aPublic)
                    XCTAssertEqual(packet.payload, Data("direct UDP".utf8))
                    let path = await a.path(to: bPublic)
                    guard case .direct = path else { XCTFail("Expected a verified direct UDP path"); return }
                    direct.fulfill()
                    // Once UDP is active the handshake acknowledgment must still use DERP.
                    try await a.send(to: bPublic, packet: Data("meow\u{02}".utf8))
                }
            }
            let send = Task {
                for _ in 0..<30 {
                    try await a.send(to: bPublic, packet: Data("direct UDP".utf8))
                    try await Task.sleep(nanoseconds: 100_000_000)
                }
            }
            await fulfillment(of: [direct,meow,fallback], timeout: 5)
            send.cancel(); receive.cancel()
            await a.close(); await b.close()
        } catch { await a.close(); await b.close(); throw error }
    }

    func testLiveAsymmetricIPv4OutboundIPv6Inbound() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let host = environment["TAILCAT_TEST_DERP_HOST"] else {
            throw XCTSkip("Set TAILCAT_TEST_DERP_HOST to test asymmetric UDP paths")
        }
        let node = DERPNode(hostName: host, stunPort: -1,
                            derpPort: Int(environment["TAILCAT_TEST_DERP_PORT"] ?? "0") ?? 0,
                            insecureForTests: environment["TAILCAT_TEST_DERP_INSECURE"] == "1")
        let nodeKey = NaClBox.random(32), discoKey = NaClBox.random(32)
        let peerKey = NaClBox.random(32), peerDisco = NaClBox.random(32)
        let peerPublic = try NaClBox.publicKey(for: peerKey)
        let discoPublic = try NaClBox.publicKey(for: discoKey)
        let transport = NetworkTransport(privateKey: nodeKey, discoPrivateKey: discoKey, relayNode: node)
        var output: AsyncStream<(Data, DiscoveryEndpoint)>.Continuation!
        let incoming = AsyncStream<(Data, DiscoveryEndpoint)> { output = $0 }
        let callback = output!
        let peerSocket = try UDPChannel { packet, endpoint in callback.yield((packet,endpoint)) }
        let peerIPv4 = DiscoveryEndpoint(host: "127.0.0.1", port: peerSocket.port)
        let transaction = NaClBox.random(12)
        let authenticatedIPv6 = expectation(description: "IPv6 source authenticated by discovery ping")
        let outboundAfterMaintenance = expectation(description: "IPv4 send survives periodic maintenance")
        let afterMaintenancePayload = Data("after maintenance".utf8)
        let responder = Task {
            for await (packet, endpoint) in incoming {
                if packet == afterMaintenancePayload {
                    XCTAssertEqual(endpoint.host, "127.0.0.1")
                    outboundAfterMaintenance.fulfill(); continue
                }
                guard let opened = try? Discovery.open(packet, privateKey: peerDisco) else { continue }
                switch opened.message {
                case let .ping(id, _):
                    // Respond only over IPv4 so the transport's outbound winner
                    // stays IPv4 while the peer deliberately sends data over IPv6.
                    guard endpoint.host == "127.0.0.1" else { continue }
                    let pong = try Discovery.seal(.pong(transaction: id, observed: endpoint), to: discoPublic, privateKey: peerDisco)
                    try await peerSocket.send(pong, to: endpoint)
                case let .pong(id, _) where id == transaction:
                    authenticatedIPv6.fulfill()
                default: break
                }
            }
        }
        defer { responder.cancel(); callback.finish(); peerSocket.close() }
        do {
            try await transport.start()
            try await transport.configurePeer(nodeKey: peerPublic, discoKey: NaClBox.publicKey(for: peerDisco), endpoints: [peerIPv4.description])
            var outbound: ConnectionPath = .relay
            for _ in 0..<30 {
                outbound = await transport.path(to: peerPublic)
                if outbound == .direct(endpoint: peerIPv4.description) { break }
                try await Task.sleep(nanoseconds: 50_000_000)
            }
            XCTAssertEqual(outbound, .direct(endpoint: peerIPv4.description))
            let local = await transport.localEndpoints()
            let localEndpoint = try XCTUnwrap(local.first).description
            let port = try DiscoveryEndpoint(localEndpoint).port
            let nativeIPv6 = DiscoveryEndpoint(host: "::1", port: port)
            let ping = try Discovery.seal(.ping(transaction: transaction, nodeKey: peerPublic), to: discoPublic, privateKey: peerDisco)
            try await peerSocket.send(ping, to: nativeIPv6)
            await fulfillment(of: [authenticatedIPv6], timeout: 2)
            let received = expectation(description: "IPv6 datagram delivered despite IPv4 outbound preference")
            let receivedAfterMaintenance = expectation(description: "IPv6 receive binding survives periodic maintenance")
            let payload = Data("asymmetric IPv6 packet".utf8)
            let receive = Task {
                for try await packet in transport.packets {
                    XCTAssertEqual(packet.source, peerPublic)
                    XCTAssertFalse(packet.viaRelay)
                    if packet.payload == afterMaintenancePayload {
                        receivedAfterMaintenance.fulfill(); break
                    }
                    XCTAssertEqual(packet.payload, payload)
                    received.fulfill()
                }
            }
            try await peerSocket.send(payload, to: nativeIPv6)
            await fulfillment(of: [received], timeout: 2)
            // The maintenance loop runs every five seconds. Keep an authenticated
            // peer alive across that tick, then exercise both directions again.
            try await Task.sleep(nanoseconds: 6_000_000_000)
            try await peerSocket.send(afterMaintenancePayload, to: nativeIPv6)
            try await transport.send(to: peerPublic, packet: afterMaintenancePayload)
            await fulfillment(of: [receivedAfterMaintenance,outboundAfterMaintenance], timeout: 2)
            let finalPath = await transport.path(to: peerPublic)
            XCTAssertEqual(finalPath, .direct(endpoint: peerIPv4.description))
            receive.cancel(); await transport.close()
        } catch { await transport.close(); throw error }
    }
}