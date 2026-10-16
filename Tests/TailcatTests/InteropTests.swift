import XCTest
@testable import Tailcat

/// Opt-in tests against an independently running upstream peer; no Go code ships in this package.
final class InteropTests: XCTestCase {
    func testNativeServerForUpstreamClient() async throws {
        guard let relayPort = ProcessInfo.processInfo.environment["TAILCAT_SERVE_TEST_RELAY_PORT"].flatMap(Int.init) else { throw XCTSkip("Set TAILCAT_SERVE_TEST_RELAY_PORT for the upstream client fixture") }
        var configuration = TailcatServer.Configuration()
        configuration.region = DERPRegion(regionID: 1, nodes: [DERPNode(hostName: "127.0.0.1", ipv4: "127.0.0.1", ipv6: "none", stunPort: -1, derpPort: relayPort, insecureForTests: true)])
        let server = TailcatServer(configuration: configuration)
        try await server.start()
        let tcp = try await server.listen(port: 80)
        let udp = try await server.listenUDP(port: 53)
        let address = try await server.address
        print("NATIVE_SERVER_ADDRESS=\(address)")
        if let path = ProcessInfo.processInfo.environment["TAILCAT_TEST_ADDRESS_FILE"] { try address.description.write(toFile: path, atomically: true, encoding: .utf8) }
        let tcpTask = Task {
            while !Task.isCancelled {
                guard let stream = try? await tcp.accept() else { break }
                Task {
                    do {
                        while true { let bytes = try await stream.read(); if bytes.isEmpty { break }; try await stream.write(bytes) }
                        try await stream.closeWrite()
                    } catch {}
                    await stream.close()
                }
            }
        }
        let udpTask = Task {
            while !Task.isCancelled {
                guard let flow = try? await udp.accept() else { break }
                Task { do { while true { try await flow.write(flow.read()) } } catch { await flow.close() } }
            }
        }
        let seconds = ProcessInfo.processInfo.environment["TAILCAT_SERVE_TEST_SECONDS"].flatMap(UInt64.init) ?? 90
        try await Task.sleep(nanoseconds: seconds * 1_000_000_000)
        tcpTask.cancel(); udpTask.cancel(); await server.close()
    }

    func testUpstreamEcho() async throws {
        guard let text = ProcessInfo.processInfo.environment["TAILCAT_UPSTREAM_ADDRESS"] else { throw XCTSkip("Set TAILCAT_UPSTREAM_ADDRESS to an upstream echo server (TCP80/UDP53)") }
        let client = try await TailcatClient.connect(to: text)
        do {
            let tcp = try await client.openTCP(port: 80)
            let payload = Data((0..<262_144).map { UInt8(truncatingIfNeeded: $0 &* 37) })
            let writer = Task { try await tcp.write(payload); try await tcp.closeWrite() }
            var response = Data()
            while true { let bytes = try await tcp.read(); if bytes.isEmpty { break }; response.append(bytes) }
            try await writer.value
            XCTAssertEqual(response, payload)
            await tcp.close()
            let udp = try await client.openUDP(port: 53)
            for count in [1, 31, 1232] {
                let datagram = Data((0..<count).map { UInt8(truncatingIfNeeded: $0) })
                try await udp.write(datagram)
                let echoed = try await udp.read()
                XCTAssertEqual(echoed, datagram)
            }
            await udp.close(); await client.close()
        } catch { await client.close(); throw error }
    }
}