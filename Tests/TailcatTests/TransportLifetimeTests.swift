import XCTest
@testable import Tailcat

#if canImport(Glibc)
import Glibc

/// Accepts TCP but deliberately never replies to the HTTP upgrade request.
private final class StalledRelay: @unchecked Sendable {
    let port: Int
    private let source: DispatchSourceRead
    private let descriptor: Int32
    private let lock = NSLock()
    private var clients = [Int32]()
    private var closed = false

    init(accepted: @escaping @Sendable () -> Void) throws {
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw TransportError.connectionFailed("test socket") }
        descriptor = fd
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0, listen(fd, 4) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else {
            Glibc.close(fd); throw TransportError.connectionFailed("test listen")
        }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard named == 0 else { Glibc.close(fd); throw TransportError.connectionFailed("test port") }
        port = Int(UInt16(bigEndian: address.sin_port))
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .global())
        source.setEventHandler { [weak self] in
            let client = accept(fd, nil, nil)
            guard client >= 0, let self else { if client >= 0 { Glibc.close(client) }; return }
            self.lock.lock()
            if self.closed { Glibc.close(client) }
            else { self.clients.append(client) }
            self.lock.unlock()
            accepted()
        }
        source.setCancelHandler { Glibc.close(fd) }
        source.resume()
    }
    func close() {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        for fd in clients { _ = shutdown(fd, Int32(SHUT_RDWR)); Glibc.close(fd) }
        clients.removeAll(); lock.unlock()
        source.cancel()
    }
    deinit { close() }
    var node: DERPNode { DERPNode(hostName: "127.0.0.1", stunPort: -1, derpPort: port, insecureForTests: true) }
}

final class TransportLifetimeTests: XCTestCase {
    func testClosePublicServerDuringStartup() async throws {
        let accepted = expectation(description: "TCP accepted")
        let fixture = try StalledRelay { accepted.fulfill() }
        defer { fixture.close() }
        var config = TailcatServer.Configuration()
        config.region = DERPRegion(regionID: 1, nodes: [fixture.node])
        let server = TailcatServer(configuration: config)
        let pending = Task { try await server.start() }
        await fulfillment(of: [accepted], timeout: 2)
        let completed = expectation(description: "Public startup closed promptly")
        let observe = Task {
            await server.close()
            do { try await pending.value; XCTFail("Closed server started") } catch {}
            completed.fulfill()
        }
        await fulfillment(of: [completed], timeout: 1)
        await observe.value
    }

    func testCancelPendingDERPConnect() async throws {
        let accepted = expectation(description: "TCP accepted")
        let fixture = try StalledRelay { accepted.fulfill() }
        defer { fixture.close() }
        let relay = DERPTransport(node: fixture.node, privateKey: Data(repeating: 0x42, count: 32))
        let pending = Task { try await relay.connect() }
        await fulfillment(of: [accepted], timeout: 2)
        let completed = expectation(description: "Cancelled startup completed promptly")
        let observe = Task {
            do { try await pending.value; XCTFail("Cancelled connection succeeded") } catch {}
            completed.fulfill()
        }
        pending.cancel()
        await fulfillment(of: [completed], timeout: 1)
        await relay.close(); await observe.value
    }

    func testClosePendingDERPConnect() async throws {
        let accepted = expectation(description: "TCP accepted")
        let fixture = try StalledRelay { accepted.fulfill() }
        defer { fixture.close() }
        let relay = DERPTransport(node: fixture.node, privateKey: Data(repeating: 0x42, count: 32))
        let pending = Task { try await relay.connect() }
        await fulfillment(of: [accepted], timeout: 2)
        let completed = expectation(description: "Closed startup completed promptly")
        let observe = Task {
            do { try await pending.value; XCTFail("Closed connection succeeded") } catch {}
            completed.fulfill()
        }
        await relay.close()
        await fulfillment(of: [completed], timeout: 1)
        await observe.value
    }

    func testCancelPendingNetworkStart() async throws {
        let accepted = expectation(description: "TCP accepted")
        let fixture = try StalledRelay { accepted.fulfill() }
        defer { fixture.close() }
        let transport = NetworkTransport(privateKey: Data(repeating: 0x42, count: 32),
                                         discoPrivateKey: Data(repeating: 0x43, count: 32), relayNode: fixture.node)
        let pending = Task { try await transport.start() }
        await fulfillment(of: [accepted], timeout: 2)
        let completed = expectation(description: "Cancelled transport startup completed promptly")
        let observe = Task {
            do { try await pending.value; XCTFail("Cancelled transport succeeded") } catch {}
            completed.fulfill()
        }
        pending.cancel()
        await fulfillment(of: [completed], timeout: 1)
        await transport.close(); await observe.value
    }
}
#endif