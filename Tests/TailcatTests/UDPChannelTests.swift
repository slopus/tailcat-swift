import XCTest
@testable import Tailcat

#if canImport(Darwin)
import Darwin

final class UDPChannelTests: XCTestCase {
    func testWriteToShutdownSocketReturnsBrokenPipeWithoutSignalling() throws {
        // Use the production socket factory. UDP sendto on Darwin raises
        // SIGPIPE as well as returning EPIPE when the socket cannot send.
        let fd = try UDPChannel.makeSocket()
        defer { Darwin.close(fd) }
        var suppressed: Int32 = 0
        var size = socklen_t(MemoryLayout<Int32>.size)
        XCTAssertEqual(getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &suppressed, &size), 0)
        // Fail safely even when the runner has SIGPIPE's default disposition.
        guard suppressed == 1 else {
            XCTFail("UDP socket must suppress SIGPIPE before its first write")
            return
        }

        var remote = sockaddr_in6()
        remote.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        remote.sin6_family = sa_family_t(AF_INET6)
        remote.sin6_port = UInt16(9).bigEndian
        remote.sin6_addr = in6addr_loopback
        let connected = withUnsafePointer(to: &remote) { address in
            address.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        XCTAssertEqual(connected, 0)
        XCTAssertEqual(shutdown(fd, SHUT_WR), 0)
        let data = Data([1])
        let written = data.withUnsafeBytes { bytes in
            withUnsafePointer(to: &remote) { address in
                address.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, bytes.baseAddress, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        }
        let error = errno
        XCTAssertEqual(written, -1)
        XCTAssertEqual(error, EPIPE)
    }
}
#endif