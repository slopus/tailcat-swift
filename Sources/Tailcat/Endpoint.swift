// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// An IP and port. IPv4 destinations use upstream's 64:ff9b::/96 mapping inside the tunnel.
public struct TailcatEndpoint: Sendable, Hashable, CustomStringConvertible {
    public let tunnelAddress: Data
    public let port: UInt16
    private static let nat64 = Data([0x00, 0x64, 0xff, 0x9b] + [UInt8](repeating: 0, count: 8))
    public init(ipAddress: String, port: UInt16) throws {
        guard port > 0 else { throw TailcatTransportError.invalidPort }
        var v4 = in_addr(); var v6 = in6_addr()
        if inet_pton(AF_INET, ipAddress, &v4) == 1 {
            tunnelAddress = Self.nat64 + withUnsafeBytes(of: &v4) { Data($0) }
        } else if inet_pton(AF_INET6, ipAddress, &v6) == 1 {
            tunnelAddress = withUnsafeBytes(of: &v6) { Data($0) }
        } else { throw TailcatTransportError.invalidAddress }
        self.port = port
    }
    public init(tunnelAddress: Data, port: UInt16) throws {
        guard tunnelAddress.count == 16 else { throw TailcatTransportError.invalidAddress }
        guard port > 0 else { throw TailcatTransportError.invalidPort }
        self.tunnelAddress = Data(tunnelAddress); self.port = port
    }
    public var ipAddress: String {
        let ipv4 = tunnelAddress.prefix(12) == Self.nat64
        let bytes = ipv4 ? Data(tunnelAddress.suffix(4)) : tunnelAddress
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = bytes.withUnsafeBytes { inet_ntop(ipv4 ? AF_INET : AF_INET6, $0.baseAddress, &output, socklen_t(output.count)) }
        return result == nil ? "" : String(cString: output)
    }
    public var description: String { ipAddress.contains(":") ? "[\(ipAddress)]:\(port)" : "\(ipAddress):\(port)" }
}

public typealias TailcatTCPHandler = @Sendable (TailcatConnection) async -> Void
public typealias TailcatUDPHandler = @Sendable (TailcatUDPConnection) async -> Void

/// Copy two streams in both directions, propagating FIN and waiting for delivery before closing.
public func proxyConnections(_ first: TailcatConnection, _ second: TailcatConnection) async throws {
    do {
        try await withThrowingTaskGroup(of: Void.self) { group in
            for (source, destination) in [(first, second), (second, first)] {
                group.addTask {
                    while true {
                        let data = try await source.read()
                        if data.isEmpty { try await destination.closeWrite(); return }
                        try await destination.write(data)
                    }
                }
            }
            try await group.waitForAll()
        }
        await first.close(); await second.close()
    } catch { await first.close(); await second.close(); throw error }
}