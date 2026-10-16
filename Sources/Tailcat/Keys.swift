// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation

public enum TailcatError: Error, Equatable, Sendable {
    case invalidKey, invalidPacket, closed, timedOut, notStarted, alreadyStarted, noRelay, peerRejected, bufferFull
    case invalidAddress(String), unsupported(String)
}

/// A WireGuard node identity. Its raw representation is exactly 32 bytes.
public struct NodePublicKey: Hashable, Sendable, Codable, CustomStringConvertible {
    public let rawValue: Data
    public init(rawValue: Data) throws {
        guard rawValue.count == 32 else { throw TailcatError.invalidKey }
        self.rawValue = Data(rawValue)
    }
    public init(_ text: String) throws {
        guard text.hasPrefix("nodekey:"), let bytes = Data(tailcatHex: String(text.dropFirst(8))) else { throw TailcatError.invalidKey }
        try self.init(rawValue: bytes)
    }
    public var description: String { "nodekey:" + rawValue.tailcatHex }
    public var address: Data { Data([0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0]) + rawValue.prefix(10) }
    public init(from decoder: Decoder) throws { try self.init(decoder.singleValueContainer().decode(String.self)) }
    public func encode(to encoder: Encoder) throws { var c = encoder.singleValueContainer(); try c.encode(description) }
}

/// Persist the private key to keep the same node and discovery identities across launches.
public struct NodePrivateKey: Sendable, Codable {
    public let rawValue: Data
    public init(rawValue: Data) throws {
        guard rawValue.count == 32 else { throw TailcatError.invalidKey }
        var value = Data(rawValue)
        value[0] &= 248; value[31] &= 127; value[31] |= 64
        self.rawValue = value
    }
    public static func generate() throws -> Self { try Self(rawValue: TailcatCrypto.randomBytes(count: 32)) }
    public var publicKey: NodePublicKey { get throws { try NodePublicKey(rawValue: TailcatCrypto.publicKey(privateKey: rawValue)) } }
    internal var discoPrivateKey: Data {
        var value = TailcatCrypto.hmacSHA256(key: rawValue, message: Data("github.com/tailscale/tailcat disco key v1".utf8))
        value[0] &= 248; value[31] &= 127; value[31] |= 64
        return value
    }
    public var discoPublicKey: Data { get throws { try TailcatCrypto.publicKey(privateKey: discoPrivateKey) } }
    public init(from decoder: Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard text.hasPrefix("privkey:"), let bytes = Data(tailcatHex: String(text.dropFirst(8))) else { throw TailcatError.invalidKey }
        try self.init(rawValue: bytes)
    }
    public func encode(to encoder: Encoder) throws { var c = encoder.singleValueContainer(); try c.encode("privkey:" + rawValue.tailcatHex) }
}

public struct PresharedKey: Sendable, Equatable, Codable {
    public let rawValue: Data
    public init(rawValue: Data) throws {
        guard rawValue.count == 32 else { throw TailcatError.invalidKey }
        self.rawValue = Data(rawValue)
    }
    public static func generate() throws -> Self { try Self(rawValue: TailcatCrypto.randomBytes(count: 32)) }
    public var isZero: Bool { rawValue.allSatisfy { $0 == 0 } }
    public static func == (lhs: Self, rhs: Self) -> Bool { zip(lhs.rawValue, rhs.rawValue).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0 }
    public init(from decoder: Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard text.hasPrefix("psk:"), let data = Data(tailcatHex: String(text.dropFirst(4))) else { throw TailcatError.invalidKey }
        try self.init(rawValue: data)
    }
    public func encode(to encoder: Encoder) throws { var c = encoder.singleValueContainer(); try c.encode("psk:" + rawValue.tailcatHex) }
}

/// A concurrent allow-list for `TailcatServer.Configuration.allowClient`.
public final class KeySet: @unchecked Sendable {
    private let lock = NSLock()
    private var values: Set<NodePublicKey> = []
    public init() {}
    public func add(_ key: NodePublicKey) { lock.lock(); defer { lock.unlock() }; values.insert(key) }
    public func remove(_ key: NodePublicKey) { lock.lock(); defer { lock.unlock() }; values.remove(key) }
    public func contains(_ key: NodePublicKey) -> Bool { lock.lock(); defer { lock.unlock() }; return values.contains(key) }
}

extension Data {
    internal var tailcatHex: String { map { String(format: "%02x", $0) }.joined() }
    internal init?(tailcatHex: String) {
        guard tailcatHex.count.isMultiple(of: 2) else { return nil }
        var data = Data(); var index = tailcatHex.startIndex
        while index < tailcatHex.endIndex {
            let end = tailcatHex.index(index, offsetBy: 2)
            guard let byte = UInt8(tailcatHex[index..<end], radix: 16) else { return nil }
            data.append(byte); index = end
        }
        self = data
    }
}