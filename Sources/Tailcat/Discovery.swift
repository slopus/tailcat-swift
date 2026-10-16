// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public enum TransportError: Error, Equatable, Sendable {
    case invalidKey, invalidNonce, authenticationFailed, malformedPacket, oversizedPacket
    case closed, timeout, invalidEndpoint, connectionFailed(String)
}

/// The NaCl crypto_box wire format: a 16-byte authenticator followed by ciphertext.
public enum NaClBox {
    public static func seal(_ message: Data, nonce: Data, publicKey: Data, privateKey: Data) throws -> Data {
        let key = try sharedKey(publicKey: publicKey, privateKey: privateKey)
        let stream = try salsaStream(key: key, nonce: nonce, count: message.count + 32)
        let encrypted = Data(zip(message, stream.dropFirst(32)).map { $0 ^ $1 })
        return poly1305(encrypted, key: Array(stream.prefix(32))) + encrypted
    }

    public static func open(_ message: Data, nonce: Data, publicKey: Data, privateKey: Data) throws -> Data {
        guard message.count >= 16 else { throw TransportError.authenticationFailed }
        let key = try sharedKey(publicKey: publicKey, privateKey: privateKey)
        let stream = try salsaStream(key: key, nonce: nonce, count: message.count - 16 + 32)
        let ciphertext = Data(message.dropFirst(16))
        let tag = poly1305(ciphertext, key: Array(stream.prefix(32)))
        var difference: UInt8 = 0
        for (a, b) in zip(tag, message.prefix(16)) { difference |= a ^ b }
        guard difference == 0 else { throw TransportError.authenticationFailed }
        return Data(zip(ciphertext, stream.dropFirst(32)).map { $0 ^ $1 })
    }

    public static func publicKey(for privateKey: Data) throws -> Data {
        guard privateKey.count == 32 else { throw TransportError.invalidKey }
        return try TailcatCrypto.publicKey(privateKey: privateKey)
    }

    static func random(_ count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }

    private static func sharedKey(publicKey: Data, privateKey: Data) throws -> [UInt8] {
        guard publicKey.count == 32, privateKey.count == 32 else { throw TransportError.invalidKey }
        let secret = try TailcatCrypto.sharedSecret(privateKey: privateKey, publicKey: publicKey)
        return hsalsa(key: Array(secret), nonce: [UInt8](repeating: 0, count: 16))
    }

    private static func word(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24
    }
    private static func bytes(_ words: [UInt32]) -> [UInt8] {
        words.flatMap { w in (0..<4).map { UInt8(truncatingIfNeeded: w >> ($0 * 8)) } }
    }
    private static func rotate(_ x: UInt32, _ n: UInt32) -> UInt32 { (x << n) | (x >> (32 - n)) }
    private static func rounds(_ input: [UInt32]) -> [UInt32] {
        var x = input
        func quarter(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            x[b] ^= rotate(x[a] &+ x[d], 7)
            x[c] ^= rotate(x[b] &+ x[a], 9)
            x[d] ^= rotate(x[c] &+ x[b], 13)
            x[a] ^= rotate(x[d] &+ x[c], 18)
        }
        for _ in 0..<10 {
            quarter(0,4,8,12); quarter(5,9,13,1); quarter(10,14,2,6); quarter(15,3,7,11)
            quarter(0,1,2,3); quarter(5,6,7,4); quarter(10,11,8,9); quarter(15,12,13,14)
        }
        return x
    }
    private static func state(key: [UInt8], nonce: [UInt8]) -> [UInt32] {
        let c = Array("expand 32-byte k".utf8)
        return [word(c,0),word(key,0),word(key,4),word(key,8),word(key,12),word(c,4),
                word(nonce,0),word(nonce,4),word(nonce,8),word(nonce,12),word(c,8),
                word(key,16),word(key,20),word(key,24),word(key,28),word(c,12)]
    }
    private static func hsalsa(key: [UInt8], nonce: [UInt8]) -> [UInt8] {
        let x = rounds(state(key: key, nonce: nonce))
        return bytes([x[0],x[5],x[10],x[15],x[6],x[7],x[8],x[9]])
    }
    private static func salsaStream(key: [UInt8], nonce: Data, count: Int) throws -> [UInt8] {
        guard nonce.count == 24 else { throw TransportError.invalidNonce }
        let n = Array(nonce)
        let subkey = hsalsa(key: key, nonce: Array(n.prefix(16)))
        var input = state(key: subkey, nonce: Array(n.suffix(8)) + [UInt8](repeating: 0, count: 8))
        var output = [UInt8](); output.reserveCapacity(count)
        while output.count < count {
            let x = rounds(input)
            output.append(contentsOf: bytes(zip(x,input).map { $0 &+ $1 }).prefix(count - output.count))
            input[8] &+= 1
            if input[8] == 0 { input[9] &+= 1 }
        }
        return output
    }

    // Five 26-bit limbs keep every multiplication below UInt64.max.
    private static func poly1305(_ data: Data, key: [UInt8]) -> Data {
        let mask: UInt64 = 0x3ffffff
        let r: [UInt64] = [UInt64(word(key,0)) & mask,
            UInt64(word(key,3) >> 2) & 0x3ffff03,
            UInt64(word(key,6) >> 4) & 0x3ffc0ff,
            UInt64(word(key,9) >> 6) & 0x3f03fff,
            UInt64(word(key,12) >> 8) & 0x00fffff]
        var h = [UInt64](repeating: 0, count: 5)
        let message = Array(data)
        for offset in stride(from: 0, to: message.count, by: 16) {
            let count = min(16, message.count - offset)
            var block = [UInt8](repeating: 0, count: 17)
            block.replaceSubrange(0..<count, with: message[offset..<(offset + count)])
            block[count] = 1
            h[0] += UInt64(word(block,0)) & mask
            h[1] += UInt64(word(block,3) >> 2) & mask
            h[2] += UInt64(word(block,6) >> 4) & mask
            h[3] += UInt64(word(block,9) >> 6) & mask
            h[4] += UInt64(word(block,12) >> 8) | UInt64(block[16]) << 24
            var d = [UInt64](repeating: 0, count: 5)
            for i in 0..<5 {
                for j in 0..<5 {
                    let k = (i - j + 5) % 5
                    d[i] += h[j] * r[k] * (j > i ? 5 : 1)
                }
            }
            for i in 0..<4 { d[i + 1] += d[i] >> 26; h[i] = d[i] & mask }
            h[4] = d[4] & mask; h[0] += (d[4] >> 26) * 5
            h[1] += h[0] >> 26; h[0] &= mask
        }
        for i in 1..<4 { h[i + 1] += h[i] >> 26; h[i] &= mask }
        h[0] += (h[4] >> 26) * 5; h[4] &= mask
        h[1] += h[0] >> 26; h[0] &= mask
        var g = h; g[0] += 5
        for i in 0..<4 { g[i + 1] += g[i] >> 26; g[i] &= mask }
        let select = UInt64(0) &- (g[4] >> 26)
        g[4] &= mask
        for i in 0..<5 { h[i] = (h[i] & ~select) | (g[i] & select) }
        var words: [UInt64] = [(h[0] | h[1] << 26) & 0xffffffff,
            (h[1] >> 6 | h[2] << 20) & 0xffffffff,
            (h[2] >> 12 | h[3] << 14) & 0xffffffff,
            (h[3] >> 18 | h[4] << 8) & 0xffffffff]
        var carry: UInt64 = 0
        for i in 0..<4 {
            words[i] += UInt64(word(key,16 + i * 4)) + carry
            carry = words[i] >> 32; words[i] &= 0xffffffff
        }
        return Data(bytes(words.map { UInt32($0) }))
    }
}

public struct DiscoveryEndpoint: Hashable, Sendable, CustomStringConvertible {
    public let host: String
    public let port: UInt16
    public var description: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }
    public init(host: String, port: UInt16) { self.host = host; self.port = port }
    public init(_ string: String) throws {
        if string.hasPrefix("["), let end = string.firstIndex(of: "]"), string.index(after: end) < string.endIndex,
           string[string.index(after: end)] == ":", let p = UInt16(string[string.index(end, offsetBy: 2)...]), p != 0 {
            self.init(host: String(string[string.index(after: string.startIndex)..<end]), port: p)
        } else if let colon = string.lastIndex(of: ":"), let p = UInt16(string[string.index(after: colon)...]), p != 0 {
            self.init(host: String(string[..<colon]), port: p)
        } else { throw TransportError.invalidEndpoint }
        self = try DiscoveryEndpoint(wire: wireBytes())
    }
    func wireBytes() throws -> Data {
        var address = in6_addr()
        if inet_pton(AF_INET6, host, &address) != 1 {
            var v4 = in_addr()
            guard inet_pton(AF_INET, host, &v4) == 1 else { throw TransportError.invalidEndpoint }
            var bytes = [UInt8](repeating: 0, count: 10) + [0xff,0xff]
            withUnsafeBytes(of: &v4) { bytes.append(contentsOf: $0) }
            return Data(bytes + [UInt8(port >> 8), UInt8(truncatingIfNeeded: port)])
        }
        return withUnsafeBytes(of: &address) { Data($0) } + Data([UInt8(port >> 8), UInt8(truncatingIfNeeded: port)])
    }
    init(wire: Data) throws {
        let b = Array(wire)
        guard b.count == 18 else { throw TransportError.malformedPacket }
        let v4 = b.prefix(12).elementsEqual([UInt8](repeating: 0, count: 10) + [0xff,0xff])
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let ip = v4 ? Array(b[12..<16]) : Array(b[0..<16])
        let result = ip.withUnsafeBytes { inet_ntop(v4 ? AF_INET : AF_INET6, $0.baseAddress, &buffer, socklen_t(buffer.count)) }
        guard result != nil else { throw TransportError.invalidEndpoint }
        self.init(host: String(cString: buffer), port: UInt16(b[16]) << 8 | UInt16(b[17]))
    }
}

public enum DiscoveryMessage: Equatable, Sendable {
    case ping(transaction: Data, nodeKey: Data?)
    case pong(transaction: Data, observed: DiscoveryEndpoint)
    case callMeMaybe([DiscoveryEndpoint])

    public func encode() throws -> Data {
        switch self {
        case let .ping(id, key):
            guard id.count == 12, key == nil || key?.count == 32 else { throw TransportError.malformedPacket }
            return Data([1,0]) + id + (key ?? Data())
        case let .pong(id, endpoint):
            guard id.count == 12 else { throw TransportError.malformedPacket }
            return Data([2,0]) + id + (try endpoint.wireBytes())
        case let .callMeMaybe(endpoints):
            guard endpoints.count <= 128 else { throw TransportError.oversizedPacket }
            return try endpoints.reduce(into: Data([3,0])) { $0.append(try $1.wireBytes()) }
        }
    }
    public init(encoded: Data) throws {
        let b = Array(encoded)
        guard b.count >= 2, b[1] == 0 else { throw TransportError.malformedPacket }
        switch b[0] {
        case 1:
            guard b.count >= 14 else { throw TransportError.malformedPacket }
            self = .ping(transaction: Data(b[2..<14]), nodeKey: b.count >= 46 ? Data(b[14..<46]) : nil)
        case 2:
            guard b.count >= 32 else { throw TransportError.malformedPacket }
            self = .pong(transaction: Data(b[2..<14]), observed: try DiscoveryEndpoint(wire: Data(b[14..<32])))
        case 3:
            guard (b.count - 2) % 18 == 0, b.count <= 2 + 128 * 18 else { throw TransportError.malformedPacket }
            self = .callMeMaybe(try stride(from: 2, to: b.count, by: 18).map { try DiscoveryEndpoint(wire: Data(b[$0..<($0 + 18)])) })
        default: throw TransportError.malformedPacket
        }
    }
}

public enum Discovery {
    public static let magic = Data("TS💬".utf8)
    public static func isPacket(_ packet: Data) -> Bool { packet.starts(with: magic) }
    public static func sourceKey(_ packet: Data) -> Data? {
        guard packet.starts(with: magic), packet.count >= 78 else { return nil }
        return Data(packet.dropFirst(6).prefix(32))
    }
    public static func seal(_ message: DiscoveryMessage, to key: Data, privateKey: Data) throws -> Data {
        let nonce = NaClBox.random(24)
        return magic + (try NaClBox.publicKey(for: privateKey)) + nonce +
            (try NaClBox.seal(message.encode(), nonce: nonce, publicKey: key, privateKey: privateKey))
    }
    public static func open(_ packet: Data, privateKey: Data) throws -> (source: Data, message: DiscoveryMessage) {
        let b = Array(packet)
        guard packet.starts(with: magic), b.count >= 78 else { throw TransportError.malformedPacket }
        let key = Data(b[6..<38])
        let payload = try NaClBox.open(Data(b[62...]), nonce: Data(b[38..<62]), publicKey: key, privateKey: privateKey)
        return (key, try DiscoveryMessage(encoded: payload))
    }
}

public enum STUN {
    public static func request(transaction: Data) throws -> Data {
        guard transaction.count == 12 else { throw TransportError.malformedPacket }
        return Data([0,1,0,0,0x21,0x12,0xa4,0x42]) + transaction
    }
    public static func response(_ packet: Data, transaction: Data) throws -> DiscoveryEndpoint {
        let b = Array(packet)
        guard b.count >= 20, b[0] == 1, b[1] == 1, b[4..<8].elementsEqual([0x21,0x12,0xa4,0x42]),
              transaction.count == 12, b[8..<20].elementsEqual(transaction) else { throw TransportError.malformedPacket }
        let end = 20 + Int(b[2]) * 256 + Int(b[3])
        guard end == b.count else { throw TransportError.malformedPacket }
        var offset = 20
        while offset + 4 <= end {
            let kind = UInt16(b[offset]) << 8 | UInt16(b[offset + 1])
            let length = Int(b[offset + 2]) * 256 + Int(b[offset + 3])
            offset += 4
            guard offset + length <= end else { throw TransportError.malformedPacket }
            if kind == 0x20 || kind == 1 {
                guard length >= 4 else { throw TransportError.malformedPacket }
                let family = b[offset + 1], size = b[offset + 1] == 1 ? 4 : 16
                guard (family == 1 || family == 2), length == 4 + size else { throw TransportError.malformedPacket }
                let xor = kind == 0x20
                let mask = [UInt8]([0x21,0x12,0xa4,0x42]) + Array(transaction)
                let port = (UInt16(b[offset + 2]) << 8 | UInt16(b[offset + 3])) ^ (xor ? 0x2112 : 0)
                let ip = (0..<size).map { b[offset + 4 + $0] ^ (xor ? mask[$0] : 0) }
                let wire = (size == 4 ? [UInt8](repeating: 0, count: 10) + [0xff,0xff] + ip : ip)
                    + [UInt8(port >> 8),UInt8(truncatingIfNeeded: port)]
                return try DiscoveryEndpoint(wire: Data(wire))
            }
            offset += (length + 3) & ~3
        }
        throw TransportError.malformedPacket
    }
}