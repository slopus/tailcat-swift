// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation

/// The bounded CBOR subset used by tailcat addresses.
internal indirect enum CBOR {
    case integer(Int64), bytes(Data), text(String), array([CBOR]), map([(String, CBOR)]), bool(Bool), null
    var bytes: Data? { if case .bytes(let v) = self { return v }; return nil }
    var text: String? { if case .text(let v) = self { return v }; return nil }
    var integer: Int? { if case .integer(let v) = self { return Int(exactly: v) }; return nil }
    var array: [CBOR]? { if case .array(let v) = self { return v }; return nil }
    var bool: Bool? { if case .bool(let v) = self { return v }; return nil }
    var dictionary: [String: CBOR]? { if case .map(let v) = self { return Dictionary(uniqueKeysWithValues: v) }; return nil }
    func encode() -> Data {
        func head(_ major: UInt8, _ count: UInt64) -> Data {
            let prefix = major << 5
            if count < 24 { return Data([prefix | UInt8(count)]) }
            if count <= 255 { return Data([prefix | 24, UInt8(count)]) }
            let size = count <= 65535 ? 2 : count <= 0xffff_ffff ? 4 : 8
            return Data([prefix | (size == 2 ? 25 : size == 4 ? 26 : 27)]) + Data((0..<size).reversed().map { UInt8(truncatingIfNeeded: count >> ($0 * 8)) })
        }
        switch self {
        case .integer(let n): return n >= 0 ? head(0, UInt64(n)) : head(1, UInt64(-(n + 1)))
        case .bytes(let d): return head(2, UInt64(d.count)) + d
        case .text(let t): let d = Data(t.utf8); return head(3, UInt64(d.count)) + d
        case .array(let a): return a.reduce(head(4, UInt64(a.count))) { $0 + $1.encode() }
        case .map(let m): return m.reduce(head(5, UInt64(m.count))) { $0 + CBOR.text($1.0).encode() + $1.1.encode() }
        case .bool(let b): return Data([b ? 0xf5 : 0xf4])
        case .null: return Data([0xf6])
        }
    }
    static func decode(_ data: Data) throws -> CBOR {
        guard data.count <= 65_536 else { throw TailcatError.invalidAddress("CBOR exceeds size limit") }
        let bytes = [UInt8](data); var cursor = 0
        func parse(_ depth: Int) throws -> CBOR {
            guard depth <= 24, cursor < bytes.count else { throw TailcatError.invalidAddress("truncated or nested CBOR") }
            let first = bytes[cursor]; cursor += 1
            let major = first >> 5; let additional = first & 31
            if major == 7 {
                switch additional {
                case 20: return .bool(false)
                case 21: return .bool(true)
                case 22: return .null
                default: throw TailcatError.invalidAddress("unsupported CBOR value")
                }
            }
            var number = UInt64(additional)
            if additional >= 24 {
                guard additional <= 27 else { throw TailcatError.invalidAddress("indefinite CBOR is unsupported") }
                let size = 1 << (additional - 24)
                guard cursor + size <= bytes.count else { throw TailcatError.invalidAddress("truncated CBOR length") }
                number = 0
                for _ in 0..<size { number = number << 8 | UInt64(bytes[cursor]); cursor += 1 }
            }
            if major <= 1 {
                guard number <= UInt64(Int64.max) else { throw TailcatError.invalidAddress("integer overflow") }
                return .integer(major == 0 ? Int64(number) : -1 - Int64(number))
            }
            guard number <= 65_536 else { throw TailcatError.invalidAddress("CBOR length exceeds limit") }
            let count = Int(number)
            switch major {
            case 2, 3:
                guard count <= bytes.count - cursor else { throw TailcatError.invalidAddress("truncated CBOR string") }
                let value = Data(bytes[cursor..<(cursor + count)]); cursor += count
                if major == 2 { return .bytes(value) }
                guard let text = String(data: value, encoding: .utf8) else { throw TailcatError.invalidAddress("invalid UTF-8") }
                return .text(text)
            case 4:
                guard count <= bytes.count - cursor else { throw TailcatError.invalidAddress("truncated CBOR array") }
                var result: [CBOR] = []
                for _ in 0..<count { result.append(try parse(depth + 1)) }
                return .array(result)
            case 5:
                guard count <= (bytes.count - cursor) / 2 else { throw TailcatError.invalidAddress("truncated CBOR map") }
                var result: [(String, CBOR)] = []; var keys: Set<String> = []
                for _ in 0..<count {
                    guard let key = try parse(depth + 1).text, keys.insert(key).inserted else { throw TailcatError.invalidAddress("invalid or duplicate map key") }
                    result.append((key, try parse(depth + 1)))
                }
                return .map(result)
            default: throw TailcatError.invalidAddress("unsupported CBOR type")
            }
        }
        let result = try parse(0)
        guard cursor == bytes.count else { throw TailcatError.invalidAddress("trailing CBOR data") }
        return result
    }
}