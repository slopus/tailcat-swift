// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// System CryptoKit on Apple; portable Swift primitives for platforms without it.
/// WireGuard uses BLAKE2s with both 16 and 32 byte digest parameters (not truncation).
enum TailcatCrypto {
    enum Error: Swift.Error { case invalidKey, invalidNonce, authenticationFailed, invalidLength }

    static func randomBytes(count: Int) throws -> Data {
        guard count >= 0 else { throw Error.invalidLength }
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }

    static func publicKey(privateKey: Data) throws -> Data {
        guard privateKey.count == 32 else { throw Error.invalidKey }
        #if canImport(CryptoKit)
        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation
        #else
        return try x25519(privateKey, Data([9] + [UInt8](repeating: 0, count: 31)))
        #endif
    }

    static func sharedSecret(privateKey: Data, publicKey: Data) throws -> Data {
        guard privateKey.count == 32, publicKey.count == 32 else { throw Error.invalidKey }
        #if canImport(CryptoKit)
        let secret = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            .sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey))
        let result = secret.withUnsafeBytes { Data($0) }
        #else
        let result = try x25519(privateKey, publicKey)
        #endif
        guard result.contains(where: { $0 != 0 }) else { throw Error.invalidKey }
        return result
    }

    static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for (x, y) in zip(a, b) { difference |= x ^ y }
        return difference == 0
    }

    static func sha256(_ data: Data) -> Data {
        #if canImport(CryptoKit)
        return Data(SHA256.hash(data: data))
        #else
        let constants: [UInt32] = [
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
        var bytes = [UInt8](data)
        let bits = UInt64(bytes.count) &* 8
        bytes.append(0x80)
        while bytes.count % 64 != 56 { bytes.append(0) }
        bytes += (0..<8).reversed().map { UInt8(truncatingIfNeeded: bits >> ($0 * 8)) }
        var state: [UInt32] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
        for offset in stride(from: 0, to: bytes.count, by: 64) {
            var w = [UInt32](repeating: 0, count: 64)
            for i in 0..<16 {
                let j = offset + i * 4
                w[i] = UInt32(bytes[j]) << 24 | UInt32(bytes[j+1]) << 16 | UInt32(bytes[j+2]) << 8 | UInt32(bytes[j+3])
            }
            for i in 16..<64 {
                let x = w[i-15], y = w[i-2]
                w[i] = w[i-16] &+ (rotate(x,7) ^ rotate(x,18) ^ (x >> 3)) &+ w[i-7] &+ (rotate(y,17) ^ rotate(y,19) ^ (y >> 10))
            }
            var a=state[0], b=state[1], c=state[2], d=state[3], e=state[4], f=state[5], g=state[6], h=state[7]
            for i in 0..<64 {
                let t1 = h &+ (rotate(e,6) ^ rotate(e,11) ^ rotate(e,25)) &+ ((e & f) ^ (~e & g)) &+ constants[i] &+ w[i]
                let t2 = (rotate(a,2) ^ rotate(a,13) ^ rotate(a,22)) &+ ((a & b) ^ (a & c) ^ (b & c))
                h=g; g=f; f=e; e=d &+ t1; d=c; c=b; b=a; a=t1 &+ t2
            }
            let working = [a,b,c,d,e,f,g,h]
            for i in 0..<8 { state[i] = state[i] &+ working[i] }
        }
        return Data(state.flatMap { word in (0..<4).reversed().map { UInt8(truncatingIfNeeded: word >> ($0*8)) } })
        #endif
    }

    static func hmacSHA256(key: Data, message: Data) -> Data {
        hmac(key: key, message: message, hash: sha256)
    }

    static func hmacBlake2s(key: Data, message: Data) -> Data {
        hmac(key: key, message: message, hash: { blake2s($0) })
    }

    private static func hmac(key: Data, message: Data, hash: (Data) -> Data) -> Data {
        var k = [UInt8](key.count > 64 ? hash(key) : key)
        k += [UInt8](repeating: 0, count: 64 - k.count)
        return hash(Data(k.map { $0 ^ 0x5c }) + hash(Data(k.map { $0 ^ 0x36 }) + message))
    }

    static func blake2s(_ data: Data, key: Data = Data()) -> Data {
        blake2s(data, key: key, digestLength: 32)
    }

    static func blake2s(_ data: Data, key: Data, digestLength: Int) -> Data {
        precondition(key.count <= 32 && (1...32).contains(digestLength))
        let iv: [UInt32] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
        let sigma = [
            [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15], [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
            [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4], [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
            [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13], [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
            [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11], [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
            [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5], [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]]
        var h = iv
        h[0] ^= 0x01010000 ^ UInt32(key.count << 8) ^ UInt32(digestLength)
        var input = [UInt8]()
        if !key.isEmpty { input = [UInt8](key) + [UInt8](repeating: 0, count: 64-key.count) }
        input += data
        let blocks = max(1, (input.count + 63) / 64)
        for block in 0..<blocks {
            let offset = block * 64, used = min(64, input.count - offset)
            var bytes = [UInt8](repeating: 0, count: 64)
            if used > 0 { bytes.replaceSubrange(0..<used, with: input[offset..<offset+used]) }
            let m = (0..<16).map { load32(bytes, $0*4) }
            var v = h + iv
            let count = UInt64(offset + used)
            v[12] ^= UInt32(truncatingIfNeeded: count); v[13] ^= UInt32(count >> 32)
            if block == blocks-1 { v[14] = ~v[14] }
            func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
                v[a] = v[a] &+ v[b] &+ x; v[d] = rotate(v[d] ^ v[a],16)
                v[c] = v[c] &+ v[d]; v[b] = rotate(v[b] ^ v[c],12)
                v[a] = v[a] &+ v[b] &+ y; v[d] = rotate(v[d] ^ v[a],8)
                v[c] = v[c] &+ v[d]; v[b] = rotate(v[b] ^ v[c],7)
            }
            for s in sigma {
                g(0,4,8,12,m[s[0]],m[s[1]]); g(1,5,9,13,m[s[2]],m[s[3]])
                g(2,6,10,14,m[s[4]],m[s[5]]); g(3,7,11,15,m[s[6]],m[s[7]])
                g(0,5,10,15,m[s[8]],m[s[9]]); g(1,6,11,12,m[s[10]],m[s[11]])
                g(2,7,8,13,m[s[12]],m[s[13]]); g(3,4,9,14,m[s[14]],m[s[15]])
            }
            for i in 0..<8 { h[i] ^= v[i] ^ v[i+8] }
        }
        return Data(h.flatMap(littleEndianBytes).prefix(digestLength))
    }

    static func seal(_ plaintext: Data, key: Data, nonce: Data, authenticating aad: Data = Data()) throws -> Data {
        guard key.count == 32 else { throw Error.invalidKey }
        guard nonce.count == 12 else { throw Error.invalidNonce }
        #if canImport(CryptoKit)
        let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key), nonce: ChaChaPoly.Nonce(data: nonce), authenticating: aad)
        return box.ciphertext + box.tag
        #else
        let ciphertext = try chacha(plaintext, key: key, nonce: nonce, counter: 1)
        return ciphertext + poly1305(aeadInput(aad, ciphertext), key: Data(chachaBlock(key: key, nonce: nonce, counter: 0).prefix(32)))
        #endif
    }

    static func open(_ ciphertext: Data, key: Data, nonce: Data, authenticating aad: Data = Data()) throws -> Data {
        guard key.count == 32 else { throw Error.invalidKey }
        guard nonce.count == 12 else { throw Error.invalidNonce }
        guard ciphertext.count >= 16 else { throw Error.authenticationFailed }
        #if canImport(CryptoKit)
        return try ChaChaPoly.open(ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce), ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16)), using: SymmetricKey(data: key), authenticating: aad)
        #else
        let body = Data(ciphertext.dropLast(16))
        let tag = poly1305(aeadInput(aad, body), key: Data(chachaBlock(key: key, nonce: nonce, counter: 0).prefix(32)))
        guard constantTimeEqual(tag, Data(ciphertext.suffix(16))) else { throw Error.authenticationFailed }
        return try chacha(body, key: key, nonce: nonce, counter: 1)
        #endif
    }

    static func xSeal(_ plaintext: Data, key: Data, nonce: Data, authenticating aad: Data = Data()) throws -> Data {
        guard key.count == 32, nonce.count == 24 else { throw Error.invalidNonce }
        return try seal(plaintext, key: hChaCha(key: key, nonce: Data(nonce.prefix(16))), nonce: Data(repeating: 0, count: 4) + nonce.suffix(8), authenticating: aad)
    }

    static func xOpen(_ ciphertext: Data, key: Data, nonce: Data, authenticating aad: Data = Data()) throws -> Data {
        guard key.count == 32, nonce.count == 24 else { throw Error.invalidNonce }
        return try open(ciphertext, key: hChaCha(key: key, nonce: Data(nonce.prefix(16))), nonce: Data(repeating: 0, count: 4) + nonce.suffix(8), authenticating: aad)
    }

    private static func rotate(_ x: UInt32, _ n: Int) -> UInt32 { (x >> n) | (x << (32-n)) }
    private static func load32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) | UInt32(bytes[offset+1]) << 8 | UInt32(bytes[offset+2]) << 16 | UInt32(bytes[offset+3]) << 24
    }
    private static func littleEndianBytes(_ x: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: x >> ($0*8)) } }
    private static func rounds(_ state: inout [UInt32]) {
        func q(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            state[a] = state[a] &+ state[b]; state[d] = rotate(state[d] ^ state[a],16)
            state[c] = state[c] &+ state[d]; state[b] = rotate(state[b] ^ state[c],20)
            state[a] = state[a] &+ state[b]; state[d] = rotate(state[d] ^ state[a],24)
            state[c] = state[c] &+ state[d]; state[b] = rotate(state[b] ^ state[c],25)
        }
        for _ in 0..<10 {
            q(0,4,8,12); q(1,5,9,13); q(2,6,10,14); q(3,7,11,15)
            q(0,5,10,15); q(1,6,11,12); q(2,7,8,13); q(3,4,9,14)
        }
    }
    private static let chachaConstants: [UInt32] = [0x61707865,0x3320646e,0x79622d32,0x6b206574]
    private static func hChaCha(key: Data, nonce: Data) -> Data {
        let k = [UInt8](key), n = [UInt8](nonce)
        var state = chachaConstants + (0..<8).map { load32(k,$0*4) } + (0..<4).map { load32(n,$0*4) }
        rounds(&state)
        return Data([0,1,2,3,12,13,14,15].flatMap { littleEndianBytes(state[$0]) })
    }
    private static func chachaBlock(key: Data, nonce: Data, counter: UInt32) -> [UInt8] {
        let k = [UInt8](key), n = [UInt8](nonce)
        let state = chachaConstants + (0..<8).map { load32(k,$0*4) } + [counter] + (0..<3).map { load32(n,$0*4) }
        var working = state
        rounds(&working)
        return (0..<16).flatMap { littleEndianBytes(working[$0] &+ state[$0]) }
    }
    private static func chacha(_ data: Data, key: Data, nonce: Data, counter: UInt32) throws -> Data {
        guard UInt64(data.count) <= (UInt64(UInt32.max) - UInt64(counter) + 1) * 64 else { throw Error.invalidLength }
        var bytes = [UInt8](data)
        for offset in stride(from: 0, to: bytes.count, by: 64) {
            let block = chachaBlock(key: key, nonce: nonce, counter: counter + UInt32(offset/64))
            for j in 0..<min(64, bytes.count-offset) { bytes[offset+j] ^= block[j] }
        }
        return Data(bytes)
    }
    private static func aeadInput(_ aad: Data, _ ciphertext: Data) -> Data {
        var result = aad + Data(repeating: 0, count: (16-aad.count%16)%16)
        result += ciphertext + Data(repeating: 0, count: (16-ciphertext.count%16)%16)
        for count in [aad.count, ciphertext.count] {
            for i in 0..<8 { result.append(UInt8(truncatingIfNeeded: UInt64(count) >> (i*8))) }
        }
        return result
    }
    private static func poly1305(_ message: Data, key: Data) -> Data {
        let k = [UInt8](key), input = [UInt8](message), mask: UInt64 = 0x3ffffff
        let r0 = UInt64(load32(k,0)) & mask
        let r1 = UInt64(load32(k,3) >> 2) & 0x3ffff03
        let r2 = UInt64(load32(k,6) >> 4) & 0x3ffc0ff
        let r3 = UInt64(load32(k,9) >> 6) & 0x3f03fff
        let r4 = UInt64(load32(k,12) >> 8) & 0x00fffff
        var h0: UInt64=0, h1: UInt64=0, h2: UInt64=0, h3: UInt64=0, h4: UInt64=0
        for offset in stride(from: 0, to: input.count, by: 16) {
            let length = min(16,input.count-offset)
            var block = [UInt8](repeating: 0, count: 17)
            block.replaceSubrange(0..<length, with: input[offset..<offset+length]); block[length]=1
            h0 += UInt64(load32(block,0)) & mask; h1 += UInt64(load32(block,3) >> 2) & mask
            h2 += UInt64(load32(block,6) >> 4) & mask; h3 += UInt64(load32(block,9) >> 6) & mask
            h4 += UInt64(load32(block,12) >> 8) | UInt64(block[16]) << 24
            var d0 = h0*r0 + h1*(r4*5) + h2*(r3*5) + h3*(r2*5) + h4*(r1*5)
            var d1 = h0*r1 + h1*r0 + h2*(r4*5) + h3*(r3*5) + h4*(r2*5)
            var d2 = h0*r2 + h1*r1 + h2*r0 + h3*(r4*5) + h4*(r3*5)
            var d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*(r4*5)
            var d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0
            d1 += d0 >> 26; h0=d0 & mask; d2 += d1 >> 26; h1=d1 & mask
            d3 += d2 >> 26; h2=d2 & mask; d4 += d3 >> 26; h3=d3 & mask
            h4=d4 & mask; d0=(d4 >> 26)*5; h0 += d0; h1 += h0 >> 26; h0 &= mask
        }
        h2 += h1 >> 26; h1 &= mask; h3 += h2 >> 26; h2 &= mask
        h4 += h3 >> 26; h3 &= mask; h0 += (h4 >> 26)*5; h4 &= mask; h1 += h0 >> 26; h0 &= mask
        var g0=h0+5, g1=h1, g2=h2, g3=h3, g4=h4
        g1 += g0 >> 26; g0 &= mask; g2 += g1 >> 26; g1 &= mask
        g3 += g2 >> 26; g2 &= mask; g4 += g3 >> 26; g3 &= mask
        g4 = g4 &- (1 << 26)
        let select = (g4 >> 63) &- 1
        h0=(h0 & ~select) | (g0 & select); h1=(h1 & ~select) | (g1 & select)
        h2=(h2 & ~select) | (g2 & select); h3=(h3 & ~select) | (g3 & select); h4=(h4 & ~select) | (g4 & select)
        let words = [(h0 | h1 << 26) & 0xffffffff, (h1 >> 6 | h2 << 20) & 0xffffffff,
                     (h2 >> 12 | h3 << 14) & 0xffffffff, (h3 >> 18 | h4 << 8) & 0xffffffff]
        var carry: UInt64 = 0, result = Data()
        for i in 0..<4 {
            carry += words[i] + UInt64(load32(k,16+i*4))
            result += littleEndianBytes(UInt32(truncatingIfNeeded: carry)); carry >>= 32
        }
        return result
    }

    // Montgomery ladder over 16 radix-2^16 limbs. The scalar controls masked swaps.
    private static func x25519(_ privateKey: Data, _ publicKey: Data) throws -> Data {
        var scalar = [UInt8](privateKey), point = [UInt8](publicKey)
        scalar[0] &= 248; scalar[31] = (scalar[31] & 127) | 64; point[31] &= 127
        typealias Field = [Int64]
        func carry(_ value: inout Field) {
            for i in 0..<16 {
                value[i] += 1 << 16
                let c = value[i] >> 16
                value[i] -= c << 16
                if i < 15 { value[i+1] += c-1 } else { value[0] += 38*(c-1) }
            }
        }
        func swap(_ a: inout Field, _ b: inout Field, _ bit: Int64) {
            let mask = -bit
            for i in 0..<16 { let t = mask & (a[i] ^ b[i]); a[i] ^= t; b[i] ^= t }
        }
        func add(_ a: Field, _ b: Field) -> Field { zip(a,b).map(+) }
        func sub(_ a: Field, _ b: Field) -> Field { zip(a,b).map(-) }
        func mul(_ a: Field, _ b: Field) -> Field {
            var t = [Int64](repeating: 0, count: 31)
            for i in 0..<16 { for j in 0..<16 { t[i+j] += a[i]*b[j] } }
            for i in 0..<15 { t[i] += 38*t[i+16] }
            var r = Array(t.prefix(16)); carry(&r); carry(&r); return r
        }
        func square(_ a: Field) -> Field { mul(a,a) }
        var x = (0..<16).map { Int64(point[2*$0]) + (Int64(point[2*$0+1]) << 8) }
        var a = Field(repeating: 0, count: 16), b=x, c=Field(repeating: 0, count: 16), d=Field(repeating: 0, count: 16)
        a[0]=1; d[0]=1
        var constant = Field(repeating: 0, count: 16); constant[0]=0xdb41; constant[1]=1
        for i in stride(from: 254, through: 0, by: -1) {
            let bit = Int64((scalar[i >> 3] >> (i & 7)) & 1)
            swap(&a,&b,bit); swap(&c,&d,bit)
            let e=add(a,c); a=sub(a,c); c=add(b,d); b=sub(b,d)
            d=square(e); let f=square(a); a=mul(c,a); c=mul(b,e)
            let e2=add(a,c); a=sub(a,c); b=square(a); c=sub(d,f)
            a=mul(c,constant); a=add(a,d); c=mul(c,a); a=mul(d,f); d=mul(b,x); b=square(e2)
            swap(&a,&b,bit); swap(&c,&d,bit)
        }
        var inverse=c
        for i in stride(from: 253, through: 0, by: -1) { inverse=square(inverse); if i != 2 && i != 4 { inverse=mul(inverse,c) } }
        x=mul(a,inverse); carry(&x); carry(&x); carry(&x)
        for _ in 0..<2 {
            var m=x; m[0] -= 0xffed
            for i in 1..<15 { m[i] -= 0xffff + ((m[i-1] >> 16) & 1); m[i-1] &= 0xffff }
            m[15] -= 0x7fff + ((m[14] >> 16) & 1)
            let bit = (m[15] >> 16) & 1; m[14] &= 0xffff
            swap(&x,&m,1-bit)
        }
        return Data(x.flatMap { [UInt8(truncatingIfNeeded: $0), UInt8(truncatingIfNeeded: $0 >> 8)] })
    }
}