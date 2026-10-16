// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation

/// A single peer's WireGuard Noise_IKpsk2 session. Its owner serializes access and
/// supplies UDP/DERP delivery, handshake retries and persistent keepalive timers.
struct WireGuard: Sendable {
    enum Error: Swift.Error, Equatable {
        case invalidKey, invalidPacket, invalidMAC, unexpectedMessage, wrongPeer
        case replay, handshakeRateLimited, notEstablished, expired, invalidTime
    }
    struct ReceiveResult: Sendable {
        var response: Data?
        var plaintext: Data?
        var handshakeCompleted = false
    }

    private static let initialChain = TailcatCrypto.blake2s(Data("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))
    private static let initialHash = TailcatCrypto.blake2s(initialChain + Data("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8))
    private static let zeroNonce = Data(repeating: 0, count: 12)
    private static let rejectAfterMessages = UInt64.max - 8192
    private let privateKey: Data
    private let publicKey: Data
    private let peerPublicKey: Data
    private let presharedKey: Data
    private let staticShared: Data
    private var pending: Initiation?
    private var previous: Session?
    private var current: Session?
    private var next: Session?
    private var lastTimestamp: Data?
    private var lastSentTimestamp: Data?
    private var lastInitiationReceived: Date?
    private var lastOutbound: Outbound?
    private var cookie: Data?
    private var cookieReceivedAt: Date?
    private var cookieSecret: Data?
    private var cookieSecretAt: Date?

    private struct Initiation: Sendable {
        var chain: Data
        var hash: Data
        var ephemeral: Data
        var localIndex: UInt32
        var created: Date
    }
    private struct Outbound: Sendable {
        var packet: Data
        var localIndex: UInt32
        var created: Date
    }
    private struct Session: Sendable {
        var sendKey: Data
        var receiveKey: Data
        var localIndex: UInt32
        var remoteIndex: UInt32
        var created: Date
        var initiator: Bool
        var sendCounter: UInt64 = 0
        var replay = ReplayWindow()
    }

    /// Replay state is committed only after successful AEAD authentication.
    struct ReplayWindow: Sendable {
        private var highest: UInt64?
        // One extra word preserves the partially overlapped oldest word.
        private var bits = [UInt64](repeating: 0, count: 129)
        mutating func accept(_ counter: UInt64) -> Bool {
            guard counter < WireGuard.rejectAfterMessages else { return false }
            if let highest {
                if counter <= highest, highest-counter >= 8192 { return false }
                if counter > highest {
                    let start = highest/64 + 1, end = counter/64
                    if end >= start {
                        if end-start >= 128 { bits = [UInt64](repeating: 0, count: 129) }
                        else { for word in start...end { bits[Int(word%129)] = 0 } }
                    }
                    self.highest = counter
                }
            } else { highest = counter }
            let index = Int((counter/64)%129), mask = UInt64(1) << (counter%64)
            guard bits[index] & mask == 0 else { return false }
            bits[index] |= mask
            return true
        }
    }

    init(privateKey: Data, peerPublicKey: Data, presharedKey: Data = Data(repeating: 0, count: 32)) throws {
        guard privateKey.count == 32, peerPublicKey.count == 32, presharedKey.count == 32 else { throw Error.invalidKey }
        self.privateKey = privateKey
        self.publicKey = try TailcatCrypto.publicKey(privateKey: privateKey)
        self.peerPublicKey = peerPublicKey
        self.presharedKey = presharedKey
        self.staticShared = try TailcatCrypto.sharedSecret(privateKey: privateKey, publicKey: peerPublicKey)
    }

    var isEstablished: Bool { current != nil }

    func needsRekey(now: Date = Date()) -> Bool {
        guard let session = current else { return true }
        return session.sendCounter >= (1 << 60) || now.timeIntervalSince(session.created) >= (session.initiator ? 120 : 165)
    }

    mutating func initiate(now: Date = Date()) throws -> Data { try initiateHandshake(now: now) }

    mutating func initiateHandshake(now: Date = Date()) throws -> Data {
        let ephemeral = try TailcatCrypto.randomBytes(count: 32)
        let ephemeralPublic = try TailcatCrypto.publicKey(privateKey: ephemeral)
        let index = try freshIndex()
        var chain = Self.initialChain
        var hash = Self.hash(Self.initialHash, peerPublicKey)
        chain = Self.kdf(chain, ephemeralPublic, count: 1)[0]
        hash = Self.hash(hash, ephemeralPublic)
        var keys = Self.kdf(chain, try TailcatCrypto.sharedSecret(privateKey: ephemeral, publicKey: peerPublicKey), count: 2)
        chain = keys[0]
        let encryptedStatic = try TailcatCrypto.seal(publicKey, key: keys[1], nonce: Self.zeroNonce, authenticating: hash)
        hash = Self.hash(hash, encryptedStatic)
        keys = Self.kdf(chain, staticShared, count: 2); chain = keys[0]
        var timestamp = try Self.timestamp(now)
        if let lastSentTimestamp, !lastSentTimestamp.lexicographicallyPrecedes(timestamp) {
            timestamp = lastSentTimestamp
            for i in (0..<timestamp.count).reversed() { timestamp[i] &+= 1; if timestamp[i] != 0 { break } }
        }
        let encryptedTimestamp = try TailcatCrypto.seal(timestamp, key: keys[1], nonce: Self.zeroNonce, authenticating: hash)
        hash = Self.hash(hash, encryptedTimestamp)
        let body = Self.le(UInt32(1)) + Self.le(index) + ephemeralPublic + encryptedStatic + encryptedTimestamp
        let packet = addMACs(body, now: now)
        lastSentTimestamp = timestamp
        pending = Initiation(chain: chain, hash: hash, ephemeral: ephemeral, localIndex: index, created: now)
        lastOutbound = Outbound(packet: packet, localIndex: index, created: now)
        return packet
    }

    /// `source` is the caller's stable IP:port encoding. Set requireCookie when
    /// under load to require proof of source address before expensive DH work.
    mutating func receive(_ datagram: Data, now: Date = Date(), source: Data? = nil, requireCookie: Bool = false) throws -> ReceiveResult {
        let packet = Data([UInt8](datagram))
        guard let type = Self.packetType(packet) else { throw Error.invalidPacket }
        if type == 1 || type == 2 {
            guard packet.count == (type == 1 ? 148 : 92) else { throw Error.invalidPacket }
            let macOffset = packet.count-32
            let key = TailcatCrypto.blake2s(Data("mac1----".utf8) + publicKey)
            guard TailcatCrypto.constantTimeEqual(Self.mac(Data(packet.prefix(macOffset)), key), Data(packet[macOffset..<macOffset+16])) else { throw Error.invalidMAC }
            if requireCookie {
                guard let source else { throw Error.invalidPacket }
                if let reply = try checkCookie(packet, source: source, now: now) { return ReceiveResult(response: reply) }
            }
        }
        switch type {
        case 1: return try consumeInitiation(packet, now: now)
        case 2: return try consumeResponse(packet, now: now)
        case 3: return try consumeCookie(packet, now: now)
        case 4: return try consumeTransport(packet, now: now)
        default: throw Error.invalidPacket
        }
    }

    mutating func encrypt(_ plaintext: Data, now: Date = Date()) throws -> Data {
        guard var session = current else { throw Error.notEstablished }
        guard now.timeIntervalSince(session.created) < 180, session.sendCounter < Self.rejectAfterMessages else { throw Error.expired }
        guard plaintext.count <= 65535 else { throw Error.invalidPacket }
        let counter = session.sendCounter
        let padded = plaintext + Data(repeating: 0, count: (16-plaintext.count%16)%16)
        let encrypted = try TailcatCrypto.seal(padded, key: session.sendKey, nonce: Self.nonce(counter))
        session.sendCounter += 1
        current = session
        return Self.le(UInt32(4)) + Self.le(session.remoteIndex) + Self.le(counter) + encrypted
    }

    static func packetType(_ packet: Data) -> UInt32? {
        guard packet.count >= 4 else { return nil }
        let bytes = [UInt8](packet.prefix(4))
        return UInt32(bytes[0]) | UInt32(bytes[1]) << 8 | UInt32(bytes[2]) << 16 | UInt32(bytes[3]) << 24
    }

    private mutating func consumeInitiation(_ packet: Data, now: Date) throws -> ReceiveResult {
        let remoteIndex = Self.u32(packet,4), remoteEphemeral = Data(packet[8..<40])
        var hash = Self.hash(Self.initialHash, publicKey)
        hash = Self.hash(hash, remoteEphemeral)
        var chain = Self.kdf(Self.initialChain, remoteEphemeral, count: 1)[0]
        var keys = Self.kdf(chain, try TailcatCrypto.sharedSecret(privateKey: privateKey, publicKey: remoteEphemeral), count: 2)
        chain = keys[0]
        let remoteStatic = try TailcatCrypto.open(Data(packet[40..<88]), key: keys[1], nonce: Self.zeroNonce, authenticating: hash)
        guard TailcatCrypto.constantTimeEqual(remoteStatic, peerPublicKey) else { throw Error.wrongPeer }
        hash = Self.hash(hash, Data(packet[40..<88]))
        keys = Self.kdf(chain, staticShared, count: 2); chain = keys[0]
        let timestamp = try TailcatCrypto.open(Data(packet[88..<116]), key: keys[1], nonce: Self.zeroNonce, authenticating: hash)
        hash = Self.hash(hash, Data(packet[88..<116]))
        if let lastTimestamp, !lastTimestamp.lexicographicallyPrecedes(timestamp) { throw Error.replay }
        if let lastInitiationReceived, now.timeIntervalSince(lastInitiationReceived) < 0.02 { throw Error.handshakeRateLimited }
        let localIndex = try freshIndex(), ephemeral = try TailcatCrypto.randomBytes(count: 32)
        let ephemeralPublic = try TailcatCrypto.publicKey(privateKey: ephemeral)
        hash = Self.hash(hash, ephemeralPublic)
        chain = Self.kdf(chain, ephemeralPublic, count: 1)[0]
        chain = Self.kdf(chain, try TailcatCrypto.sharedSecret(privateKey: ephemeral, publicKey: remoteEphemeral), count: 1)[0]
        chain = Self.kdf(chain, try TailcatCrypto.sharedSecret(privateKey: ephemeral, publicKey: peerPublicKey), count: 1)[0]
        keys = Self.kdf(chain, presharedKey, count: 3); chain = keys[0]
        hash = Self.hash(hash, keys[1])
        let encryptedEmpty = try TailcatCrypto.seal(Data(), key: keys[2], nonce: Self.zeroNonce, authenticating: hash)
        let transportKeys = Self.kdf(chain, Data(), count: 2)
        let body = Self.le(UInt32(2)) + Self.le(localIndex) + Self.le(remoteIndex) + ephemeralPublic + encryptedEmpty
        let response = addMACs(body, now: now)
        next = Session(sendKey: transportKeys[1], receiveKey: transportKeys[0], localIndex: localIndex, remoteIndex: remoteIndex, created: now, initiator: false)
        lastTimestamp = timestamp
        lastInitiationReceived = now
        lastOutbound = Outbound(packet: response, localIndex: localIndex, created: now)
        return ReceiveResult(response: response)
    }

    private mutating func consumeResponse(_ packet: Data, now: Date) throws -> ReceiveResult {
        guard let initiation = pending, Self.u32(packet,8) == initiation.localIndex else { throw Error.unexpectedMessage }
        guard now.timeIntervalSince(initiation.created) < 180 else { throw Error.expired }
        let ephemeral = Data(packet[12..<44])
        var hash = Self.hash(initiation.hash, ephemeral)
        var chain = Self.kdf(initiation.chain, ephemeral, count: 1)[0]
        chain = Self.kdf(chain, try TailcatCrypto.sharedSecret(privateKey: initiation.ephemeral, publicKey: ephemeral), count: 1)[0]
        chain = Self.kdf(chain, try TailcatCrypto.sharedSecret(privateKey: privateKey, publicKey: ephemeral), count: 1)[0]
        let keys = Self.kdf(chain, presharedKey, count: 3)
        hash = Self.hash(hash, keys[1])
        _ = try TailcatCrypto.open(Data(packet[44..<60]), key: keys[2], nonce: Self.zeroNonce, authenticating: hash)
        let transportKeys = Self.kdf(keys[0], Data(), count: 2)
        previous = current
        current = Session(sendKey: transportKeys[0], receiveKey: transportKeys[1], localIndex: initiation.localIndex, remoteIndex: Self.u32(packet,4), created: now, initiator: true)
        pending = nil
        // The first transport authenticates the response for the responder and
        // promotes its next keypair even when there is no queued IP packet.
        return ReceiveResult(response: try encrypt(Data(), now: now), handshakeCompleted: true)
    }

    private mutating func consumeTransport(_ packet: Data, now: Date) throws -> ReceiveResult {
        guard packet.count >= 32, packet.count <= 65568 else { throw Error.invalidPacket }
        let index = Self.u32(packet,4), counter = Self.u64(packet,8)
        let slot: Int
        var session: Session
        if let candidate = next, candidate.localIndex == index { session=candidate; slot=2 }
        else if let candidate = current, candidate.localIndex == index { session=candidate; slot=1 }
        else if let candidate = previous, candidate.localIndex == index { session=candidate; slot=0 }
        else { throw Error.unexpectedMessage }
        guard now.timeIntervalSince(session.created) < 180 else { throw Error.expired }
        var replay = session.replay
        guard replay.accept(counter) else { throw Error.replay }
        let padded = try TailcatCrypto.open(Data(packet.dropFirst(16)), key: session.receiveKey, nonce: Self.nonce(counter))
        session.replay = replay
        if slot == 2 { previous=current; current=session; next=nil }
        else if slot == 1 { current=session }
        else { previous=session }
        let plaintext = try Self.unpadIP(padded)
        return ReceiveResult(plaintext: plaintext, handshakeCompleted: slot == 2)
    }

    private mutating func consumeCookie(_ packet: Data, now: Date) throws -> ReceiveResult {
        guard packet.count == 64 else { throw Error.invalidPacket }
        guard let outbound = lastOutbound, Self.u32(packet,4) == outbound.localIndex,
              now.timeIntervalSince(outbound.created) < 120 else { throw Error.unexpectedMessage }
        let key = TailcatCrypto.blake2s(Data("cookie--".utf8) + peerPublicKey)
        let mac1 = Data(outbound.packet[(outbound.packet.count-32)..<(outbound.packet.count-16)])
        let value = try TailcatCrypto.xOpen(Data(packet[32..<64]), key: key, nonce: Data(packet[8..<32]), authenticating: mac1)
        guard value.count == 16 else { throw Error.invalidPacket }
        cookie = value; cookieReceivedAt = now
        let response = addMACs(Data(outbound.packet.dropLast(32)), now: now)
        lastOutbound = Outbound(packet: response, localIndex: outbound.localIndex, created: outbound.created)
        return ReceiveResult(response: response)
    }

    private mutating func checkCookie(_ packet: Data, source: Data, now: Date) throws -> Data? {
        if cookieSecret == nil || now.timeIntervalSince(cookieSecretAt ?? .distantPast) >= 120 {
            cookieSecret = try TailcatCrypto.randomBytes(count: 32); cookieSecretAt = now
        }
        let expectedCookie = Self.mac(source, cookieSecret!)
        let expectedMAC = Self.mac(Data(packet.dropLast(16)), expectedCookie)
        if TailcatCrypto.constantTimeEqual(expectedMAC, Data(packet.suffix(16))) { return nil }
        let key = TailcatCrypto.blake2s(Data("cookie--".utf8) + publicKey)
        let nonce = try TailcatCrypto.randomBytes(count: 24)
        let mac1 = Data(packet[(packet.count-32)..<(packet.count-16)])
        return Self.le(UInt32(3)) + Self.le(Self.u32(packet,4)) + nonce + (try TailcatCrypto.xSeal(expectedCookie, key: key, nonce: nonce, authenticating: mac1))
    }

    private func addMACs(_ body: Data, now: Date) -> Data {
        let key = TailcatCrypto.blake2s(Data("mac1----".utf8) + peerPublicKey)
        let packet = body + Self.mac(body,key)
        if let cookie, let cookieReceivedAt, now.timeIntervalSince(cookieReceivedAt) < 115 {
            return packet + Self.mac(packet,cookie)
        }
        return packet + Data(repeating: 0, count: 16)
    }

    private func freshIndex() throws -> UInt32 {
        while true {
            let index = Self.u32(try TailcatCrypto.randomBytes(count: 4),0)
            if index != 0 && index != current?.localIndex && index != previous?.localIndex && index != next?.localIndex && index != pending?.localIndex { return index }
        }
    }

    private static func hash(_ a: Data, _ b: Data) -> Data { TailcatCrypto.blake2s(a+b) }
    private static func mac(_ data: Data, _ key: Data) -> Data { TailcatCrypto.blake2s(data, key: key, digestLength: 16) }
    private static func kdf(_ key: Data, _ input: Data, count: Int) -> [Data] {
        let secret = TailcatCrypto.hmacBlake2s(key: key, message: input)
        var result = [Data](), previous = Data()
        for i in 1...count {
            previous = TailcatCrypto.hmacBlake2s(key: secret, message: previous + Data([UInt8(i)]))
            result.append(previous)
        }
        return result
    }
    private static func nonce(_ counter: UInt64) -> Data { Data(repeating: 0, count: 4) + le(counter) }
    private static func le<T: FixedWidthInteger>(_ value: T) -> Data {
        Data((0..<MemoryLayout<T>.size).map { UInt8(truncatingIfNeeded: value >> ($0*8)) })
    }
    private static func u32(_ data: Data, _ offset: Int) -> UInt32 {
        (0..<4).reduce(0) { $0 | UInt32(data[offset+$1]) << ($1*8) }
    }
    private static func u64(_ data: Data, _ offset: Int) -> UInt64 {
        (0..<8).reduce(0) { $0 | UInt64(data[offset+$1]) << ($1*8) }
    }
    private static func timestamp(_ now: Date) throws -> Data {
        let unix = now.timeIntervalSince1970
        guard unix.isFinite, unix >= 0, unix < Double(Int64.max) else { throw Error.invalidTime }
        let seconds = UInt64(unix.rounded(.down)) + 0x400000000000000a
        let nanos = UInt32((unix-unix.rounded(.down))*1_000_000_000)
        return Data((0..<8).reversed().map { UInt8(truncatingIfNeeded: seconds >> ($0*8)) }) + Data((0..<4).reversed().map { UInt8(truncatingIfNeeded: nanos >> ($0*8)) })
    }
    private static func unpadIP(_ data: Data) throws -> Data? {
        if data.isEmpty { return nil }
        let bytes = [UInt8](data)
        let length: Int
        switch bytes[0] >> 4 {
        case 4:
            guard bytes.count >= 20 else { throw Error.invalidPacket }
            let headerLength = Int(bytes[0] & 15)*4
            length = Int(bytes[2]) << 8 | Int(bytes[3])
            guard headerLength >= 20, length >= headerLength else { throw Error.invalidPacket }
        case 6:
            guard bytes.count >= 40 else { throw Error.invalidPacket }
            length = 40 + (Int(bytes[4]) << 8 | Int(bytes[5]))
        default: throw Error.invalidPacket
        }
        guard length <= bytes.count else { throw Error.invalidPacket }
        return Data(bytes.prefix(length))
    }
}