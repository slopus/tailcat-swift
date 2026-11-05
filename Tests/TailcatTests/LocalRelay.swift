import Foundation
@testable import Tailcat
#if canImport(Glibc)
import Glibc

/// Minimal authenticated DERP fixture. WireGuard remains end-to-end between the
/// real clients; this relay only forwards opaque packets using the DERP framing.
final class LocalRelay: @unchecked Sendable {
    enum FastStartBehavior { case supported, ignored, mismatchedGreeting, stalled, corruptServerInfo }
    private final class Connection: @unchecked Sendable {
        let fd: Int32
        let writeLock = NSLock()
        private var stopped = false
        init(_ fd: Int32) { self.fd = fd }
        deinit { Glibc.close(fd) }
        func stop() {
            writeLock.lock(); defer { writeLock.unlock() }
            stopped = true; _ = shutdown(fd, Int32(SHUT_RDWR))
        }
        func send(_ data: Data) throws {
            writeLock.lock(); defer { writeLock.unlock() }
            guard !stopped else { throw TransportError.closed }
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = Glibc.send(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, Int32(MSG_NOSIGNAL))
                    guard count > 0 else { throw TransportError.closed }
                    offset += count
                }
            }
        }
        func read(_ count: Int) throws -> Data {
            var bytes = [UInt8](repeating: 0, count: count)
            try bytes.withUnsafeMutableBytes { buffer in
                var offset = 0
                while offset < count {
                    let received = recv(fd, buffer.baseAddress!.advanced(by: offset), count - offset, 0)
                    guard received > 0 else { throw TransportError.closed }
                    offset += received
                }
            }
            return Data(bytes)
        }
        func frame() throws -> (type: UInt8, payload: Data) {
            let header = try DERPFrame.header(read(5))
            return (header.type, try read(header.length))
        }
    }

    let port: Int
    private let source: DispatchSourceRead
    private let lock = NSLock()
    private var connections = [UUID: Connection]()
    private var peers = [Data: Connection]()
    private var available = true
    private var closed = false
    private var wireGuardTypes = Set<UInt32>()
    private var keepalives = [Data: Data]()
    private let privateKey = NaClBox.random(32)
    private let fastStartBehavior: FastStartBehavior
    private var fastStarts = 0
    private var clientNonces = [Data]()

    var serverPublicKey: Data { get throws { try NaClBox.publicKey(for: privateKey) } }
    var fastStartCount: Int { lock.lock(); defer { lock.unlock() }; return fastStarts }
    var authenticationNonces: [Data] { lock.lock(); defer { lock.unlock() }; return clientNonces }

    init(fastStartBehavior: FastStartBehavior = .supported) throws {
        self.fastStartBehavior = fastStartBehavior
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw TransportError.connectionFailed("fixture socket") }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0, listen(fd, 32) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else {
            Glibc.close(fd); throw TransportError.connectionFailed("fixture bind")
        }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        port = Int(UInt16(bigEndian: address.sin_port))
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .global())
        source.setEventHandler { [weak self] in
            while true {
                let accepted = Glibc.accept(fd, nil, nil)
                guard accepted >= 0 else { return }
                guard let self else { Glibc.close(accepted); return }
                self.accept(Connection(accepted))
            }
        }
        source.setCancelHandler { Glibc.close(fd) }
        source.resume()
    }

    var node: DERPNode {
        DERPNode(hostName: "127.0.0.1", ipv4: "127.0.0.1", ipv6: "none", stunPort: -1, derpPort: port, insecureForTests: true)
    }

    private func accept(_ connection: Connection) {
        lock.lock()
        guard available, !closed else { lock.unlock(); connection.stop(); return }
        let id = UUID(); connections[id] = connection
        lock.unlock()
        DispatchQueue.global().async { [weak self] in self?.serve(connection, id: id) }
    }

    private func serve(_ connection: Connection, id: UUID) {
        var identity: Data?
        defer {
            connection.stop()
            lock.lock(); connections[id] = nil
            if let identity, peers[identity] === connection { peers[identity] = nil }
            lock.unlock()
        }
        do {
            var header = Data()
            while !header.suffix(4).elementsEqual([13,10,13,10]) {
                guard header.count < 16384 else { throw TransportError.malformedPacket }
                header.append(try connection.read(1))
            }
            let fast = String(decoding: header, as: UTF8.self).contains("Derp-Fast-Start: 1\r\n")
            if fast { lock.lock(); fastStarts += 1; lock.unlock() }
            if fast, fastStartBehavior == .stalled {
                while true { _ = try connection.read(1) }
            }
            let greetingKey = fast && fastStartBehavior == .mismatchedGreeting ? NaClBox.random(32) : try NaClBox.publicKey(for: privateKey)
            let greeting = try DERPFrame.encode(type: 1, payload: Data("DERP🔑".utf8) + greetingKey)
            if !fast || fastStartBehavior == .ignored {
                try connection.send(Data("HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n".utf8))
                try connection.send(greeting)
            }
            let auth = try connection.frame()
            guard auth.type == 2, auth.payload.count >= 72 else { throw TransportError.malformedPacket }
            let key = Data(auth.payload.prefix(32)), nonce = Data(auth.payload.dropFirst(32).prefix(24))
            lock.lock(); clientNonces.append(nonce); lock.unlock()
            _ = try NaClBox.open(Data(auth.payload.dropFirst(56)), nonce: nonce, publicKey: key, privateKey: privateKey)
            identity = key
            lock.lock(); peers[key] = connection; lock.unlock()
            let responseNonce = NaClBox.random(24)
            var info = try NaClBox.seal(Data("{\"version\":2}".utf8), nonce: responseNonce, publicKey: key, privateKey: privateKey)
            if fastStartBehavior == .corruptServerInfo { info[0] ^= 1 }
            let serverInfo = try DERPFrame.encode(type: 3, payload: responseNonce + info)
            // Exercise a coalesced greeting+ServerInfo as well as a coalesced
            // HTTP request+ClientInfo. Neither frame may be skipped by parsing.
            try connection.send(fast && fastStartBehavior != .ignored ? greeting + serverInfo : serverInfo)
            while true {
                let frame = try connection.frame()
                if frame.type == 4, frame.payload.count >= 32 {
                    let destination = Data(frame.payload.prefix(32))
                    lock.lock()
                    let packet = Data(frame.payload.dropFirst(32))
                    if let type = WireGuard.packetType(packet) {
                        wireGuardTypes.insert(type)
                        if type == 4, packet.count == 32 { keepalives[key] = packet }
                    }
                    let target = peers[destination]; lock.unlock()
                    try? target?.send(DERPFrame.encode(type: 5, payload: key + frame.payload.dropFirst(32)))
                } else if frame.type == 0x12 {
                    try connection.send(DERPFrame.encode(type: 0x13, payload: frame.payload))
                }
            }
        } catch {}
    }

    func setAvailable(_ value: Bool) {
        lock.lock(); available = value
        let current = Array(connections.values); lock.unlock()
        if !value { for connection in current { connection.stop() } }
    }

    func lastKeepalive(from source: Data) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return keepalives[source]
    }

    func inject(_ packet: Data, from source: Data, to destination: Data) throws {
        lock.lock(); let target = peers[destination]; lock.unlock()
        try target?.send(DERPFrame.encode(type: 5, payload: source + packet))
    }

    func dropConnections() {
        lock.lock(); let current = Array(connections.values); lock.unlock()
        for connection in current { connection.stop() }
    }

    var relayedInitialHandshakeAndConfirmation: Bool {
        lock.lock(); defer { lock.unlock() }
        return wireGuardTypes.isSuperset(of: [1, 2, 4])
    }

    func close() {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true; let current = Array(connections.values); lock.unlock()
        for connection in current { connection.stop() }
        source.cancel()
    }
    deinit { close() }
}
#endif