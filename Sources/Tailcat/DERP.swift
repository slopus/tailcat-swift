// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation
#if canImport(Network)
import Network
import Security
#else
import Glibc
#endif

public struct DERPPacket: Sendable, Equatable {
    public let source: Data
    public let payload: Data
    public init(source: Data, payload: Data) { self.source = source; self.payload = payload }
}

/// A bounded DERP frame codec, also used by the streaming transport.
enum DERPFrame {
    static let maximumLength = (1 << 20) + 64
    static func encode(type: UInt8, payload: Data) throws -> Data {
        guard payload.count <= maximumLength else { throw TransportError.oversizedPacket }
        let n = UInt32(payload.count)
        return Data([type, UInt8(truncatingIfNeeded: n >> 24), UInt8(truncatingIfNeeded: n >> 16),
                     UInt8(truncatingIfNeeded: n >> 8), UInt8(truncatingIfNeeded: n)]) + payload
    }
    static func header(_ data: Data) throws -> (type: UInt8, length: Int) {
        let b = Array(data)
        guard b.count == 5 else { throw TransportError.malformedPacket }
        let n = b[1...4].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard n <= maximumLength else { throw TransportError.oversizedPacket }
        return (b[0], Int(n))
    }
}

#if canImport(Network)
/// Owns a single TCP connection. Each send is one complete HTTP request or DERP frame.
private final class DERPStream: @unchecked Sendable {
    let connection: NWConnection
    private let queue = DispatchQueue(label: "tailcat.derp")
    private let lock = NSLock()
    private var readyContinuation: CheckedContinuation<Void, Error>?
    private var timeoutWork: DispatchWorkItem?

    init(node: DERPNode) throws {
        let port = node.derpPort > 0 ? node.derpPort : 443
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(exactly: port) ?? 0), nwPort.rawValue != 0,
              !node.hostName.contains("\r"), !node.hostName.contains("\n") else { throw TransportError.invalidEndpoint }
        let tls = NWProtocolTLS.Options()
        node.hostName.withCString { sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, $0) }
        if node.insecureForTests {
            sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, complete in complete(true) }, .global(qos: .utility))
        } else if !node.certName.isEmpty, node.certName != node.hostName {
            let expectedName = node.certName
            sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
                let certificateTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                let policy = SecPolicyCreateSSL(true, expectedName as CFString)
                guard SecTrustSetPolicies(certificateTrust, policy) == errSecSuccess else { complete(false); return }
                complete(SecTrustEvaluateWithError(certificateTrust, nil))
            }, .global(qos: .utility))
        }
        let host = !node.ipv4.isEmpty && node.ipv4 != "none" ? node.ipv4 :
            (!node.ipv6.isEmpty && node.ipv6 != "none" ? node.ipv6 : node.hostName)
        connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort,
                                  using: NWParameters(tls: tls, tcp: NWProtocolTCP.Options()))
    }

    func start() async throws {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock(); readyContinuation = continuation; lock.unlock()
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready: self?.completeStart(nil)
                case .failed(let error): self?.completeStart(error)
                case .cancelled: self?.completeStart(TransportError.closed)
                default: break
                }
            }
            let timeout = DispatchWorkItem { [weak self] in
                self?.completeStart(TransportError.timeout); self?.connection.cancel()
            }
            timeoutWork = timeout
            queue.asyncAfter(deadline: .now() + 15, execute: timeout)
            connection.start(queue: queue)
        }
    }
    private func completeStart(_ error: Error?) {
        lock.lock(); let continuation = readyContinuation; readyContinuation = nil; lock.unlock()
        timeoutWork?.cancel()
        if let error { continuation?.resume(throwing: error) } else { continuation?.resume() }
    }
    func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }
    func receive() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, complete, error in
                if let data, !data.isEmpty { continuation.resume(returning: data) }
                else if let error { continuation.resume(throwing: error) }
                else { continuation.resume(throwing: TransportError.closed) }
            }
        }
    }
    func close() { connection.cancel() }
}
#else
/// Loopback-only plaintext backend for protocol integration tests on Linux.
/// Production connections use Network.framework TLS on supported Apple platforms.
private final class DERPStream: @unchecked Sendable {
    private let descriptor: Int32
    private let remote: Data
    private let writeQueue = DispatchQueue(label: "tailcat.derp.test.write")
    private let readQueue = DispatchQueue(label: "tailcat.derp.test.read")
    init(node: DERPNode) throws {
        let host = node.ipv4.isEmpty ? node.hostName : node.ipv4
        guard node.insecureForTests, ["127.0.0.1", "::1", "localhost"].contains(host) else {
            throw TransportError.connectionFailed("Production DERP TLS requires Network.framework on an Apple platform")
        }
        guard !node.hostName.contains("\r"), !node.hostName.contains("\n"),
              let port = UInt16(exactly: node.derpPort > 0 ? node.derpPort : 443), port != 0 else { throw TransportError.invalidEndpoint }
        if host == "::1" {
            var address = sockaddr_in6()
            address.sin6_family = sa_family_t(AF_INET6); address.sin6_port = port.bigEndian
            _ = inet_pton(AF_INET6, host, &address.sin6_addr)
            remote = withUnsafeBytes(of: &address) { Data($0) }
            descriptor = socket(AF_INET6, Int32(SOCK_STREAM.rawValue), 0)
        } else {
            var address = sockaddr_in()
            address.sin_family = sa_family_t(AF_INET); address.sin_port = port.bigEndian
            _ = inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
            remote = withUnsafeBytes(of: &address) { Data($0) }
            descriptor = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        }
        guard descriptor >= 0 else { throw TransportError.connectionFailed("TCP socket: \(errno)") }
    }
    deinit { Glibc.close(descriptor) }
    func start() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            writeQueue.async { [self] in
                var timeout = timeval(tv_sec: 15, tv_usec: 0)
                _ = setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
                let flags = fcntl(descriptor, F_GETFL)
                guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                    continuation.resume(throwing: TransportError.connectionFailed("TCP configure: \(errno)")); return
                }
                let result = remote.withUnsafeBytes { bytes in
                    bytes.baseAddress!.assumingMemoryBound(to: sockaddr.self).withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Glibc.connect(descriptor, $0, socklen_t(bytes.count))
                    }
                }
                var socketError: Int32 = 0
                if result != 0 {
                    guard errno == EINPROGRESS else {
                        continuation.resume(throwing: TransportError.connectionFailed("TCP connect: \(errno)")); return
                    }
                    var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
                    let ready = poll(&pollDescriptor, 1, 15_000)
                    var size = socklen_t(MemoryLayout<Int32>.size)
                    guard ready > 0, getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socketError, &size) == 0, socketError == 0 else {
                        continuation.resume(throwing: TransportError.connectionFailed("TCP connect: \(socketError)")); return
                    }
                }
                _ = fcntl(descriptor, F_SETFL, flags)
                continuation.resume()
            }
        }
    }
    func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            writeQueue.async { [self] in
                let result: Bool = data.withUnsafeBytes { bytes in
                    var offset = 0
                    while offset < bytes.count {
                        let count = Glibc.send(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, Int32(MSG_NOSIGNAL))
                        if count < 0, errno == EINTR { continue }
                        guard count > 0 else { return false }
                        offset += count
                    }
                    return true
                }
                if result { continuation.resume() }
                else { continuation.resume(throwing: TransportError.connectionFailed("TCP send: \(errno)")) }
            }
        }
    }
    func receive() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            readQueue.async { [self] in
                var buffer = [UInt8](repeating: 0, count: 65536)
                var count: Int
                repeat { count = recv(descriptor, &buffer, buffer.count, 0) } while count < 0 && errno == EINTR
                if count > 0 { continuation.resume(returning: Data(buffer.prefix(count))) }
                else { continuation.resume(throwing: TransportError.closed) }
            }
        }
    }
    func close() { _ = shutdown(descriptor, Int32(SHUT_RDWR)) }
}
#endif

/// Authenticated DERP client with bounded frames, keepalives and automatic reconnect.
public actor DERPTransport {
    public nonisolated let packets: AsyncThrowingStream<DERPPacket, Error>
    private let continuation: AsyncThrowingStream<DERPPacket, Error>.Continuation
    private let nodes: [DERPNode]
    private var nodeIndex = 0
    private let privateKey: Data
    private var closed = false
    private var connecting: (id: UUID, task: Task<Void, Error>)?
    private var reader: Task<Void, Never>?
    private var watchdog: Task<Void, Never>?
    private var reconnect: Task<Void, Never>?
    private var reconnectGeneration = UUID()
    private var generation = UUID()
    private var lastReceived = Date()
    private var tokens: Double = 0
    private var tokenRate: Double = 0
    private var tokenBurst: Double = 0
    private var tokenDate = ProcessInfo.processInfo.systemUptime
    private var pendingSends = 0
    private var rateWaiters = [UUID: Task<Void, Error>]()
    private var stream: DERPStream?
    private var incoming = Data()

    public init(node: DERPNode, privateKey: Data) {
        self.init(nodes: [node], privateKey: privateKey)
    }

    public init(nodes: [DERPNode], privateKey: Data) {
        self.nodes = nodes.filter { !$0.stunOnly }; self.privateKey = privateKey
        var output: AsyncThrowingStream<DERPPacket, Error>.Continuation!
        packets = AsyncThrowingStream(bufferingPolicy: .bufferingNewest(256)) { output = $0 }
        continuation = output
    }

    public func connect() async throws {
        try Task.checkCancellation()
        guard !closed else { throw TransportError.closed }
        if let connecting { return try await waitForConnection(connecting.task, id: connecting.id) }
        if stream != nil { return }
        let id = UUID()
        let task = Task { try await establishAcrossNodes() }
        connecting = (id, task)
        defer { if connecting?.id == id { connecting = nil } }
        try await waitForConnection(task, id: id)
    }

    private func waitForConnection(_ task: Task<Void, Error>, id: UUID) async throws {
        try await withTaskCancellationHandler(operation: {
            try await task.value
            try Task.checkCancellation()
        }, onCancel: {
            task.cancel()
            Task { await self.cancelConnectionAttempt(id: id) }
        })
    }

    private func cancelConnectionAttempt(id: UUID) {
        guard connecting?.id == id else { return }
        generation = UUID(); stream?.close(); stream = nil; incoming = Data()
        reader?.cancel(); watchdog?.cancel()
    }

    public func send(to key: Data, packet: Data) async throws {
        guard key.count == 32 else { throw TransportError.invalidKey }
        guard packet.count <= 65536 else { throw TransportError.oversizedPacket }
        guard pendingSends < 256 else { throw TransportError.connectionFailed("DERP send queue is full") }
        pendingSends += 1
        defer { pendingSends -= 1 }
        var lastError: Error = TransportError.closed
        for attempt in 0..<4 {
            try Task.checkCancellation()
            do {
                try await connect()
                guard let stream else { throw TransportError.closed }
                let id = generation
                try await rateLimit(packet.count + 37)
                guard generation == id, !closed else { throw TransportError.closed }
                do { try await stream.send(DERPFrame.encode(type: 4, payload: key + packet)) }
                catch { failed(id: id); throw error }
                return
            } catch {
                lastError = error
                guard !closed else { throw TransportError.closed }
                if attempt < 3 { try await Task.sleep(nanoseconds: UInt64(1 << attempt) * 250_000_000) }
            }
        }
        throw lastError
    }

    public func close() {
        guard !closed else { return }
        closed = true; generation = UUID()
        connecting?.task.cancel(); reconnect?.cancel(); reader?.cancel(); watchdog?.cancel()
        for waiter in rateWaiters.values { waiter.cancel() }
        stream?.close(); stream = nil
        continuation.finish()
    }

    private func rateLimit(_ size: Int) async throws {
        guard tokenRate > 0, tokenBurst > 0 else { return }
        guard Double(size) <= tokenBurst else { throw TransportError.oversizedPacket }
        let now = ProcessInfo.processInfo.systemUptime
        tokens = min(tokenBurst, tokens + max(0, now - tokenDate) * tokenRate)
        tokenDate = now
        tokens -= Double(size)
        if tokens < 0 {
            let delay = -tokens / tokenRate
            let waiter = Task { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            let id = UUID(); rateWaiters[id] = waiter
            defer { rateWaiters[id] = nil }
            try await withTaskCancellationHandler(operation: { try await waiter.value }, onCancel: { waiter.cancel() })
            try Task.checkCancellation()
        }
    }

    private func establishAcrossNodes() async throws {
        guard !nodes.isEmpty else { throw TransportError.invalidEndpoint }
        var lastError: Error = TransportError.invalidEndpoint
        for _ in nodes.indices {
            guard !closed else { throw TransportError.closed }
            try Task.checkCancellation()
            do { try await establish(node: nodes[nodeIndex]); return }
            catch {
                lastError = error
                nodeIndex = (nodeIndex + 1) % nodes.count
            }
        }
        throw lastError
    }

    private func establish(node: DERPNode) async throws {
        guard privateKey.count == 32 else { throw TransportError.invalidKey }
        let connection = try DERPStream(node: node)
        let id = UUID(); generation = id
        stream = connection; incoming = Data()
        // A separate timer closes stalled TLS, HTTP and DERP authentication reads.
        let timeout = Task {
            try? await Task.sleep(nanoseconds: 20_000_000_000)
            if !Task.isCancelled { connection.close() }
        }
        defer { timeout.cancel() }
        do {
            try await connection.start()
            try Task.checkCancellation()
            let host = node.hostName
            try await connection.send(Data("GET /derp HTTP/1.1\r\nHost: \(host)\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n".utf8))
            var headerEnd: Range<Data.Index>?
            while headerEnd == nil {
                guard incoming.count < 16384 else { throw TransportError.oversizedPacket }
                incoming.append(try await connection.receive())
                headerEnd = incoming.range(of: Data([13,10,13,10]))
            }
            guard let end = headerEnd,
                  end.upperBound <= 16384,
                  let text = String(data: incoming[..<end.lowerBound], encoding: .utf8) else { throw TransportError.malformedPacket }
            let lines = text.components(separatedBy: "\r\n")
            guard let status = lines.first, status.hasPrefix("HTTP/1.1 101 ") || status == "HTTP/1.1 101" else {
                throw TransportError.connectionFailed("DERP HTTP upgrade rejected")
            }
            var headers = [String: String]()
            for line in lines.dropFirst() {
                guard let colon = line.firstIndex(of: ":") else { throw TransportError.malformedPacket }
                headers[String(line[..<colon]).lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces).lowercased()
            }
            guard headers["upgrade"] == "derp",
                  headers["connection"]?.split(separator: ",").contains(where: { $0.trimmingCharacters(in: .whitespaces) == "upgrade" }) == true else {
                throw TransportError.malformedPacket
            }
            incoming = Data(incoming[end.upperBound...])
            let greeting = try await readFrame(connection)
            guard greeting.type == 1, greeting.payload.count >= 40, greeting.payload.count <= 1024,
                  greeting.payload.prefix(8) == Data("DERP🔑".utf8) else { throw TransportError.malformedPacket }
            let serverKey = Data(greeting.payload.dropFirst(8).prefix(32))
            let nonce = NaClBox.random(24)
            let info = Data("{\"version\":2,\"CanAckPings\":true}".utf8)
            let auth = try NaClBox.publicKey(for: privateKey) + nonce +
                NaClBox.seal(info, nonce: nonce, publicKey: serverKey, privateKey: privateKey)
            try await connection.send(DERPFrame.encode(type: 2, payload: auth))
            let serverInfo = try await readFrame(connection)
            guard serverInfo.type == 3, serverInfo.payload.count >= 40 else { throw TransportError.malformedPacket }
            let json = try NaClBox.open(Data(serverInfo.payload.dropFirst(24)), nonce: Data(serverInfo.payload.prefix(24)),
                                       publicKey: serverKey, privateKey: privateKey)
            guard let info = try JSONSerialization.jsonObject(with: json) as? [String: Any],
                  let version = info["version"] as? Int, version >= 2 else { throw TransportError.malformedPacket }
            tokenRate = Double(max(0, (info["TokenBucketBytesPerSecond"] as? Int) ?? 0))
            tokenBurst = Double(max(0, (info["TokenBucketBytesBurst"] as? Int) ?? 0))
            tokens = tokenBurst; tokenDate = ProcessInfo.processInfo.systemUptime; lastReceived = Date()
            guard generation == id, !closed else { throw TransportError.closed }
            try Task.checkCancellation()
            try await connection.send(DERPFrame.encode(type: 7, payload: Data([1])))
            reader = Task { await receiveLoop(connection, id: id) }
            watchdog = Task { await keepaliveLoop(connection, id: id) }
        } catch {
            connection.close()
            if generation == id { stream = nil; incoming = Data() }
            throw error
        }
    }

    private func read(_ count: Int, from connection: DERPStream) async throws -> Data {
        guard stream === connection else { throw TransportError.closed }
        while incoming.count < count {
            let bytes = try await connection.receive()
            guard stream === connection else { throw TransportError.closed }
            incoming.append(bytes)
        }
        let result = Data(incoming.prefix(count)); incoming = Data(incoming.dropFirst(count))
        return result
    }
    private func readFrame(_ connection: DERPStream) async throws -> (type: UInt8, payload: Data) {
        let header = try DERPFrame.header(await read(5, from: connection))
        return (header.type, try await read(header.length, from: connection))
    }

    private func receiveLoop(_ connection: DERPStream, id: UUID) async {
        do {
            while !Task.isCancelled, !closed, generation == id {
                let frame = try await readFrame(connection)
                guard generation == id else { return }
                lastReceived = Date()
                switch frame.type {
                case 5:
                    guard frame.payload.count >= 32, frame.payload.count <= 65568 else { throw TransportError.malformedPacket }
                    continuation.yield(DERPPacket(source: Data(frame.payload.prefix(32)), payload: Data(frame.payload.dropFirst(32))))
                case 6:
                    guard frame.payload.isEmpty else { throw TransportError.malformedPacket }
                case 0x12:
                    guard frame.payload.count == 8 else { throw TransportError.malformedPacket }
                    try await connection.send(DERPFrame.encode(type: 0x13, payload: frame.payload))
                case 0x13:
                    guard frame.payload.count == 8 else { throw TransportError.malformedPacket }
                case 8:
                    guard frame.payload.count >= 32 else { throw TransportError.malformedPacket }
                case 0x15:
                    guard frame.payload.count == 8 else { throw TransportError.malformedPacket }
                    let ms = frame.payload.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
                    failed(id: id, reconnectDelay: min(Double(ms) / 1000, 60)); return
                default: break // Future frame types are bounded by readFrame.
                }
            }
        } catch { failed(id: id) }
    }

    private func keepaliveLoop(_ connection: DERPStream, id: UUID) async {
        do {
            while !Task.isCancelled, !closed, generation == id {
                try await Task.sleep(nanoseconds: 30_000_000_000)
                guard generation == id, !closed else { return }
                guard Date().timeIntervalSince(lastReceived) < 120 else { throw TransportError.timeout }
                try await connection.send(DERPFrame.encode(type: 0x12, payload: NaClBox.random(8)))
            }
        } catch { if !Task.isCancelled { failed(id: id) } }
    }

    private func failed(id: UUID, reconnectDelay: Double = 0.25) {
        guard generation == id, !closed else { return }
        generation = UUID(); stream?.close(); stream = nil; incoming = Data()
        reader?.cancel(); watchdog?.cancel()
        for waiter in rateWaiters.values { waiter.cancel() }
        if !nodes.isEmpty { nodeIndex = (nodeIndex + 1) % nodes.count }
        reconnect?.cancel()
        let reconnectID = UUID(); reconnectGeneration = reconnectID
        reconnect = Task {
            var delay = reconnectDelay
            while !closed, !Task.isCancelled {
                do {
                    try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                    try await connect(); break
                } catch {
                    delay = min(30, max(0.25, delay * 2))
                }
            }
            if reconnectGeneration == reconnectID { reconnect = nil }
        }
    }
}