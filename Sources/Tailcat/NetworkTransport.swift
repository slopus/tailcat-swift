// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation
#if canImport(Network)
import Network
#endif
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public struct TransportPacket: Sendable, Equatable {
    public let source: Data
    public let payload: Data
    public let viaRelay: Bool
    public init(source: Data, payload: Data, viaRelay: Bool) {
        self.source = source; self.payload = payload; self.viaRelay = viaRelay
    }
}

public enum ConnectionPath: Sendable, Equatable {
    case relay
    case direct(endpoint: String)
}

struct UDPDatagram: Sendable {
    let payload: Data
    let source: DiscoveryEndpoint
}

/// Bounds unauthenticated work before it can enter the transport actor's mailbox.
struct UDPIngress: Sendable {
    static let capacity = 256
    static let maximumDatagramSize = 2048 // Tailcat's 1280-byte IP MTU plus WireGuard overhead.
    enum OfferResult: Equatable { case queued, overflow, rejected }
    let packets: AsyncStream<UDPDatagram>
    private let continuation: AsyncStream<UDPDatagram>.Continuation
    init() {
        var output: AsyncStream<UDPDatagram>.Continuation!
        packets = AsyncStream(bufferingPolicy: .bufferingNewest(Self.capacity)) { output = $0 }
        continuation = output
    }
    @discardableResult
    func offer(_ packet: Data, from endpoint: DiscoveryEndpoint) -> OfferResult {
        guard packet.count <= Self.maximumDatagramSize else { return .rejected }
        switch continuation.yield(UDPDatagram(payload: packet, source: endpoint)) {
        case .enqueued: return .queued
        case .dropped: return .overflow
        case .terminated: return .rejected
        @unknown default: return .rejected
        }
    }
    func finish() { continuation.finish() }
}

/// A single dual-stack socket keeps STUN, discovery and WireGuard on the same NAT mapping.
final class UDPChannel: @unchecked Sendable {
    let port: UInt16
    private let descriptor: Int32
    private let source: DispatchSourceRead
    private let queue = DispatchQueue(label: "tailcat.udp")
    private var closed = false // Only accessed on queue.

    init(receive: @escaping @Sendable (Data, DiscoveryEndpoint) -> Void) throws {
        #if canImport(Darwin)
        let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        #else
        let fd = socket(AF_INET6, Int32(SOCK_DGRAM.rawValue), Int32(IPPROTO_UDP))
        #endif
        guard fd >= 0 else { throw TransportError.connectionFailed("UDP socket: \(errno)") }
        descriptor = fd
        var disabled: Int32 = 0
        guard setsockopt(fd, Int32(IPPROTO_IPV6), IPV6_V6ONLY, &disabled, socklen_t(MemoryLayout<Int32>.size)) == 0,
              fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else {
            Self.closeDescriptor(fd); throw TransportError.connectionFailed("UDP configure: \(errno)")
        }
        var address = sockaddr_in6()
        address.sin6_family = sa_family_t(AF_INET6)
        #if canImport(Darwin)
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        #endif
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
        }
        guard result == 0 else { Self.closeDescriptor(fd); throw TransportError.connectionFailed("UDP bind: \(errno)") }
        var length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard named == 0 else { Self.closeDescriptor(fd); throw TransportError.connectionFailed("UDP port: \(errno)") }
        port = UInt16(bigEndian: address.sin6_port)
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler {
            var buffer = [UInt8](repeating: 0, count: 65536)
            for _ in 0..<64 {
                var remote = sockaddr_storage()
                var size = socklen_t(MemoryLayout<sockaddr_storage>.size)
                let count = withUnsafeMutablePointer(to: &remote) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        recvfrom(fd, &buffer, buffer.count, 0, $0, &size)
                    }
                }
                guard count >= 0 else { break }
                guard let endpoint = Self.endpoint(remote, size: size) else { continue }
                receive(Data(buffer.prefix(count)), endpoint)
            }
        }
        source.setCancelHandler { Self.closeDescriptor(fd) }
        source.resume()
    }

    deinit { source.cancel() }
    private static func closeDescriptor(_ fd: Int32) {
        #if canImport(Darwin)
        Darwin.close(fd)
        #else
        Glibc.close(fd)
        #endif
    }

    private static func endpoint(_ storage: sockaddr_storage, size: socklen_t) -> DiscoveryEndpoint? {
        var value = storage
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var service = [CChar](repeating: 0, count: Int(NI_MAXSERV))
        let result = withUnsafePointer(to: &value) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, size, &host, socklen_t(host.count), &service, socklen_t(service.count), NI_NUMERICHOST | NI_NUMERICSERV)
            }
        }
        guard result == 0, let port = UInt16(String(cString: service)) else { return nil }
        let parsed = DiscoveryEndpoint(host: String(cString: host), port: port)
        // Normalize mapped IPv4 so probe transaction endpoints compare exactly.
        guard let wire = try? parsed.wireBytes() else { return nil }
        return try? DiscoveryEndpoint(wire: wire)
    }

    static func resolve(host: String, port: UInt16) async throws -> [DiscoveryEndpoint] {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                var result: UnsafeMutablePointer<addrinfo>?
                var hints = addrinfo()
                hints.ai_family = AF_UNSPEC
                #if canImport(Darwin)
                hints.ai_socktype = SOCK_DGRAM
                #else
                hints.ai_socktype = Int32(SOCK_DGRAM.rawValue)
                #endif
                let status = getaddrinfo(host, String(port), &hints, &result)
                guard status == 0 else {
                    continuation.resume(throwing: TransportError.connectionFailed("UDP DNS: \(status)")); return
                }
                defer { if let result { freeaddrinfo(result) } }
                var endpoints = [DiscoveryEndpoint]()
                var current = result
                while let entry = current {
                    let a = entry.pointee
                    if let pointer = a.ai_addr, Int(a.ai_addrlen) <= MemoryLayout<sockaddr_storage>.size {
                        var storage = sockaddr_storage()
                        withUnsafeMutableBytes(of: &storage) { destination in
                            destination.copyBytes(from: UnsafeRawBufferPointer(start: pointer, count: Int(a.ai_addrlen)))
                        }
                        if let endpoint = endpoint(storage, size: a.ai_addrlen) { endpoints.append(endpoint) }
                    }
                    current = a.ai_next
                }
                continuation.resume(returning: endpoints)
            }
        }
    }

    func send(_ packet: Data, to endpoint: DiscoveryEndpoint) async throws {
        let wire = try endpoint.wireBytes()
        guard packet.count <= 65507 else { throw TransportError.oversizedPacket }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            queue.async { [self] in
                guard !closed else { continuation.resume(throwing: TransportError.closed); return }
                var address = sockaddr_in6()
                address.sin6_family = sa_family_t(AF_INET6)
                address.sin6_port = endpoint.port.bigEndian
                #if canImport(Darwin)
                address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                #endif
                withUnsafeMutableBytes(of: &address.sin6_addr) { $0.copyBytes(from: wire.prefix(16)) }
                let count = packet.withUnsafeBytes { bytes in
                    withUnsafePointer(to: &address) {
                        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            sendto(descriptor, bytes.baseAddress, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                        }
                    }
                }
                if count == packet.count { continuation.resume() }
                else { continuation.resume(throwing: TransportError.connectionFailed("UDP send: \(errno)")) }
            }
        }
    }

    func close() { queue.async { [self] in closed = true; source.cancel() } }

    func interfaceEndpoints() -> [DiscoveryEndpoint] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return [] }
        defer { freeifaddrs(list) }
        var current = list, endpoints = Set<DiscoveryEndpoint>()
        while let entry = current {
            let value = entry.pointee
            current = value.ifa_next
            guard value.ifa_flags & UInt32(IFF_UP) != 0, value.ifa_flags & UInt32(IFF_LOOPBACK) == 0,
                  let address = value.ifa_addr else { continue }
            let family = Int32(address.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            let size = family == AF_INET ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size
            var storage = sockaddr_storage()
            withUnsafeMutableBytes(of: &storage) { $0.copyBytes(from: UnsafeRawBufferPointer(start: address, count: size)) }
            if let endpoint = Self.endpoint(storage, size: socklen_t(size)), !endpoint.host.contains("%"),
               !endpoint.host.hasPrefix("fe80:"), endpoint.host != "0.0.0.0", endpoint.host != "::" {
                endpoints.insert(DiscoveryEndpoint(host: endpoint.host, port: port))
            }
        }
        return Array(endpoints).sorted { $0.description < $1.description }
    }
}

/// Routes encrypted WireGuard datagrams over verified UDP paths, with DERP fallback.
public actor NetworkTransport {
    public nonisolated let packets: AsyncThrowingStream<TransportPacket, Error>
    private let continuation: AsyncThrowingStream<TransportPacket, Error>.Continuation
    private let privateKey: Data
    private let discoPrivateKey: Data
    private let relay: DERPTransport
    private let relayNodes: [DERPNode]
    private var udp: UDPChannel?
    private var udpIngress: UDPIngress?
    private var udpReader: Task<Void, Never>?
    private var relayReader: Task<Void, Never>?
    private var maintenance: Task<Void, Never>?
    private var starting: Task<Void, Error>?
    private var started = false
    private var closed = false
    private struct Peer {
        var discoKey: Data
        var endpoints: Set<DiscoveryEndpoint>
        var direct: DiscoveryEndpoint?
        var verified = Date.distantPast
        var lastProbe = Date.distantPast
        var lastCall = Date.distantPast
        var lastInvitation = Date.distantPast
        var generation = UUID()
        // Receive bindings are independent of our preferred outbound path.
        var inbound = [DiscoveryEndpoint: Date]()
    }
    private struct Probe {
        let peer: Data
        let endpoint: DiscoveryEndpoint
        let sent: Date
    }
    private var peers = [Data: Peer]()
    private var probes = [Data: Probe]()
    private var stun = [Data: (endpoint: DiscoveryEndpoint, sent: Date)]()
    private var observed = [DiscoveryEndpoint: Date]()
    private var stunServers = [DiscoveryEndpoint]()
    private var lastSTUN = Date.distantPast
    private var stunDiscoveryGeneration = UUID()
    #if canImport(Network)
    private var pathMonitor: NWPathMonitor?
    private var pathSignature: String?
    #endif

    public init(privateKey: Data, discoPrivateKey: Data, relayNode: DERPNode) {
        self.init(privateKey: privateKey, discoPrivateKey: discoPrivateKey, relayNodes: [relayNode])
    }

    public init(privateKey: Data, discoPrivateKey: Data, relayNodes: [DERPNode]) {
        self.privateKey = privateKey; self.discoPrivateKey = discoPrivateKey; self.relayNodes = relayNodes
        relay = DERPTransport(nodes: relayNodes, privateKey: privateKey)
        var output: AsyncThrowingStream<TransportPacket, Error>.Continuation!
        packets = AsyncThrowingStream(bufferingPolicy: .bufferingNewest(256)) { output = $0 }
        continuation = output
    }

    public func start() async throws {
        try Task.checkCancellation()
        guard !closed else { throw TransportError.closed }
        if let starting { return try await waitForStartup(starting) }
        if started { return }
        let task = Task { try await begin() }
        starting = task
        defer { starting = nil }
        try await waitForStartup(task)
    }
    private func waitForStartup(_ task: Task<Void, Error>) async throws {
        try await withTaskCancellationHandler(operation: {
            try await task.value
            try Task.checkCancellation()
        }, onCancel: { task.cancel() })
    }
    private func begin() async throws {
        try Task.checkCancellation()
        _ = try NaClBox.publicKey(for: discoPrivateKey)
        do {
            let ingress = UDPIngress()
            udpIngress = ingress
            udp = try UDPChannel { packet, endpoint in
                ingress.offer(packet, from: endpoint)
            }
            udpReader = Task { [weak self] in
                for await datagram in ingress.packets {
                    guard !Task.isCancelled else { break }
                    await self?.receiveUDP(datagram.payload, from: datagram.source)
                }
            }
            try await relay.connect()
            try Task.checkCancellation()
            guard !closed else { throw TransportError.closed }
            started = true
            relayReader = Task { [weak self, relay] in
                do {
                    for try await packet in relay.packets { await self?.receiveRelay(packet) }
                } catch { await self?.relayEnded(error) }
            }
            #if canImport(Network)
            monitorNetworkPath()
            #endif
            maintenance = Task { [weak self] in
                await self?.discoverSTUNServers()
                while !Task.isCancelled {
                    await self?.maintain()
                    do { try await Task.sleep(nanoseconds: 5_000_000_000) } catch { break }
                }
            }
        } catch {
            udpIngress?.finish(); udpIngress = nil; udpReader?.cancel(); udpReader = nil
            udp?.close(); udp = nil; throw error
        }
    }

    private func discoverSTUNServers() async {
        let generation = UUID(); stunDiscoveryGeneration = generation
        var discovered = Set<DiscoveryEndpoint>()
        for node in relayNodes where node.stunPort >= 0 {
            guard !closed, !Task.isCancelled, stunDiscoveryGeneration == generation else { return }
            let port = UInt16(exactly: node.stunPort > 0 ? node.stunPort : 3478) ?? 3478
            let host = !node.ipv4.isEmpty && node.ipv4 != "none" ? node.ipv4 : node.hostName
            let ipv4 = (try? await UDPChannel.resolve(host: host, port: port)) ?? []
            guard !closed, !Task.isCancelled, stunDiscoveryGeneration == generation else { return }
            discovered.formUnion(ipv4)
            if !node.ipv6.isEmpty, node.ipv6 != "none" {
                let ipv6 = (try? await UDPChannel.resolve(host: node.ipv6, port: port)) ?? []
                guard !closed, !Task.isCancelled, stunDiscoveryGeneration == generation else { return }
                discovered.formUnion(ipv6)
            }
        }
        stunServers = Array(discovered)
    }

    #if canImport(Network)
    private func monitorNetworkPath() {
        let monitor = NWPathMonitor()
        pathMonitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
            let kinds: [NWInterface.InterfaceType] = [.wifi, .cellular, .wiredEthernet, .loopback, .other]
            let used = kinds.filter { path.usesInterfaceType($0) }.map { String(describing: $0) }
            let names = path.availableInterfaces.filter { path.usesInterfaceType($0.type) }.map(\.name).sorted()
            let signature = ([String(describing: path.status), String(path.isExpensive), String(path.isConstrained)] + used + names).joined(separator: ":")
            Task { await self?.networkPathChanged(signature) }
        }
        monitor.start(queue: DispatchQueue(label: "tailcat.network-path"))
    }

    private func networkPathChanged(_ signature: String) async {
        guard !closed, started else { return }
        let previous = pathSignature
        pathSignature = signature
        guard let previous, previous != signature else { return }
        resetDirectPaths()
        await discoverSTUNServers()
        guard !closed, pathSignature == signature else { return }
        await maintain()
    }
    #endif

    public func configurePeer(nodeKey: Data, discoKey: Data, endpoints: [String] = []) async throws {
        guard nodeKey.count == 32, discoKey.count == 32,
              nodeKey.contains(where: { $0 != 0 }), discoKey.contains(where: { $0 != 0 }) else { throw TransportError.invalidKey }
        // A discovery key belongs to exactly one configured WireGuard identity.
        guard !peers.contains(where: { $0.key != nodeKey && $0.value.discoKey == discoKey }) else { throw TransportError.invalidKey }
        let addresses = try Set(endpoints.map { try DiscoveryEndpoint($0) })
        guard addresses.count <= 128 else { throw TransportError.oversizedPacket }
        if var peer = peers[nodeKey], peer.discoKey == discoKey {
            peer.endpoints.formUnion(addresses)
            guard peer.endpoints.count <= 128 else { throw TransportError.oversizedPacket }
            peers[nodeKey] = peer
        } else { peers[nodeKey] = Peer(discoKey: discoKey, endpoints: addresses) }
        if started { await probe(nodeKey); await callMeMaybe(nodeKey) }
    }

    public func removePeer(_ nodeKey: Data) {
        peers[nodeKey] = nil
        probes = probes.filter { $0.value.peer != nodeKey }
    }

    public func removePeer(nodeKey: Data) { removePeer(nodeKey) }

    public func path(to nodeKey: Data) -> ConnectionPath {
        guard let peer = peers[nodeKey], let endpoint = peer.direct, udp != nil,
              Date().timeIntervalSince(peer.verified) < 30 else { return .relay }
        return .direct(endpoint: endpoint.description)
    }

    /// Invalidates a failed path immediately; discovery can establish a fresh path later.
    func invalidateDirectPath(to nodeKey: Data) {
        peers[nodeKey]?.direct = nil
        peers[nodeKey]?.generation = UUID()
        probes = probes.filter { $0.value.peer != nodeKey }
    }

    /// Call after a network change to discard paths tied to the previous NAT mapping.
    public func resetDirectPaths() {
        for key in peers.keys {
            peers[key]?.direct = nil; peers[key]?.lastProbe = .distantPast; peers[key]?.generation = UUID()
            peers[key]?.lastCall = .distantPast; peers[key]?.lastInvitation = .distantPast
            peers[key]?.inbound.removeAll()
        }
        probes.removeAll(); stun.removeAll(); observed.removeAll(); lastSTUN = .distantPast
    }

    public func send(to nodeKey: Data, packet: Data) async throws {
        guard !closed else { throw TransportError.closed }
        guard nodeKey.count == 32 else { throw TransportError.invalidKey }
        if !started { try await start() }
        if packet.starts(with: Data("meow".utf8)) {
            try await relay.send(to: nodeKey, packet: packet)
            return
        }
        if packet.count <= UDPIngress.maximumDatagramSize, let peer = peers[nodeKey], let direct = peer.direct,
           Date().timeIntervalSince(peer.verified) < 30, let udp {
            do { try await udp.send(packet, to: direct); return }
            catch { invalidateDirectPath(to: nodeKey) }
        }
        try await relay.send(to: nodeKey, packet: packet)
        if let peer = peers[nodeKey], Date().timeIntervalSince(peer.lastProbe) >= 5 {
            await probe(nodeKey); await callMeMaybe(nodeKey)
        }
    }

    public func localEndpoints() -> [String] {
        var endpoints = Set(udp?.interfaceEndpoints() ?? [])
        for (endpoint, date) in observed where Date().timeIntervalSince(date) < 120 { endpoints.insert(endpoint) }
        return endpoints.map(\.description).sorted()
    }

    public func close() async {
        guard !closed else { return }
        closed = true; started = false
        starting?.cancel(); relayReader?.cancel(); maintenance?.cancel()
        udpIngress?.finish(); udpIngress = nil; udpReader?.cancel(); udpReader = nil
        #if canImport(Network)
        pathMonitor?.cancel(); pathMonitor = nil
        #endif
        udp?.close(); udp = nil
        await relay.close(); continuation.finish()
    }

    private func relayEnded(_ error: Error) { if !closed { continuation.finish(throwing: error) } }

    private func receiveRelay(_ packet: DERPPacket) async {
        if Discovery.isPacket(packet.payload) {
            await receiveDiscovery(packet.payload, endpoint: nil, relaySource: packet.source)
        } else {
            continuation.yield(TransportPacket(source: packet.source, payload: packet.payload, viaRelay: true))
        }
    }

    private func receiveUDP(_ packet: Data, from endpoint: DiscoveryEndpoint) async {
        guard !closed else { return }
        if packet.count >= 20, packet.prefix(2) == Data([1,1]),
           packet.dropFirst(4).prefix(4) == Data([0x21,0x12,0xa4,0x42]) {
            let transaction = Data(packet.dropFirst(8).prefix(12))
            guard let pending = stun[transaction], pending.endpoint == endpoint,
                  Date().timeIntervalSince(pending.sent) < 10,
                  let mapped = try? STUN.response(packet, transaction: transaction) else { return }
            stun[transaction] = nil; observed[mapped] = Date()
            for key in peers.keys { await callMeMaybe(key) }
        } else if Discovery.isPacket(packet) {
            await receiveDiscovery(packet, endpoint: endpoint, relaySource: nil)
        } else {
            let now = Date()
            for (key, peer) in peers {
                guard let authenticated = peer.inbound[endpoint], now.timeIntervalSince(authenticated) < 120 else { continue }
                // An endpoint can be shared by configured identities. The WireGuard
                // authentication layer determines which peer owns the datagram.
                continuation.yield(TransportPacket(source: key, payload: packet, viaRelay: false))
            }
        }
    }

    private func bindInbound(_ endpoint: DiscoveryEndpoint, to key: Data) {
        guard var peer = peers[key] else { return }
        let now = Date()
        peer.inbound = peer.inbound.filter { now.timeIntervalSince($0.value) < 120 }
        if peer.inbound[endpoint] == nil, peer.inbound.count >= 128,
           let oldest = peer.inbound.min(by: { $0.value < $1.value })?.key {
            peer.inbound[oldest] = nil
        }
        peer.inbound[endpoint] = now
        peers[key] = peer
    }

    private func receiveDiscovery(_ packet: Data, endpoint: DiscoveryEndpoint?, relaySource: Data?) async {
        guard let source = Discovery.sourceKey(packet),
              let match = peers.first(where: { $0.value.discoKey == source }),
              relaySource == nil || relaySource == match.key,
              let sender = try? Discovery.open(packet, privateKey: discoPrivateKey) else { return }
        let key = match.key
        switch sender.message {
        case let .ping(transaction, claimedKey):
            guard claimedKey == nil || claimedKey == key else { return }
            if let endpoint, let udp {
                bindInbound(endpoint, to: key)
                if peers[key]?.endpoints.count ?? 0 < 128 { peers[key]?.endpoints.insert(endpoint) }
                if let response = try? Discovery.seal(.pong(transaction: transaction, observed: endpoint), to: sender.source, privateKey: discoPrivateKey) {
                    try? await udp.send(response, to: endpoint)
                }
                if Date().timeIntervalSince(peers[key]?.lastProbe ?? .distantPast) >= 1 { await probe(key) }
            }
        case let .pong(transaction, mapped):
            guard let pending = probes.removeValue(forKey: transaction), pending.peer == key,
                  pending.endpoint == endpoint, Date().timeIntervalSince(pending.sent) < 10,
                  let endpoint else { return }
            bindInbound(endpoint, to: key)
            peers[key]?.direct = endpoint; peers[key]?.verified = Date()
            observed[mapped] = Date()
        case let .callMeMaybe(endpoints):
            // Only the relay's authenticated source can authorize endpoint invitations.
            guard relaySource == key, endpoint == nil else { return }
            for address in endpoints.prefix(128) where address.port != 0 {
                if peers[key]?.endpoints.count ?? 0 < 128 { peers[key]?.endpoints.insert(address) }
            }
            // The invitation proves the peer is now ready; an earlier UDP probe
            // may have arrived before it registered our discovery key.
            if Date().timeIntervalSince(peers[key]?.lastInvitation ?? .distantPast) >= 1 {
                peers[key]?.lastInvitation = Date()
                await probe(key)
            }
        }
    }

    private func probe(_ key: Data) async {
        guard let peer = peers[key], let udp, let nodePublic = try? NaClBox.publicKey(for: privateKey) else { return }
        peers[key]?.lastProbe = Date()
        for endpoint in peer.endpoints.prefix(128) {
            guard !closed, peers[key]?.generation == peer.generation else { return }
            let transaction = NaClBox.random(12)
            guard let packet = try? Discovery.seal(.ping(transaction: transaction, nodeKey: nodePublic), to: peer.discoKey, privateKey: discoPrivateKey) else { continue }
            probes[transaction] = Probe(peer: key, endpoint: endpoint, sent: Date())
            try? await udp.send(packet, to: endpoint)
        }
    }

    private func callMeMaybe(_ key: Data) async {
        guard let peer = peers[key], Date().timeIntervalSince(peer.lastCall) >= 1 else { return }
        peers[key]?.lastCall = Date()
        let endpoints = localEndpoints().prefix(128).compactMap { try? DiscoveryEndpoint($0) }
        guard let packet = try? Discovery.seal(.callMeMaybe(endpoints), to: peer.discoKey, privateKey: discoPrivateKey) else { return }
        try? await relay.send(to: key, packet: packet)
    }

    private func maintain() async {
        guard !closed else { return }
        let now = Date()
        probes = probes.filter { now.timeIntervalSince($0.value.sent) < 10 }
        stun = stun.filter { now.timeIntervalSince($0.value.sent) < 10 }
        observed = observed.filter { now.timeIntervalSince($0.value) < 120 }
        for key in Array(peers.keys) {
            guard var peer = peers[key] else { continue }
            peer.inbound = peer.inbound.filter { now.timeIntervalSince($0.value) < 120 }
            peers[key] = peer
        }
        if now.timeIntervalSince(lastSTUN) >= 30, let udp {
            lastSTUN = now
            for endpoint in stunServers {
                let transaction = NaClBox.random(12)
                stun[transaction] = (endpoint, now)
                if let packet = try? STUN.request(transaction: transaction) { try? await udp.send(packet, to: endpoint) }
            }
        }
        for (key, peer) in peers {
            if now.timeIntervalSince(peer.lastProbe) >= 10 { await probe(key) }
            if now.timeIntervalSince(peer.lastCall) >= 25 { await callMeMaybe(key) }
        }
    }
}