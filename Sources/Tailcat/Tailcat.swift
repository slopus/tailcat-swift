// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation

/// A server embedded in your app. Start it, share its address, and accept byte streams.
public actor TailcatServer {
    public struct Configuration: Sendable {
        public var privateKey: NodePrivateKey?
        public var presharedKey: PresharedKey?
        public var disablePresharedKey = false
        /// Start over DERP without waiting for UDP setup; discover direct paths in the background.
        public var relayFirst = false
        var directDiscovery = DirectDiscovery()
        public var region: DERPRegion?
        public var regionID = -1
        public var mapURL = DERPMap.defaultURL
        public var mapCache: any DERPMapCache = MemoryDERPMapCache.shared
        public var allowClient: (@Sendable (NodePublicKey) async -> Bool)?
        public var onTCP: (@Sendable (UInt16) -> TailcatTCPHandler?)?
        public var onUDP: (@Sendable (UInt16) -> TailcatUDPHandler?)?
        public var onTCPForward: (@Sendable (TailcatEndpoint) -> TailcatTCPHandler?)?
        public var onUDPForward: (@Sendable (TailcatEndpoint) -> TailcatUDPHandler?)?
        public var allowProxy: (@Sendable (TailcatEndpoint) -> Bool)?
        public var servedTCPPorts: Set<UInt16>?
        public var servedUDPPorts: Set<UInt16>?
        public var udpIdleTimeout: TimeInterval = 120
        public init() {}
    }
    private let configuration: Configuration
    private var engine: TailcatEngine?
    private var starting = false
    private var startup: Task<TailcatEngine, Error>?
    private var closed = false
    private var udpListeners: [TailcatUDPListener] = []
    public init(configuration: Configuration = Configuration()) { self.configuration = configuration }

    /// Startup is cancellable. Cancellation after startup leaves the server running until close().
    public func start() async throws {
        guard !closed else { throw TailcatError.closed }
        guard engine == nil, !starting else { throw TailcatError.alreadyStarted }
        guard configuration.udpIdleTimeout > 0 else { throw TailcatError.invalidAddress("UDP idle timeout must be positive") }
        starting = true; defer { starting = false; startup = nil }
        let task = Task { [configuration] in try await Self.startEngine(configuration) }
        startup = task
        let e = try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
        guard !closed else { await e.close(); throw TailcatError.closed }
        engine = e
    }
    private static func startEngine(_ configuration: Configuration) async throws -> TailcatEngine {
        let key = try configuration.privateKey ?? NodePrivateKey.generate()
        let psk: PresharedKey?
        if configuration.disablePresharedKey { psk = nil }
        else if let supplied = configuration.presharedKey, !supplied.isZero { psk = supplied }
        else { psk = try PresharedKey.generate() }
        var address = try TailcatAddress(serverPublicKey: key.publicKey, serverDiscoPublicKey: key.discoPublicKey, presharedKey: psk, regions: configuration.region.map { [$0] } ?? [], regionID: configuration.regionID)
        address = try await address.expanded(mapURL: configuration.mapURL, cache: configuration.mapCache, forServer: true)
        address.regionID = 0
        try Task.checkCancellation()
        let e = try TailcatEngine(key: key, address: address, server: true, configuration: configuration)
        do {
            try await e.start()
            try Task.checkCancellation()
            return e
        } catch { await e.close(); throw error }
    }
    public var address: TailcatAddress {
        get async throws { guard let engine else { throw TailcatError.notStarted }; return engine.address }
    }
    public var publicKey: NodePublicKey {
        get async throws { guard let engine else { throw TailcatError.notStarted }; return engine.publicKey }
    }
    public func listen(port: UInt16) async throws -> TailcatListener {
        if engine == nil { try await start() }
        guard let engine else { throw TailcatError.notStarted }
        return try await engine.listen(port: port)
    }
    public func listenUDP(port: UInt16) async throws -> TailcatUDPListener {
        if engine == nil { try await start() }
        guard let engine else { throw TailcatError.notStarted }
        let socket = try await engine.udp(port: port, idleTimeout: nil)
        let listener = TailcatUDPListener(socket: socket, idleTimeout: configuration.udpIdleTimeout)
        udpListeners.append(listener)
        return listener
    }
    public func peerKey(for connection: TailcatConnection) async -> NodePublicKey? {
        await engine?.peerKey(address: connection.remoteAddress)
    }
    public func peerKey(for connection: TailcatUDPConnection) async -> NodePublicKey? {
        await engine?.peerKey(address: connection.remoteAddress)
    }
    public func peerKey(remoteAddress: Data) async -> NodePublicKey? { await engine?.peerKey(address: remoteAddress) }
    public func path(to key: NodePublicKey) async throws -> ConnectionPath {
        guard let engine else { throw TailcatError.notStarted }; return await engine.path(to: key)
    }
    /// Probe without dropping an existing route or encrypted session. Nil targets all peers.
    public func retryDirect(to key: NodePublicKey? = nil) async { await engine?.retryDirect(to: key) }
    /// Discard old network paths, rebind UDP and reconnect DERP, preserving encrypted sessions.
    public func notifyNetworkChanged() async { await engine?.notifyNetworkChanged() }
    public func resetNetworkPaths() async { await notifyNetworkChanged() }
    /// The server's own TCP flows (its listeners' and those it opened);
    /// zero before it starts. Forwarded flows are not counted.
    public var flowStatistics: TailcatFlowStatistics {
        get async { await engine?.flowStatistics() ?? TailcatFlowStatistics(open: 0, closing: 0) }
    }
    public func disconnectClient(_ key: NodePublicKey) async {
        await engine?.disconnect(key)
        for listener in udpListeners { await listener.disconnect(peer: key.address) }
    }
    public func close() async {
        closed = true
        if let pending = startup { pending.cancel(); _ = await pending.result }
        for listener in udpListeners { await listener.close() }; udpListeners.removeAll()
        await engine?.close(); engine = nil
    }
}

/// One encrypted peer relationship; any number of TCP streams can share the tunnel.
public actor TailcatClient {
    public struct Configuration: Sendable {
        public var privateKey: NodePrivateKey?
        public var mapURL = DERPMap.defaultURL
        public var mapCache: any DERPMapCache = MemoryDERPMapCache.shared
        public var connectTimeout: TimeInterval = 30
        /// Start over DERP without waiting for UDP setup; discover direct paths in the background.
        public var relayFirst = false
        var directDiscovery = DirectDiscovery()
        package var startupTrace: StartupTrace?
        public init() {}
    }
    private let engine: TailcatEngine
    public let serverAddress: TailcatAddress
    public let publicKey: NodePublicKey
    private init(engine: TailcatEngine, address: TailcatAddress, publicKey: NodePublicKey) {
        self.engine = engine; serverAddress = address; self.publicKey = publicKey
    }
    public static func connect(to address: TailcatAddress, configuration: Configuration = Configuration()) async throws -> TailcatClient {
        guard configuration.connectTimeout > 0, configuration.connectTimeout.isFinite else { throw TailcatError.timedOut }
        return try await withThrowingTaskGroup(of: TailcatClient.self) { group in
            group.addTask { try await connectPrepared(to: address, configuration: configuration) }
            group.addTask {
                let nanoseconds = min(configuration.connectTimeout * 1_000_000_000, Double(UInt64.max / 2))
                try await Task.sleep(nanoseconds: UInt64(nanoseconds)); throw TailcatError.timedOut
            }
            defer { group.cancelAll() }
            guard let connected = try await group.next() else { throw TailcatError.closed }
            return connected
        }
    }
    private static func connectPrepared(to address: TailcatAddress, configuration: Configuration) async throws -> TailcatClient {
        let trace = configuration.startupTrace
        trace?.record("connectStarted")
        let key = try configuration.privateKey ?? NodePrivateKey.generate()
        trace?.record("identityGenerated")
        let expanded = try await address.expanded(mapURL: configuration.mapURL, cache: configuration.mapCache)
        trace?.record("addressExpanded")
        guard let disco = expanded.serverDiscoPublicKey, disco.count == 32, disco.contains(where: { $0 != 0 }) else {
            throw TailcatError.invalidAddress("server discovery key is required")
        }
        var transportConfiguration = TailcatServer.Configuration()
        transportConfiguration.relayFirst = configuration.relayFirst
        transportConfiguration.directDiscovery = configuration.directDiscovery
        let engine = try TailcatEngine(key: key, address: expanded, server: false, configuration: transportConfiguration, startupTrace: trace)
        do {
            try await engine.start()
            trace?.record("engineStarted")
            try await engine.connect(timeout: configuration.connectTimeout)
            trace?.record("connectReturned")
            return TailcatClient(engine: engine, address: expanded, publicKey: try key.publicKey)
        } catch { await engine.close(); throw error }
    }
    public static func connect(to text: String, configuration: Configuration = Configuration()) async throws -> TailcatClient {
        try await connect(to: TailcatAddress(text), configuration: configuration)
    }
    public func openTCP(port: UInt16) async throws -> TailcatConnection { try await engine.openTCP(port: port) }
    public func openTCP(to endpoint: TailcatEndpoint) async throws -> TailcatConnection { try await engine.openTCP(to: endpoint) }
    public func openUDP(to endpoint: TailcatEndpoint) async throws -> TailcatUDPConnection {
        let socket = try await engine.udp(port: 0)
        return TailcatUDPConnection(socket: socket, peer: endpoint.tunnelAddress, port: endpoint.port)
    }
    public func openUDP(port: UInt16) async throws -> TailcatUDPConnection {
        let socket = try await engine.udp(port: 0)
        return TailcatUDPConnection(socket: socket, peer: serverAddress.serverPublicKey.address, port: port)
    }
    public func close() async { await engine.close() }
    package var discoveryPublicKey: Data { get async throws { try await engine.discoveryPublicKey } }
    public var path: ConnectionPath { get async { await engine.path(to: serverAddress.serverPublicKey) } }
    /// Request a background probe without disrupting the current route or session.
    public func retryDirect() async { await engine.retryDirect(to: serverAddress.serverPublicKey) }
    public func notifyNetworkChanged() async { await engine.notifyNetworkChanged() }
    public func resetNetworkPaths() async { await notifyNetworkChanged() }
    /// This client's TCP flows to the server, open and closing, against
    /// the budgets in `TailcatFlowStatistics`.
    public var flowStatistics: TailcatFlowStatistics { get async { await engine.flowStatistics() } }
}

/// Owns session state, binds authenticated node identities to tunnel IPs, and drives protocol timers.
internal actor TailcatEngine {
    let address: TailcatAddress
    let publicKey: NodePublicKey
    private let key: NodePrivateKey
    private let server: Bool
    private let configuration: TailcatServer.Configuration
    private let allowClient: (@Sendable (NodePublicKey) async -> Bool)?
    private let network: NetworkTransport
    private var stack: IPStack!
    private var peers: [Data: Peer] = [:]
    private var admitting: [Data: (UUID, Task<Void, Never>)] = [:]
    private var reader: Task<Void, Never>?
    private var timer: Task<Void, Never>?
    private var connectionWaiter: (id: UUID, continuation: CheckedContinuation<Void, Error>)?
    private var connectionDeadline: Task<Void, Never>?
    private var closed = false
    private var explicitTCPPorts: Set<UInt16> = []
    private var explicitUDPPorts: Set<UInt16> = []
    private var targets: [Data: IPStack] = [:]
    private var targetActivity: [Data: Date] = [:]
    private struct HandlerKey: Hashable { let address: Data; let port: UInt16; let udp: Bool }
    private var handlerTasks: [HandlerKey: Task<Void, Never>] = [:]
    private var handlerTCP: [HandlerKey: TailcatListener] = [:]
    private var handlerUDP: [HandlerKey: TailcatUDPListener] = [:]
    private struct HandlerFlowKey: Hashable {
        let address: Data; let peer: Data; let localPort: UInt16; let remotePort: UInt16
    }
    private var selectedTCPHandlers: [HandlerFlowKey: (TailcatTCPHandler, Date)] = [:]
    private struct Peer {
        var wireguard: WireGuard
        var disco: Data
        var acknowledged = false
        var lastMeow = Date.distantPast
        var lastHandshake = Date.distantPast
        var lastSend = Date()
        var pending: [Data] = []
        var pendingBytes = 0
        var admittedAt = Date()
        var authenticated = false
        var lastReceived = Date()
        /// The last packet with application bytes, either way.
        var lastActivity = Date()
    }
    private let startupTrace: StartupTrace?
    var discoveryPublicKey: Data { get throws { try key.discoPublicKey } }
    init(key: NodePrivateKey, address: TailcatAddress, server: Bool, configuration: TailcatServer.Configuration = .init(), startupTrace: StartupTrace? = nil) throws {
        guard address.regions.first?.nodes.contains(where: { !$0.stunOnly }) == true else { throw TailcatError.noRelay }
        self.key = key; self.publicKey = try key.publicKey; self.address = address
        self.server = server; self.configuration = configuration; self.allowClient = configuration.allowClient
        self.startupTrace = startupTrace
        self.network = NetworkTransport(privateKey: key.rawValue, discoPrivateKey: key.discoPrivateKey, relayNodes: address.regions[0].nodes.filter { !$0.stunOnly }, relayFirst: configuration.relayFirst, discovery: configuration.directDiscovery, deferDirectUntilAuthenticated: configuration.relayFirst, startupTrace: startupTrace)
    }
    func start() async throws {
        await network.setRelayMarkerProvider { [weak self] node in
            try await self?.makeRelayResetMarker(to: node)
        }
        stack = IPStack(address: publicKey.address) { [weak self] packet in
            guard let self else { throw TailcatError.closed }; try await self.sendIP(packet)
        }
        if !server {
            let peerKey = address.serverPublicKey.rawValue
            guard let disco = address.serverDiscoPublicKey else { throw TailcatError.invalidKey }
            peers[peerKey] = Peer(wireguard: try newWireGuard(peerKey), disco: disco)
            try await network.configurePeer(nodeKey: peerKey, discoKey: disco, endpoints: [])
        }
        try await network.start()
        reader = Task { [weak self, network] in
            do { for try await packet in network.packets { await self?.receive(packet) } }
            catch { await self?.close() }
        }
        timer = Task { [weak self] in
            var delay: TimeInterval = 1
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) } catch { break }
                guard let next = await self?.tickAndDelay() else { break }
                delay = next
            }
        }
    }
    /// One tick, then how long until the next: every second while anything
    /// is connecting or moving data, else until the next idle mark.
    private func tickAndDelay() async -> TimeInterval {
        await tick()
        guard !server, !closed else { return 1 }
        let now = Date()
        let busy = peers.values.contains {
            !$0.acknowledged || !$0.wireguard.isEstablished || !$0.pending.isEmpty || now.timeIntervalSince($0.lastActivity) < Self.idleAfter
        }
        return busy ? 1 : IdleGrid.untilNextMark()
    }
    /// No application bytes either way for this long: keepalives and rekeys
    /// wait for the shared idle marks.
    static let idleAfter: TimeInterval = 30
    /// An idle client's keepalive: the server forgets a peer silent for 300 s.
    static let idleKeepalive: TimeInterval = 110
    private func newWireGuard(_ peer: Data) throws -> WireGuard {
        try WireGuard(privateKey: key.rawValue, peerPublicKey: peer, presharedKey: address.presharedKey?.rawValue ?? Data(repeating: 0, count: 32))
    }
    func connect(timeout: TimeInterval) async throws {
        try Task.checkCancellation()
        guard !closed else { throw TailcatError.closed }
        guard timeout > 0, timeout.isFinite else { throw TailcatError.timedOut }
        if peers[address.serverPublicKey.rawValue]?.wireguard.isEstablished == true { return }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        try await tickThrowing()
        let id = UUID()
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                // tickThrowing can suspend while the reader authenticates the
                // handshake. Recheck before installing the one bounded waiter.
                if Task.isCancelled { continuation.resume(throwing: CancellationError()); return }
                if closed { continuation.resume(throwing: TailcatError.closed); return }
                if peers[address.serverPublicKey.rawValue]?.wireguard.isEstablished == true {
                    continuation.resume(); return
                }
                guard connectionWaiter == nil else { continuation.resume(throwing: TailcatError.alreadyStarted); return }
                let remaining = deadline - ProcessInfo.processInfo.systemUptime
                guard remaining > 0 else { continuation.resume(throwing: TailcatError.timedOut); return }
                connectionWaiter = (id, continuation)
                startupTrace?.record("connectionWaiterInstalled")
                connectionDeadline = Task { [weak self] in
                    do { try await Task.sleep(nanoseconds: UInt64(min(remaining * 1_000_000_000, Double(UInt64.max / 2)))) }
                    catch { return }
                    await self?.finishConnection(.failure(TailcatError.timedOut), id: id)
                }
            }
        }, onCancel: {
            Task { await self.finishConnection(.failure(CancellationError()), id: id) }
        })
        try Task.checkCancellation()
        guard !closed else { throw TailcatError.closed }
    }
    private func finishConnection(_ result: Result<Void, Error>, id: UUID? = nil) {
        guard let waiter = connectionWaiter, id == nil || waiter.id == id else { return }
        connectionWaiter = nil
        connectionDeadline?.cancel(); connectionDeadline = nil
        startupTrace?.record("connectionWaiterResolved")
        waiter.continuation.resume(with: result)
    }
    func listen(port: UInt16) async throws -> TailcatListener {
        guard !closed else { throw TailcatError.closed }
        let handlerKey = HandlerKey(address: publicKey.address, port: port, udp: false)
        if let automatic = handlerTCP.removeValue(forKey: handlerKey) {
            handlerTasks.removeValue(forKey: handlerKey)?.cancel(); await automatic.close()
        }
        let listener = try await stack.listen(port: port); explicitTCPPorts.insert(listener.port); return listener
    }
    func udp(port: UInt16, idleTimeout: TimeInterval? = 120) async throws -> TailcatUDPSocket {
        guard !closed else { throw TailcatError.closed }
        if server {
            let handlerKey = HandlerKey(address: publicKey.address, port: port, udp: true)
            if let automatic = handlerUDP.removeValue(forKey: handlerKey) {
                handlerTasks.removeValue(forKey: handlerKey)?.cancel(); await automatic.close()
            }
        }
        let socket = try await stack.udp(port: port, idleTimeout: idleTimeout)
        if server { explicitUDPPorts.insert(socket.port) }
        return socket
    }
    func openTCP(port: UInt16) async throws -> TailcatConnection {
        guard !closed else { throw TailcatError.closed }; return try await stack.connect(peer: address.serverPublicKey.address, port: port)
    }
    func openTCP(to endpoint: TailcatEndpoint) async throws -> TailcatConnection {
        guard !closed else { throw TailcatError.closed }; return try await stack.connect(peer: endpoint.tunnelAddress, port: endpoint.port)
    }
    func peerKey(address: Data) -> NodePublicKey? {
        for raw in peers.keys { if let key = try? NodePublicKey(rawValue: raw), key.address == address { return key } }
        return nil
    }
    func path(to key: NodePublicKey) async -> ConnectionPath { await network.path(to: key.rawValue) }
    func retryDirect(to key: NodePublicKey?) async { await network.retryDirect(to: key?.rawValue) }
    func notifyNetworkChanged() async { await network.notifyNetworkChanged() }
    func flowStatistics() async -> TailcatFlowStatistics {
        guard let stack else { return TailcatFlowStatistics(open: 0, closing: 0) }
        return await stack.flowStatistics
    }
    func disconnect(_ peer: NodePublicKey) async {
        admitting.removeValue(forKey: peer.rawValue)?.1.cancel()
        peers.removeValue(forKey: peer.rawValue)
        await stack.disconnect(peer: peer.address)
        for target in targets.values { await target.disconnect(peer: peer.address) }
        for listener in handlerUDP.values { await listener.disconnect(peer: peer.address) }
        await network.removePeer(nodeKey: peer.rawValue)
    }
    func close() async {
        guard !closed else { return }; closed = true
        finishConnection(.failure(TailcatError.closed))
        reader?.cancel(); timer?.cancel(); selectedTCPHandlers.removeAll()
        for (_, task) in admitting.values { task.cancel() }; admitting.removeAll()
        for task in handlerTasks.values { task.cancel() }; handlerTasks.removeAll()
        for listener in handlerUDP.values { await listener.close() }; handlerUDP.removeAll(); handlerTCP.removeAll()
        for target in targets.values { await target.close() }; targets.removeAll(); targetActivity.removeAll()
        await stack?.close(); await network.close(); peers.removeAll()
    }
    private func receive(_ packet: TransportPacket) async {
        guard !closed else { return }
        let data = packet.payload
        if data.starts(with: Data("meow".utf8)) {
            guard packet.viaRelay else { return }
            if server, data.count >= 69, data[4] == 1 {
                let node = Data(data[5..<37]); let disco = Data(data[37..<69])
                guard node == packet.source, disco.contains(where: { $0 != 0 }), let identity = try? NodePublicKey(rawValue: node) else { return }
                if let peer = peers[node] {
                    guard peer.disco == disco else { return }
                    try? await network.send(to: node, packet: Data("meow\u{02}".utf8)); return
                }
                guard admitting.count < 128, admitting[node] == nil, peers.count < 1024 else { return }
                let attempt = UUID()
                let task = Task { [weak self] in
                    guard let self else { return }; await self.admit(identity, disco: disco, attempt: attempt)
                }
                admitting[node] = (attempt, task)
            } else if !server, data.count >= 5, data[4] == 2, packet.source == address.serverPublicKey.rawValue {
                startupTrace?.record("meowAcknowledged")
                peers[packet.source]?.acknowledged = true
                try? await tickThrowing()
            }
            return
        }
        guard var peer = peers[packet.source] else { return }
        let previouslyAuthenticated = peer.authenticated
        do {
            let result = try peer.wireguard.receive(data)
            if result.handshakeCompleted { startupTrace?.record("wireGuardEstablished") }
            if WireGuard.packetType(data) == 4, peer.wireguard.isEstablished {
                peer.authenticated = true; peer.lastReceived = Date()
            }
            peers[packet.source] = peer
            if !server, peer.wireguard.isEstablished { finishConnection(.success(())) }
            if WireGuard.packetType(data) == 4, data.count == 32 {
                // WireGuard represents an authenticated empty keepalive as nil
                // plaintext. A 32-byte type-4 packet has no encrypted IP bytes.
                await observeTransportPacket(packet, allowFallback: previouslyAuthenticated && !result.handshakeCompleted)
            }
            if let response = result.response { try await network.send(to: packet.source, packet: response) }
            if result.handshakeCompleted {
                // An empty authenticated transport packet confirms responder key promotion.
                if result.response == nil { try await sendPayload(Data(), to: packet.source) }
                await network.allowDirect(to: packet.source)
                await flush(packet.source)
            }
            if let plaintext = result.plaintext, !plaintext.isEmpty {
                peers[packet.source]?.lastActivity = Date()
                guard plaintext.count >= 40, plaintext[0] >> 4 == 6,
                      let identity = try? NodePublicKey(rawValue: packet.source),
                      (!server || Data(plaintext[8..<24]) == identity.address) else { return }
                let length = 40 + Int(plaintext[4]) * 256 + Int(plaintext[5])
                guard length <= plaintext.count, length <= 1280 else { return }
                let ip = Data(plaintext.prefix(length))
                await observeTransportPacket(packet, allowFallback: false)
                if ip.count >= 60, ip[6] == 6 {
                    TransportDiagnostics.log("TCP receive server=\(server) relay=\(packet.viaRelay) flags=\(ip[53]) bytes=\(ip.count) seq=\(Array(ip[44..<48])) ack=\(Array(ip[48..<52]))")
                }
                if server { await deliverServerIP(ip) }
                else if Data(ip[24..<40]) == publicKey.address { await stack.receive(ip) }
            }
        } catch { TransportDiagnostics.log("WG reject server=\(server) relay=\(packet.viaRelay) bytes=\(data.count) error=\(error)") }
    }

    private func observeTransportPacket(_ packet: TransportPacket, allowFallback: Bool) async {
        // The caller has already authenticated this type-4 packet. These are
        // existing public WireGuard header fields, not a new wire message.
        let header = packet.payload
        guard header.count >= 16 else { return }
        let counter = header[8..<16].enumerated().reduce(UInt64(0)) { result, byte in
            result | (UInt64(byte.element) << (byte.offset * 8))
        }
        await network.observeAuthenticatedTransport(from: packet.source, viaRelay: packet.viaRelay,
                                                     receiver: Data(header[4..<8]), counter: counter,
                                                     allowFallback: allowFallback && counter > 0)
    }
    private func admit(_ identity: NodePublicKey, disco: Data, attempt: UUID) async {
        let node = identity.rawValue
        let allowed = await allowClient?(identity) ?? true
        guard admitting[node]?.0 == attempt else { return }
        admitting.removeValue(forKey: node)
        guard allowed, !closed, !Task.isCancelled, peers[node] == nil else { return }
        // Meow is intentionally public. Reserve bounded space for peers that have
        // yet to prove possession of the tunnel PSK, and replace their oldest entry.
        let pending = peers.filter { !$0.value.authenticated }
        if pending.count >= 128 || peers.count >= 1024 {
            guard let oldest = pending.min(by: { $0.value.admittedAt < $1.value.admittedAt })?.key else { return }
            peers.removeValue(forKey: oldest); await network.removePeer(nodeKey: oldest)
        }
        guard !closed, !Task.isCancelled, peers.count < 1024 else { return }
        do {
            peers[node] = Peer(wireguard: try newWireGuard(node), disco: disco, acknowledged: true)
            try await network.configurePeer(nodeKey: node, discoKey: disco, endpoints: [])
            guard !closed, peers[node] != nil else { return }
            try await network.send(to: node, packet: Data("meow\u{02}".utf8))
        } catch { peers.removeValue(forKey: node); await network.removePeer(nodeKey: node) }
    }
    private func sendIP(_ packet: Data) async throws {
        guard !closed, packet.count >= 40 else { throw TailcatError.closed }
        guard let identity = server ? peerKey(address: Data(packet[24..<40])) : address.serverPublicKey else { throw TailcatError.peerRejected }
        if server, targets[Data(packet[8..<24])] != nil { targetActivity[Data(packet[8..<24])] = Date() }
        let node = identity.rawValue
        guard var peer = peers[node] else { throw TailcatError.peerRejected }
        if peer.wireguard.isEstablished { try await sendPayload(packet, to: node) }
        else {
            guard peer.pendingBytes + packet.count <= 262_144 else { throw TailcatError.bufferFull }
            peer.pending.append(packet); peer.pendingBytes += packet.count; peers[node] = peer
            try await tickThrowing()
        }
    }
    private func deliverServerIP(_ ip: Data) async {
        let destination = Data(ip[24..<40])
        let local = destination == publicKey.address
        var proto = ip[6]; var offset = 40; var extensions = 0
        while [UInt8(0), 60, 43, 44].contains(proto) {
            guard offset + 8 <= ip.count, extensions < 8 else { return }; extensions += 1
            let next = ip[offset]
            if proto == 44 { guard ip[offset + 2] == 0, ip[offset + 3] == 0 else { return }; offset += 8 }
            else { offset += (Int(ip[offset + 1]) + 1) * 8 }
            proto = next
        }
        guard proto == 6 || proto == 17, offset + (proto == 6 ? 20 : 8) <= ip.count else { return }
        let port = UInt16(ip[offset + 2]) << 8 | UInt16(ip[offset + 3])
        guard port > 0, let endpoint = try? TailcatEndpoint(tunnelAddress: destination, port: port) else { return }
        let udp = proto == 17
        let handlerKey = HandlerKey(address: destination, port: port, udp: udp)
        let target: IPStack
        if local { target = stack }
        else {
            guard configuration.allowProxy?(endpoint) ?? true else { return }
            guard (udp ? configuration.onUDPForward != nil : configuration.onTCPForward != nil) else { return }
            if let existing = targets[destination] { target = existing }
            else {
                guard targets.count < 128 else { return }
                target = IPStack(address: destination) { [weak self] packet in
                    guard let self else { throw TailcatError.closed }; try await self.sendIP(packet)
                }
                targets[destination] = target
            }
            targetActivity[destination] = Date()
        }
        let alreadyBound = udp ? await target.hasUDPSocket(port: port) : await target.hasTCPListener(port: port)
        let automatic = udp ? handlerUDP[handlerKey] != nil : handlerTCP[handlerKey] != nil
        if local {
            let served = udp ? configuration.servedUDPPorts : configuration.servedTCPPorts
            if let served, !served.contains(port), !(alreadyBound && !automatic) { return }
        }
        if !udp, ip[offset + 13] & 0x17 == 0x02, !alreadyBound || automatic {
            let peer = Data(ip[8..<24]); let remotePort = UInt16(ip[offset]) << 8 | UInt16(ip[offset + 1])
            if !(await target.hasTCPFlow(peer: peer, localPort: port, remotePort: remotePort)) {
                let handler = local ? configuration.onTCP?(port) : configuration.onTCPForward?(endpoint)
                guard let handler, selectedTCPHandlers.count < 1024 else {
                    await target.rejectTCP(peer: peer, body: Data(ip.dropFirst(offset))); return
                }
                selectedTCPHandlers[HandlerFlowKey(address: destination, peer: peer, localPort: port, remotePort: remotePort)] = (handler, Date())
            }
        }
        if !alreadyBound, handlerTasks.count < 256 {
            if udp {
                if local ? configuration.onUDP != nil : configuration.onUDPForward != nil {
                    do {
                        let socket = try await target.udp(port: port, idleTimeout: nil)
                        let listener = TailcatUDPListener(socket: socket, idleTimeout: configuration.udpIdleTimeout)
                        handlerUDP[handlerKey] = listener
                        handlerTasks[handlerKey] = Task { [weak self] in
                            while !Task.isCancelled {
                                guard let flow = try? await listener.accept() else { return }
                                await self?.dispatchUDP(flow, destination: endpoint)
                            }
                        }
                    } catch { return }
                }
            } else if ip[offset + 13] & 0x17 == 0x02 {
                if local ? configuration.onTCP != nil : configuration.onTCPForward != nil {
                    do {
                        let listener = try await target.listen(port: port)
                        handlerTCP[handlerKey] = listener
                        handlerTasks[handlerKey] = Task { [weak self] in
                            while !Task.isCancelled {
                                guard let connection = try? await listener.accept() else { return }
                                await self?.dispatchTCP(connection)
                            }
                        }
                    } catch { return }
                }
            }
        }
        guard !closed else { return }
        await target.receive(ip)
    }
    private func dispatchTCP(_ connection: TailcatConnection) async {
        let key = HandlerFlowKey(address: connection.localAddress, peer: connection.remoteAddress, localPort: connection.localPort, remotePort: connection.remotePort)
        guard !closed, let (handler, _) = selectedTCPHandlers.removeValue(forKey: key) else { await connection.abort(); return }
        Task { await handler(connection) }
    }
    private func dispatchUDP(_ connection: TailcatUDPConnection, destination: TailcatEndpoint) async {
        let handler = destination.tunnelAddress == publicKey.address ? configuration.onUDP?(destination.port) : configuration.onUDPForward?(destination)
        guard !closed, let handler else { await connection.close(); return }
        Task { await handler(connection) }
    }
    private func makeRelayResetMarker(to node: Data) throws -> Data? {
        guard !closed, var peer = peers[node], peer.authenticated, peer.wireguard.isEstablished else { return nil }
        var encrypted = try peer.wireguard.encrypt(Data())
        if encrypted[8..<16].allSatisfy({ $0 == 0 }) {
            // Counter zero remains a key-confirmation packet, even if reset
            // preparation races the responder's first outbound confirmation.
            encrypted = try peer.wireguard.encrypt(Data())
        }
        peer.lastSend = Date(); peers[node] = peer
        return encrypted
    }

    private func sendPayload(_ packet: Data, to node: Data) async throws {
        guard var peer = peers[node] else { throw TailcatError.peerRejected }
        let encrypted = try peer.wireguard.encrypt(packet)
        peer.lastSend = Date()
        if !packet.isEmpty { peer.lastActivity = peer.lastSend }
        peers[node] = peer
        try await network.send(to: node, packet: encrypted)
    }
    private func flush(_ node: Data) async {
        guard var peer = peers[node], peer.wireguard.isEstablished else { return }
        let pending = peer.pending; peer.pending.removeAll(); peer.pendingBytes = 0; peers[node] = peer
        for packet in pending { try? await sendPayload(packet, to: node) }
    }
    private func tick() async { try? await tickThrowing() }
    private func tickThrowing() async throws {
        guard !closed else { throw TailcatError.closed }
        let now = Date()
        selectedTCPHandlers = selectedTCPHandlers.filter { now.timeIntervalSince($0.value.1) < 60 }
        for node in peers.filter({ !$0.value.authenticated && now.timeIntervalSince($0.value.admittedAt) >= 30 }).map(\.key) {
            peers.removeValue(forKey: node); await network.removePeer(nodeKey: node)
        }
        if server {
            for node in peers.filter({ $0.value.authenticated && now.timeIntervalSince($0.value.lastReceived) >= 300 }).map(\.key) {
                if let identity = try? NodePublicKey(rawValue: node) { await disconnect(identity) }
            }
        }
        for (destination, activity) in targetActivity where now.timeIntervalSince(activity) > max(300, configuration.udpIdleTimeout) {
            guard let target = targets[destination], await target.connectionCount == 0 else { continue }
            for handlerKey in Array(handlerTasks.keys) where handlerKey.address == destination {
                handlerTasks.removeValue(forKey: handlerKey)?.cancel()
                await handlerTCP.removeValue(forKey: handlerKey)?.close()
                await handlerUDP.removeValue(forKey: handlerKey)?.close()
            }
            await target.close(); targets.removeValue(forKey: destination); targetActivity.removeValue(forKey: destination)
        }
        if !server, peers[address.serverPublicKey.rawValue]?.acknowledged == false {
            var peer = peers[address.serverPublicKey.rawValue]!
            if now.timeIntervalSince(peer.lastMeow) >= 1 {
                peer.lastMeow = now; peers[address.serverPublicKey.rawValue] = peer
                let meow = Data("meow\u{01}".utf8) + publicKey.rawValue + (try key.discoPublicKey)
                startupTrace?.record("meowSendStarted")
                try await network.send(to: address.serverPublicKey.rawValue, packet: meow)
                startupTrace?.record("meowWritten")
            }
        }
        for node in Array(peers.keys) {
            guard var peer = peers[node], peer.acknowledged else { continue }
            // An idle client rekeys and keeps alive only at the shared marks: a
            // session is never older than 150 s there, inside WireGuard's 180.
            let idle = !server && now.timeIntervalSince(peer.lastActivity) >= Self.idleAfter
            let due = !idle || IdleGrid.atMark()
            do {
            if (!peer.wireguard.isEstablished || (peer.wireguard.needsRekey(now: now) && due)), now.timeIntervalSince(peer.lastHandshake) >= 5 {
                // Clients initiate the first handshake. Either endpoint may rekey established sessions.
                if server && !peer.wireguard.isEstablished { continue }
                let handshake = try peer.wireguard.initiateHandshake(now: now)
                peer.lastHandshake = now; peers[node] = peer
                startupTrace?.record("wireGuardInitiationSendStarted")
                try await network.send(to: node, packet: handshake)
            } else if peer.wireguard.isEstablished, due, now.timeIntervalSince(peer.lastSend) >= (idle ? Self.idleKeepalive : 25) { try await sendPayload(Data(), to: node) }
            } catch { if !server { throw error } }
        }
    }
}