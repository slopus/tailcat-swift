// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation

/// A bounded IPv6 TCP/UDP stack. All transport state is isolated on this actor;
/// the supplied packet writer is the only interface to the encrypted tunnel.
internal actor IPStack {
    private struct FlowKey: Hashable {
        let peer: Data
        let localPort: UInt16
        let remotePort: UInt16
    }

    private struct ReadWaiter {
        let id: UUID
        let maximum: Int
        let continuation: CheckedContinuation<Data, Error>
    }

    private struct WriteWaiter {
        let id: UUID
        let data: Data
        var offset = 0
        var end: UInt32?
        let continuation: CheckedContinuation<Void, Error>
    }

    private struct Segment {
        let sequence: UInt32
        let flags: UInt8
        let payload: Data
        var sent: TimeInterval
        var retries = 0
        var end: UInt32 {
            sequence &+ UInt32(payload.count) &+ ((flags & 0x03) != 0 ? 1 : 0)
        }
    }

    private struct Incoming {
        let sequence: UInt32
        let payload: Data
        let fin: Bool
    }

    private final class TCPState {
        enum Phase { case synSent, synReceived, established }
        let id = UUID()
        let key: FlowKey
        var phase: Phase
        let listener: UUID?
        var connect: CheckedContinuation<TailcatConnection, Error>?
        var sendUnacknowledged: UInt32
        var sendNext: UInt32
        var receiveNext: UInt32 = 0
        var remoteWindow: UInt32 = 65_535
        var windowSequence: UInt32 = 0
        var windowAck: UInt32 = 0
        var mss = 1220
        var congestionWindow = 4880
        var slowStartThreshold = 65_535
        var duplicateACKs = 0
        var retransmitDelay: TimeInterval = 0.5
        var segments: [Segment] = []
        var incoming: [Incoming] = []
        var buffer = Data()
        var reads: [ReadWaiter] = []
        var writes: [WriteWaiter] = []
        var drains: [(UUID, Set<UUID>, CheckedContinuation<Void, Error>)] = []
        var closeWaiters: [(UUID, CheckedContinuation<Void, Error>)] = []
        var writeClosed = false
        var applicationClosedAt: TimeInterval?
        var finSequence: UInt32?
        var finAcknowledged = false
        var readEOF = false
        var lastActivity = ProcessInfo.processInfo.systemUptime
        var persistSent: TimeInterval = 0
        var finishedAt: TimeInterval?

        init(key: FlowKey, phase: Phase, sequence: UInt32, listener: UUID? = nil) {
            self.key = key
            self.phase = phase
            self.sendUnacknowledged = sequence
            self.sendNext = sequence
            self.listener = listener
        }
    }

    private final class ListenerState {
        let id = UUID()
        let port: UInt16
        var pending: [UUID] = []
        var waiters: [(UUID, CheckedContinuation<TailcatConnection, Error>)] = []
        init(port: UInt16) { self.port = port }
    }

    private final class UDPState {
        let id = UUID()
        let port: UInt16
        let idleTimeout: TimeInterval?
        var pending: [TailcatDatagram] = []
        var waiters: [(UUID, CheckedContinuation<TailcatDatagram, Error>)] = []
        var activity = ProcessInfo.processInfo.systemUptime
        init(port: UInt16, idleTimeout: TimeInterval?) {
            self.port = port
            self.idleTimeout = idleTimeout
        }
    }

    private let address: Data
    private let sendPacket: @Sendable (Data) async throws -> Void
    private var connections: [UUID: TCPState] = [:]
    private var flows: [FlowKey: UUID] = [:]
    private var listeners: [UUID: ListenerState] = [:]
    private var listenPorts: [UInt16: UUID] = [:]
    private var udpSockets: [UUID: UDPState] = [:]
    private var udpPorts: [UInt16: UUID] = [:]
    private var terminalErrors: [UUID: Error] = [:]
    private var terminalOrder: [UUID] = []
    private var nextPort: UInt16 = UInt16.random(in: 49_152...65_535)
    private var closed = false
    private var timer: Task<Void, Never>?
    private var output: [Data] = []
    private var outputRunning = false
    private let receiveCapacity = 65_535

    internal init(address: Data, send: @escaping @Sendable (Data) async throws -> Void) {
        self.address = address
        self.sendPacket = send
    }

    deinit { timer?.cancel() }

    internal func connect(peer: Data, port: UInt16) async throws -> TailcatConnection {
        try validate(peer: peer, port: port)
        try Task.checkCancellation()
        guard connections.count < 1024 else { throw TailcatTransportError.resourceLimit }
        let local = try allocatePort(udp: false)
        let state = TCPState(key: FlowKey(peer: peer, localPort: local, remotePort: port),
                             phase: .synSent, sequence: UInt32.random(in: .min ... .max))
        connections[state.id] = state
        flows[state.key] = state.id
        startTimer()
        let id = state.id
        return try await withTaskCancellationHandler {
            return try await withCheckedThrowingContinuation { continuation in
                state.connect = continuation
                transmit(state, flags: 0x02)
            }
        } onCancel: {
            Task { await self.cancelConnection(id) }
        }
    }

    internal func listen(port: UInt16) throws -> TailcatListener {
        try validate(peer: address, port: port)
        guard listenPorts[port] == nil else { throw TailcatTransportError.addressInUse }
        let state = ListenerState(port: port)
        listeners[state.id] = state
        listenPorts[port] = state.id
        return TailcatListener(stack: self, id: state.id, port: port, localAddress: address)
    }

    internal func hasTCPListener(port: UInt16) -> Bool { listenPorts[port] != nil }

    internal func hasTCPFlow(peer: Data, localPort: UInt16, remotePort: UInt16) -> Bool {
        flows[FlowKey(peer: peer, localPort: localPort, remotePort: remotePort)] != nil
    }

    internal func hasUDPSocket(port: UInt16) -> Bool { udpPorts[port] != nil }

    /// Includes closing and TIME-WAIT flows, so callers cannot expire a stack
    /// while it still owes a peer retransmission or a final acknowledgement.
    internal var connectionCount: Int { connections.count }

    internal func udp(port: UInt16 = 0, idleTimeout: TimeInterval? = 120) throws -> TailcatUDPSocket {
        guard !closed else { throw TailcatTransportError.closed }
        guard address.count == 16 else { throw TailcatTransportError.invalidAddress }
        if let timeout = idleTimeout, !timeout.isFinite || timeout <= 0 {
            throw TailcatTransportError.invalidTimeout
        }
        let bound = port == 0 ? try allocatePort(udp: true) : port
        guard udpPorts[bound] == nil else { throw TailcatTransportError.addressInUse }
        let state = UDPState(port: bound, idleTimeout: idleTimeout)
        udpSockets[state.id] = state
        udpPorts[bound] = state.id
        startTimer()
        return TailcatUDPSocket(stack: self, id: state.id, port: bound)
    }

    internal func close() {
        closed = true
        timer?.cancel()
        timer = nil
        for id in Array(connections.keys) { fail(id, error: TailcatTransportError.closed, reset: true) }
        for id in Array(listeners.keys) { closeListener(id) }
        for id in Array(udpSockets.keys) { closeUDP(id) }
    }

    internal func disconnect(peer: Data) {
        // Drop queued application packets before enqueueing TCP resets.
        output.removeAll { $0.count >= 40 && Data($0[24..<40]) == peer }
        let ids = connections.values.filter { $0.key.peer == peer }.map(\.id)
        for id in ids { fail(id, error: TailcatTransportError.closed, reset: true) }
        for state in udpSockets.values { state.pending.removeAll { $0.peer == peer } }
    }

    private func validate(peer: Data, port: UInt16) throws {
        guard !closed else { throw TailcatTransportError.closed }
        guard address.count == 16, peer.count == 16 else { throw TailcatTransportError.invalidAddress }
        guard port != 0 else { throw TailcatTransportError.invalidPort }
    }

    private func connection(_ state: TCPState) -> TailcatConnection {
        TailcatConnection(stack: self, id: state.id, localAddress: address,
                          remoteAddress: state.key.peer, localPort: state.key.localPort,
                          remotePort: state.key.remotePort)
    }

    private func allocatePort(udp: Bool) throws -> UInt16 {
        for _ in 0..<16_384 {
            let port = nextPort
            nextPort = nextPort == 65_535 ? 49_152 : nextPort + 1
            if udp {
                if udpPorts[port] == nil { return port }
            } else if listenPorts[port] == nil && !flows.keys.contains(where: { $0.localPort == port }) {
                return port
            }
        }
        throw TailcatTransportError.addressInUse
    }

    private func startTimer() {
        guard timer == nil else { return }
        timer = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: 100_000_000) } catch { return }
                await self?.tick()
            }
        }
    }

    private func emit(_ packet: Data) {
        // TCP's send window bounds ordinary output; the hard cap also bounds
        // responses to unauthenticated/unconsumed traffic while a link stalls.
        guard output.count < 1024 else { return }
        output.append(packet)
        if !outputRunning {
            outputRunning = true
            Task { await self.drainOutput() }
        }
    }

    private func drainOutput() async {
        while !output.isEmpty {
            let packet = output.removeFirst()
            // TCP retransmission handles transient tunnel send failures.
            try? await sendPacket(packet)
        }
        outputRunning = false
    }

    internal func receive(_ packet: Data) {
        guard !closed, packet.count >= 40 else { return }
        let bytes = [UInt8](packet)
        guard bytes[0] >> 4 == 6, Data(bytes[24..<40]) == address else { return }
        let length = Int(Self.u16(bytes, 4))
        guard length > 0, bytes.count >= 40 + length else { return }
        let peer = Data(bytes[8..<24])
        // Multicast and unspecified source addresses cannot identify a flow.
        guard peer.contains(where: { $0 != 0 }), peer.first != 0xff else { return }
        var proto = bytes[6]
        var offset = 40
        let end = 40 + length
        var extensions = 0
        while proto == 0 || proto == 60 || proto == 43 || proto == 44 {
            extensions += 1
            guard extensions <= 8, offset + 8 <= end else { return }
            let next = bytes[offset]
            if proto == 44 {
                // Only atomic fragments: reassembly is intentionally excluded
                // by the 1280-byte tunnel MTU and advertised TCP MSS.
                guard Self.u16(bytes, offset + 2) == 0 else { return }
                offset += 8
            } else {
                if proto == 43 && bytes[offset + 3] != 0 { return }
                offset += (Int(bytes[offset + 1]) + 1) * 8
            }
            guard offset <= end else { return }
            proto = next
        }
        let body = Array(bytes[offset..<end])
        guard Self.checksum(source: peer, destination: address, proto: proto, body: body) == 0 else { return }
        if proto == 6 { receiveTCP(peer: peer, body: body) }
        if proto == 17 { receiveUDP(peer: peer, body: body) }
    }

    private func receiveTCP(peer: Data, body: [UInt8]) {
        guard body.count >= 20 else { return }
        let headerLength = Int(body[12] >> 4) * 4
        guard headerLength >= 20, headerLength <= body.count else { return }
        let key = FlowKey(peer: peer, localPort: Self.u16(body, 2), remotePort: Self.u16(body, 0))
        guard key.localPort != 0, key.remotePort != 0 else { return }
        let sequence = Self.u32(body, 4)
        let acknowledgement = Self.u32(body, 8)
        let flags = body[13]
        let payload = Data(body[headerLength...])
        guard let id = flows[key], let state = connections[id] else {
            if flags & 0x17 == 0x02, let listenerID = listenPorts[key.localPort],
               let listener = listeners[listenerID], listener.pending.count < 128,
               connections.count < 1024,
               connections.values.filter({ $0.listener == listenerID }).count < 256 {
                let state = TCPState(key: key, phase: .synReceived,
                                     sequence: UInt32.random(in: .min ... .max), listener: listenerID)
                state.receiveNext = sequence &+ 1
                state.windowSequence = sequence
                state.remoteWindow = UInt32(Self.u16(body, 14))
                state.mss = parseMSS(body, headerLength: headerLength)
                connections[state.id] = state
                flows[key] = state.id
                startTimer()
                transmit(state, flags: 0x12)
            } else {
                reset(key, sequence: sequence, acknowledgement: acknowledgement,
                      flags: flags, payloadLength: payload.count)
            }
            return
        }
        state.lastActivity = ProcessInfo.processInfo.systemUptime
        if state.phase == .synSent {
            guard flags & 0x10 != 0, acknowledgement == state.sendNext else { return }
            if flags & 0x04 != 0 { fail(id, error: TailcatTransportError.connectionRefused); return }
            guard flags & 0x02 != 0 else { return }
            state.receiveNext = sequence &+ 1
            state.remoteWindow = UInt32(Self.u16(body, 14))
            state.windowSequence = sequence
            state.windowAck = acknowledgement
            state.mss = parseMSS(body, headerLength: headerLength)
            state.phase = .established
            acknowledge(state, acknowledgement)
            sendACK(state)
            let continuation = state.connect
            state.connect = nil
            continuation?.resume(returning: connection(state))
            return
        }
        if flags & 0x04 != 0 {
            // RFC 5961: only an exact in-window RST can terminate a stream.
            if sequence == state.receiveNext { fail(id, error: TailcatTransportError.connectionReset) }
            else { sendACK(state) }
            return
        }
        if state.phase == .synReceived && flags & 0x02 != 0 && sequence &+ 1 == state.receiveNext {
            if let syn = state.segments.first { retransmit(state, syn) }
            return
        }
        // Duplicate SYN+ACK after our final handshake ACK was lost.
        if flags & 0x02 != 0 {
            sendACK(state)
            return
        }
        guard flags & 0x10 != 0 else { return }
        let available = UInt32(receiveWindow(state))
        let segmentLength = UInt32(payload.count) &+ (flags & 1 != 0 ? 1 : 0)
        let intersects = sequence == state.receiveNext ||
            (available > 0 && (Self.before(sequence, state.receiveNext &+ available) &&
             !Self.before(sequence &+ segmentLength, state.receiveNext)))
        guard intersects else { sendACK(state); return }
        guard !Self.before(state.sendNext, acknowledgement) else { sendACK(state); return }
        if state.phase == .synReceived {
            guard acknowledgement == state.sendNext else { return }
            state.phase = .established
            if let listenerID = state.listener, let listener = listeners[listenerID] {
                if !listener.waiters.isEmpty {
                    listener.waiters.removeFirst().1.resume(returning: connection(state))
                } else { listener.pending.append(id) }
            } else { fail(id, error: TailcatTransportError.closed, reset: true); return }
        }
        let oldWindow = state.remoteWindow
        if Self.before(state.windowSequence, sequence) ||
            (state.windowSequence == sequence && !Self.before(acknowledgement, state.windowAck)) {
            state.remoteWindow = UInt32(Self.u16(body, 14))
            state.windowSequence = sequence
            state.windowAck = acknowledgement
        }
        if acknowledgement == state.sendUnacknowledged && payload.isEmpty && flags & 1 == 0 &&
            oldWindow == state.remoteWindow && !state.segments.isEmpty {
            state.duplicateACKs += 1
            if state.duplicateACKs == 3, let first = state.segments.first {
                state.slowStartThreshold = max(state.mss * 2, state.congestionWindow / 2)
                state.congestionWindow = state.slowStartThreshold
                retransmit(state, first)
            }
        } else if Self.before(state.sendUnacknowledged, acknowledgement) {
            acknowledge(state, acknowledgement)
        }
        if !payload.isEmpty || flags & 1 != 0 {
            ingest(state, sequence: sequence, payload: payload, fin: flags & 1 != 0)
            sendACK(state)
        }
        flush(state)
    }

    /// Rejects a transport segment before it enters a listening endpoint.
    /// The caller supplies the IPv6 payload, with extension headers removed.
    internal func rejectTCP(peer: Data, body: Data) {
        guard !closed, address.count == 16, peer.count == 16,
              peer.contains(where: { $0 != 0 }), peer.first != 0xff,
              body.count >= 20, body.count <= 65_535 else { return }
        let bytes = [UInt8](body)
        let headerLength = Int(bytes[12] >> 4) * 4
        guard headerLength >= 20, headerLength <= bytes.count,
              Self.checksum(source: peer, destination: address, proto: 6, body: bytes) == 0 else { return }
        let key = FlowKey(peer: peer, localPort: Self.u16(bytes, 2), remotePort: Self.u16(bytes, 0))
        guard key.localPort != 0, key.remotePort != 0 else { return }
        reset(key, sequence: Self.u32(bytes, 4), acknowledgement: Self.u32(bytes, 8),
              flags: bytes[13], payloadLength: bytes.count - headerLength)
    }

    private func reset(_ key: FlowKey, sequence: UInt32, acknowledgement: UInt32,
                       flags: UInt8, payloadLength: Int) {
        guard flags & 0x04 == 0 else { return }
        if flags & 0x10 != 0 {
            emit(tcpPacket(key, sequence: acknowledgement, ack: 0, flags: 0x04, window: 0))
        } else {
            let consumed = UInt32(payloadLength) &+ (flags & 0x02 != 0 ? 1 : 0) &+ (flags & 0x01 != 0 ? 1 : 0)
            emit(tcpPacket(key, sequence: 0, ack: sequence &+ consumed, flags: 0x14, window: 0))
        }
    }

    private func parseMSS(_ body: [UInt8], headerLength: Int) -> Int {
        var offset = 20
        var result = 1220
        while offset < headerLength {
            let kind = body[offset]
            if kind == 0 { break }
            if kind == 1 { offset += 1; continue }
            guard offset + 1 < headerLength else { break }
            let length = Int(body[offset + 1])
            guard length >= 2, offset + length <= headerLength else { break }
            if kind == 2 && length == 4 { result = min(1220, max(1, Int(Self.u16(body, offset + 2)))) }
            offset += length
        }
        return result
    }

    private func acknowledge(_ state: TCPState, _ ack: UInt32) {
        guard !Self.before(ack, state.sendUnacknowledged), !Self.before(state.sendNext, ack) else { return }
        let advanced = Int(ack &- state.sendUnacknowledged)
        state.sendUnacknowledged = ack
        state.duplicateACKs = 0
        state.retransmitDelay = 0.5
        state.segments.removeAll { !Self.before(ack, $0.end) }
        if let first = state.segments.first, Self.before(first.sequence, ack), !first.payload.isEmpty {
            let count = Int(ack &- first.sequence)
            if count < first.payload.count {
                state.segments[0] = Segment(sequence: ack, flags: first.flags,
                    payload: Data(first.payload.dropFirst(count)), sent: first.sent, retries: first.retries)
            }
        }
        if advanced > 0 {
            let increment = state.congestionWindow < state.slowStartThreshold ? min(advanced, state.mss) :
                max(1, state.mss * min(advanced, state.mss) / max(1, state.congestionWindow))
            state.congestionWindow = min(65_535, state.congestionWindow + increment)
        }
        while let first = state.writes.first, let end = first.end, !Self.before(ack, end) {
            state.writes.removeFirst().continuation.resume()
        }
        let outstanding = Set(state.writes.map(\.id))
        let completedDrains = state.drains.filter { $0.1.isDisjoint(with: outstanding) }
        state.drains.removeAll { $0.1.isDisjoint(with: outstanding) }
        for (_, _, continuation) in completedDrains { continuation.resume() }
        if let fin = state.finSequence, Self.before(fin, ack) {
            state.finAcknowledged = true
            let waiters = state.closeWaiters
            state.closeWaiters.removeAll()
            for (_, continuation) in waiters { continuation.resume() }
            if state.readEOF { state.finishedAt = ProcessInfo.processInfo.systemUptime }
        }
    }

    private func receiveWindow(_ state: TCPState) -> UInt16 {
        let used = state.buffer.count + state.incoming.reduce(0) { $0 + $1.payload.count }
        return UInt16(max(0, receiveCapacity - used))
    }

    private func ingest(_ state: TCPState, sequence: UInt32, payload: Data, fin: Bool) {
        guard !state.readEOF else { return }
        var seq = sequence
        var data = payload
        if Self.before(seq, state.receiveNext) {
            let skip = Int(state.receiveNext &- seq)
            guard skip <= data.count else { return }
            data = Data(data.dropFirst(skip))
            seq = state.receiveNext
        }
        let distance = Int(seq &- state.receiveNext)
        let capacity = Int(receiveWindow(state))
        guard distance <= capacity else { return }
        let accepted = min(data.count, max(0, capacity - distance))
        let acceptedFIN = fin && accepted == data.count && distance + accepted < capacity
        data = Data(data.prefix(accepted))
        if seq == state.receiveNext {
            if state.applicationClosedAt == nil { state.buffer.append(data) }
            state.receiveNext &+= UInt32(data.count)
            if acceptedFIN { state.readEOF = true; state.receiveNext &+= 1 }
        } else if !data.isEmpty || acceptedFIN {
            if !state.incoming.contains(where: { $0.sequence == seq && $0.payload.count >= data.count }) && state.incoming.count < 256 {
                state.incoming.append(Incoming(sequence: seq, payload: data, fin: acceptedFIN))
            }
        }
        state.incoming.sort { Self.before($0.sequence, $1.sequence) }
        while let first = state.incoming.first, !Self.before(state.receiveNext, first.sequence), !state.readEOF {
            state.incoming.removeFirst()
            let skip = Int(state.receiveNext &- first.sequence)
            if skip <= first.payload.count {
                let tail = first.payload.dropFirst(skip)
                if state.applicationClosedAt == nil { state.buffer.append(tail) }
                state.receiveNext &+= UInt32(tail.count)
                if first.fin { state.readEOF = true; state.receiveNext &+= 1 }
            }
        }
        if state.readEOF {
            state.incoming.removeAll()
            if state.finAcknowledged { state.finishedAt = ProcessInfo.processInfo.systemUptime }
        }
        satisfyReads(state)
    }

    private func satisfyReads(_ state: TCPState) {
        while !state.reads.isEmpty && (!state.buffer.isEmpty || state.readEOF) {
            let waiter = state.reads.removeFirst()
            let result = Data(state.buffer.prefix(waiter.maximum))
            state.buffer.removeFirst(result.count)
            waiter.continuation.resume(returning: result)
        }
    }

    private func transmit(_ state: TCPState, flags: UInt8, payload: Data = Data()) {
        let segment = Segment(sequence: state.sendNext, flags: flags, payload: payload,
                              sent: ProcessInfo.processInfo.systemUptime)
        state.sendNext = segment.end
        state.segments.append(segment)
        retransmit(state, segment)
    }

    private func retransmit(_ state: TCPState, _ segment: Segment) {
        emit(tcpPacket(state.key, sequence: segment.sequence, ack: state.receiveNext,
                       flags: segment.flags, window: receiveWindow(state), payload: segment.payload))
    }

    private func sendACK(_ state: TCPState) {
        emit(tcpPacket(state.key, sequence: state.sendNext, ack: state.receiveNext,
                       flags: 0x10, window: receiveWindow(state)))
    }

    private func flush(_ state: TCPState) {
        guard state.phase == .established else { return }
        for index in state.writes.indices {
            while state.writes[index].offset < state.writes[index].data.count {
                let inFlight = Int(state.sendNext &- state.sendUnacknowledged)
                let allowed = min(Int(state.remoteWindow), state.congestionWindow) - inFlight
                guard allowed > 0 else { return }
                let offset = state.writes[index].offset
                let count = min(state.mss, allowed, state.writes[index].data.count - offset)
                let bytes = state.writes[index].data.subdata(in: offset..<(offset + count))
                state.writes[index].offset += count
                transmit(state, flags: 0x18, payload: bytes)
            }
            if state.writes[index].end == nil { state.writes[index].end = state.sendNext }
        }
        if state.writeClosed && state.finSequence == nil && state.remoteWindow > state.sendNext &- state.sendUnacknowledged {
            state.finSequence = state.sendNext
            transmit(state, flags: 0x11)
        }
    }

    internal func read(_ id: UUID, maximumBytes: Int) async throws -> Data {
        guard maximumBytes > 0 else { throw TailcatTransportError.invalidReadSize }
        guard let state = connections[id] else { throw terminalErrors[id] ?? TailcatTransportError.closed }
        guard state.applicationClosedAt == nil else { throw TailcatTransportError.closed }
        let waiterID = UUID()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                state.reads.append(ReadWaiter(id: waiterID, maximum: maximumBytes, continuation: continuation))
                let previous = receiveWindow(state)
                satisfyReads(state)
                if receiveWindow(state) > previous { sendACK(state) }
            }
        } onCancel: { Task { await self.cancelRead(id, waiter: waiterID) } }
    }

    internal func write(_ id: UUID, data: Data) async throws {
        guard let state = connections[id] else { throw terminalErrors[id] ?? TailcatTransportError.closed }
        guard !state.writeClosed else { throw TailcatTransportError.closed }
        if data.isEmpty { return }
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                state.writes.append(WriteWaiter(id: waiterID, data: Data(data), continuation: continuation))
                flush(state)
            }
        } onCancel: { Task { await self.cancelWrite(id, waiter: waiterID) } }
    }

    internal func closeWrite(_ id: UUID) async throws {
        guard let state = connections[id] else { throw terminalErrors[id] ?? TailcatTransportError.closed }
        guard state.applicationClosedAt == nil else { throw TailcatTransportError.closed }
        if state.finAcknowledged { return }
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                state.writeClosed = true
                state.closeWaiters.append((waiterID, continuation))
                flush(state)
            }
        } onCancel: { Task { await self.cancelCloseWrite(id, waiter: waiterID) } }
    }

    internal func drain(_ id: UUID) async throws {
        guard let state = connections[id] else { throw terminalErrors[id] ?? TailcatTransportError.closed }
        guard state.applicationClosedAt == nil else { throw TailcatTransportError.closed }
        try Task.checkCancellation()
        let outstanding = Set(state.writes.map(\.id))
        guard !outstanding.isEmpty else { return }
        let waiterID = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                state.drains.append((waiterID, outstanding, continuation))
            }
        } onCancel: { Task { await self.cancelDrain(id, waiter: waiterID) } }
    }

    private func cancelDrain(_ id: UUID, waiter: UUID) {
        guard let state = connections[id], let index = state.drains.firstIndex(where: { $0.0 == waiter }) else { return }
        state.drains.remove(at: index).2.resume(throwing: CancellationError())
    }

    internal func closeConnection(_ id: UUID) {
        guard let state = connections[id], state.applicationClosedAt == nil else { return }
        state.applicationClosedAt = ProcessInfo.processInfo.systemUptime
        state.writeClosed = true
        state.buffer.removeAll()
        let reads = state.reads
        state.reads.removeAll()
        for waiter in reads { waiter.continuation.resume(throwing: TailcatTransportError.closed) }
        sendACK(state)
        flush(state)
    }

    internal func abortConnection(_ id: UUID) {
        fail(id, error: TailcatTransportError.closed, reset: true)
    }

    private func cancelConnection(_ id: UUID) { fail(id, error: CancellationError(), reset: true) }

    private func cancelRead(_ id: UUID, waiter: UUID) {
        guard let state = connections[id], let index = state.reads.firstIndex(where: { $0.id == waiter }) else { return }
        state.reads.remove(at: index).continuation.resume(throwing: CancellationError())
    }

    private func cancelWrite(_ id: UUID, waiter: UUID) {
        guard connections[id]?.writes.contains(where: { $0.id == waiter }) == true else { return }
        fail(id, error: CancellationError(), reset: true)
    }

    private func cancelCloseWrite(_ id: UUID, waiter: UUID) {
        guard let state = connections[id], let index = state.closeWaiters.firstIndex(where: { $0.0 == waiter }) else { return }
        state.closeWaiters.remove(at: index).1.resume(throwing: CancellationError())
    }

    private func fail(_ id: UUID, error: Error, reset: Bool = false) {
        guard let state = connections.removeValue(forKey: id) else { return }
        rememberError(id, error: error)
        flows.removeValue(forKey: state.key)
        if reset && !(state.readEOF && state.finAcknowledged) {
            emit(tcpPacket(state.key, sequence: state.sendNext, ack: state.receiveNext, flags: 0x14, window: 0))
        }
        if let listenerID = state.listener { listeners[listenerID]?.pending.removeAll { $0 == id } }
        state.connect?.resume(throwing: error)
        state.connect = nil
        for waiter in state.reads { waiter.continuation.resume(throwing: error) }
        for waiter in state.writes { waiter.continuation.resume(throwing: error) }
        for (_, _, continuation) in state.drains { continuation.resume(throwing: error) }
        for (_, continuation) in state.closeWaiters { continuation.resume(throwing: error) }
    }

    private func rememberError(_ id: UUID, error: Error) {
        terminalErrors[id] = error
        terminalOrder.append(id)
        if terminalOrder.count > 1024 { terminalErrors.removeValue(forKey: terminalOrder.removeFirst()) }
    }

    internal func accept(_ id: UUID) async throws -> TailcatConnection {
        guard let state = listeners[id] else { throw TailcatTransportError.closed }
        if !state.pending.isEmpty {
            let pending = state.pending.removeFirst()
            guard let accepted = connections[pending] else { throw TailcatTransportError.closed }
            return connection(accepted)
        }
        let waiterID = UUID()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { state.waiters.append((waiterID, $0)) }
        } onCancel: { Task { await self.cancelAccept(id, waiter: waiterID) } }
    }

    private func cancelAccept(_ id: UUID, waiter: UUID) {
        guard let state = listeners[id], let index = state.waiters.firstIndex(where: { $0.0 == waiter }) else { return }
        state.waiters.remove(at: index).1.resume(throwing: CancellationError())
    }

    internal func closeListener(_ id: UUID) {
        guard let state = listeners.removeValue(forKey: id) else { return }
        listenPorts.removeValue(forKey: state.port)
        for (_, continuation) in state.waiters { continuation.resume(throwing: TailcatTransportError.closed) }
        let unfinished = connections.values.filter { $0.listener == id && ($0.phase != .established || state.pending.contains($0.id)) }.map(\.id)
        for connection in unfinished { fail(connection, error: TailcatTransportError.closed, reset: true) }
    }

    internal func sendUDP(_ id: UUID, data: Data, peer: Data, port: UInt16) async throws {
        try validate(peer: peer, port: port)
        guard let state = udpSockets[id] else { throw terminalErrors[id] ?? TailcatTransportError.closed }
        guard data.count <= 1232 else { throw TailcatTransportError.datagramTooLarge }
        try Task.checkCancellation()
        var body = [UInt8](repeating: 0, count: 8)
        Self.put16(&body, 0, state.port)
        Self.put16(&body, 2, port)
        Self.put16(&body, 4, UInt16(8 + data.count))
        body.append(contentsOf: data)
        let sum = Self.checksum(source: address, destination: peer, proto: 17, body: body)
        Self.put16(&body, 6, sum == 0 ? 0xffff : sum)
        state.activity = ProcessInfo.processInfo.systemUptime
        try await sendPacket(ipv6(peer: peer, proto: 17, body: body))
    }

    private func receiveUDP(peer: Data, body: [UInt8]) {
        guard body.count >= 8, body.count <= 1240, Self.u16(body, 4) == body.count,
              Self.u16(body, 6) != 0, Self.u16(body, 0) != 0,
              let id = udpPorts[Self.u16(body, 2)], let state = udpSockets[id] else { return }
        state.activity = ProcessInfo.processInfo.systemUptime
        let datagram = TailcatDatagram(data: Data(body.dropFirst(8)), peer: peer, port: Self.u16(body, 0))
        if !state.waiters.isEmpty { state.waiters.removeFirst().1.resume(returning: datagram) }
        else if state.pending.count < 128 { state.pending.append(datagram) }
    }

    internal func receiveUDP(_ id: UUID) async throws -> TailcatDatagram {
        guard let state = udpSockets[id] else { throw terminalErrors[id] ?? TailcatTransportError.closed }
        if !state.pending.isEmpty { return state.pending.removeFirst() }
        let waiterID = UUID()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { state.waiters.append((waiterID, $0)) }
        } onCancel: { Task { await self.cancelUDPReceive(id, waiter: waiterID) } }
    }

    private func cancelUDPReceive(_ id: UUID, waiter: UUID) {
        guard let state = udpSockets[id], let index = state.waiters.firstIndex(where: { $0.0 == waiter }) else { return }
        state.waiters.remove(at: index).1.resume(throwing: CancellationError())
    }

    internal func closeUDP(_ id: UUID) { closeUDP(id, error: TailcatTransportError.closed) }

    private func closeUDP(_ id: UUID, error: Error) {
        guard let state = udpSockets.removeValue(forKey: id) else { return }
        rememberError(id, error: error)
        udpPorts.removeValue(forKey: state.port)
        for (_, continuation) in state.waiters { continuation.resume(throwing: error) }
    }

    private func tick() {
        let now = ProcessInfo.processInfo.systemUptime
        for state in Array(connections.values) {
            if let finished = state.finishedAt {
                // Retain receive buffers and TIME-WAIT state for late FINs.
                if now - finished > 120 && state.buffer.isEmpty {
                    fail(state.id, error: TailcatTransportError.closed)
                }
                continue
            }
            if let closedAt = state.applicationClosedAt, now - closedAt > 120 {
                fail(state.id, error: TailcatTransportError.closed, reset: true)
                continue
            }
            if let first = state.segments.first, now - first.sent >= state.retransmitDelay {
                if first.retries >= 8 { fail(state.id, error: TailcatTransportError.timedOut); continue }
                state.slowStartThreshold = max(state.mss * 2, state.congestionWindow / 2)
                state.congestionWindow = state.mss
                state.retransmitDelay = min(8, state.retransmitDelay * 2)
                state.segments[0].sent = now
                state.segments[0].retries += 1
                retransmit(state, state.segments[0])
            }
            if state.remoteWindow == 0 && (!state.writes.isEmpty || state.writeClosed) && now - state.persistSent >= 1 {
                state.persistSent = now
                // A sequence one byte before SND.NXT elicits the current window
                // without advancing the stream or consuming unsent application data.
                emit(tcpPacket(state.key, sequence: state.sendNext &- 1, ack: state.receiveNext,
                               flags: 0x10, window: receiveWindow(state)))
                if now - state.lastActivity > 120 { fail(state.id, error: TailcatTransportError.timedOut) }
            }
        }
        for state in Array(udpSockets.values) {
            if let timeout = state.idleTimeout, now - state.activity >= timeout {
                closeUDP(state.id, error: TailcatTransportError.timedOut)
            }
        }
    }

    private func tcpPacket(_ key: FlowKey, sequence: UInt32, ack: UInt32, flags: UInt8,
                           window: UInt16, payload: Data = Data()) -> Data {
        var body = [UInt8](repeating: 0, count: flags & 0x02 != 0 ? 24 : 20)
        Self.put16(&body, 0, key.localPort)
        Self.put16(&body, 2, key.remotePort)
        Self.put32(&body, 4, sequence)
        Self.put32(&body, 8, ack)
        body[12] = UInt8(body.count / 4) << 4
        body[13] = flags
        Self.put16(&body, 14, window)
        if flags & 0x02 != 0 { body[20] = 2; body[21] = 4; Self.put16(&body, 22, 1220) }
        body.append(contentsOf: payload)
        Self.put16(&body, 16, Self.checksum(source: address, destination: key.peer, proto: 6, body: body))
        return ipv6(peer: key.peer, proto: 6, body: body)
    }

    private func ipv6(peer: Data, proto: UInt8, body: [UInt8]) -> Data {
        var header = [UInt8](repeating: 0, count: 40)
        header[0] = 0x60
        Self.put16(&header, 4, UInt16(body.count))
        header[6] = proto
        header[7] = 64
        header.replaceSubrange(8..<24, with: address)
        header.replaceSubrange(24..<40, with: peer)
        header.append(contentsOf: body)
        return Data(header)
    }

    private static func before(_ lhs: UInt32, _ rhs: UInt32) -> Bool {
        Int32(bitPattern: lhs &- rhs) < 0
    }

    private static func u16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    private static func u32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(u16(bytes, offset)) << 16 | UInt32(u16(bytes, offset + 2))
    }

    private static func put16(_ bytes: inout [UInt8], _ offset: Int, _ value: UInt16) {
        bytes[offset] = UInt8(truncatingIfNeeded: value >> 8)
        bytes[offset + 1] = UInt8(truncatingIfNeeded: value)
    }

    private static func put32(_ bytes: inout [UInt8], _ offset: Int, _ value: UInt32) {
        put16(&bytes, offset, UInt16(truncatingIfNeeded: value >> 16))
        put16(&bytes, offset + 2, UInt16(truncatingIfNeeded: value))
    }

    private static func checksum(source: Data, destination: Data, proto: UInt8, body: [UInt8]) -> UInt16 {
        var sum = UInt32(body.count) + UInt32(proto)
        let addresses = [UInt8](source + destination)
        for index in stride(from: 0, to: addresses.count, by: 2) { sum += UInt32(u16(addresses, index)) }
        for index in stride(from: 0, to: body.count, by: 2) {
            sum += UInt32(body[index]) << 8
            if index + 1 < body.count { sum += UInt32(body[index + 1]) }
        }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum)
    }
}