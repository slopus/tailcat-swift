// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation

/// A connected UDP flow. Reads and writes preserve datagram boundaries, including empty datagrams.
public final class TailcatUDPConnection: @unchecked Sendable {
    public let remoteAddress: Data
    public let remotePort: UInt16
    public let localPort: UInt16
    private let socket: TailcatUDPSocket
    private let flow: UDPFlow?
    internal init(socket: TailcatUDPSocket, peer: Data, port: UInt16, flow: UDPFlow? = nil) {
        self.socket = socket; remoteAddress = peer; remotePort = port; localPort = socket.port; self.flow = flow
    }
    public func read() async throws -> Data {
        if let flow { return try await flow.read() }
        while true {
            let datagram = try await socket.receive()
            if datagram.peer == remoteAddress && datagram.port == remotePort { return datagram.data }
        }
    }
    public func write(_ data: Data) async throws {
        guard data.count <= 1232 else { throw TailcatTransportError.datagramTooLarge }
        if let flow { try await flow.touch() }
        try await socket.send(data, to: remoteAddress, port: remotePort)
    }
    public func close() async { if let flow { await flow.close() } else { await socket.close() } }
}

public final class TailcatUDPListener: @unchecked Sendable {
    public let port: UInt16
    private let hub: UDPFlowHub
    internal init(socket: TailcatUDPSocket, idleTimeout: TimeInterval) {
        port = socket.port; hub = UDPFlowHub(socket: socket, idleTimeout: idleTimeout)
        Task { [hub] in await hub.start() }
    }
    public func accept() async throws -> TailcatUDPConnection { try await hub.accept() }
    public func close() async { await hub.close() }
    internal func disconnect(peer: Data) async { await hub.disconnect(peer: peer) }
}

internal actor UDPFlow {
    private var queue: [Data] = []
    private var queuedBytes = 0
    private var readers: [(UUID, CheckedContinuation<Data, Error>)] = []
    private(set) var closed = false
    private(set) var lastActivity = Date()
    func touch() throws { guard !closed else { throw TailcatError.closed }; lastActivity = Date() }
    func deliver(_ data: Data) {
        guard !closed else { return }; lastActivity = Date()
        if !readers.isEmpty { readers.removeFirst().1.resume(returning: data) }
        else if queue.count < 256, queuedBytes + data.count <= 262_144 { queue.append(data); queuedBytes += data.count }
    }
    func read() async throws -> Data {
        try Task.checkCancellation()
        guard !closed else { throw TailcatError.closed }
        lastActivity = Date()
        if !queue.isEmpty { let first = queue.removeFirst(); queuedBytes -= first.count; return first }
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { readers.append((id, $0)) }
        } onCancel: { Task { await self.cancel(id) } }
    }
    private func cancel(_ id: UUID) {
        guard let index = readers.firstIndex(where: { $0.0 == id }) else { return }
        readers.remove(at: index).1.resume(throwing: CancellationError())
    }
    func close() {
        guard !closed else { return }; closed = true; queue.removeAll(); queuedBytes = 0
        let waiting = readers; readers.removeAll(); waiting.forEach { $0.1.resume(throwing: TailcatError.closed) }
    }
}

private actor UDPFlowHub {
    private struct Key: Hashable { let peer: Data; let port: UInt16 }
    private let socket: TailcatUDPSocket
    private let idleTimeout: TimeInterval
    private var flows: [Key: UDPFlow] = [:]
    private var pending: [TailcatUDPConnection] = []
    private var accepts: [(UUID, CheckedContinuation<TailcatUDPConnection, Error>)] = []
    private var reader: Task<Void, Never>?
    private var timer: Task<Void, Never>?
    private var closed = false
    init(socket: TailcatUDPSocket, idleTimeout: TimeInterval) { self.socket = socket; self.idleTimeout = idleTimeout }
    func start() {
        guard reader == nil, !closed else { return }
        reader = Task { [weak self, socket] in
            do { while !Task.isCancelled { let d = try await socket.receive(); await self?.deliver(d) } }
            catch { await self?.close() }
        }
        timer = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: 1_000_000_000) } catch { break }
                await self?.expire()
            }
        }
    }
    func accept() async throws -> TailcatUDPConnection {
        try Task.checkCancellation()
        guard !closed else { throw TailcatError.closed }
        if !pending.isEmpty { return pending.removeFirst() }
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { accepts.append((id, $0)) }
        } onCancel: { Task { await self.cancelAccept(id) } }
    }
    private func cancelAccept(_ id: UUID) {
        guard let index = accepts.firstIndex(where: { $0.0 == id }) else { return }
        accepts.remove(at: index).1.resume(throwing: CancellationError())
    }
    private func deliver(_ datagram: TailcatDatagram) async {
        guard !closed else { return }
        let key = Key(peer: datagram.peer, port: datagram.port)
        if let flow = flows[key], !(await flow.closed) { await flow.deliver(datagram.data); return }
        guard flows.count < 1024, pending.count < 128 else { return }
        let flow = UDPFlow(); flows[key] = flow
        await flow.deliver(datagram.data)
        let connection = TailcatUDPConnection(socket: socket, peer: key.peer, port: key.port, flow: flow)
        if accepts.isEmpty { pending.append(connection) } else { accepts.removeFirst().1.resume(returning: connection) }
    }
    private func expire() async {
        for (key, flow) in flows {
            let isClosed = await flow.closed
            let activity = await flow.lastActivity
            if isClosed || Date().timeIntervalSince(activity) >= idleTimeout {
                await flow.close(); flows.removeValue(forKey: key)
                pending.removeAll { $0.remoteAddress == key.peer && $0.remotePort == key.port }
            }
        }
    }
    func disconnect(peer: Data) async {
        for (key, flow) in flows where key.peer == peer { await flow.close(); flows.removeValue(forKey: key) }
        pending.removeAll { $0.remoteAddress == peer }
    }
    func close() async {
        guard !closed else { return }; closed = true; reader?.cancel(); timer?.cancel()
        let waiting = accepts; accepts.removeAll(); waiting.forEach { $0.1.resume(throwing: TailcatError.closed) }
        for flow in flows.values { await flow.close() }; flows.removeAll(); pending.removeAll(); await socket.close()
    }
}