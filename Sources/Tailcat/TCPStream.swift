// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation

/// Errors reported by the userspace IPv6 transports.
public enum TailcatTransportError: Error, Equatable, Sendable {
    case invalidAddress
    case invalidPort
    case addressInUse
    case closed
    case connectionRefused
    case connectionReset
    case timedOut
    case datagramTooLarge
    case invalidReadSize
    case invalidTimeout
    case resourceLimit
}

/// A TCP byte stream carried directly over the Tailcat IPv6 tunnel.
public final class TailcatConnection: Sendable {
    public let localAddress: Data
    public let remoteAddress: Data
    public let localPort: UInt16
    public let remotePort: UInt16
    private let stack: IPStack
    private let id: UUID

    internal init(stack: IPStack, id: UUID, localAddress: Data, remoteAddress: Data,
                  localPort: UInt16, remotePort: UInt16) {
        self.stack = stack
        self.id = id
        self.localAddress = localAddress
        self.remoteAddress = remoteAddress
        self.localPort = localPort
        self.remotePort = remotePort
    }

    /// Returns buffered bytes, waiting if necessary. Empty data means orderly EOF.
    public func read(maximumBytes: Int = 65_536) async throws -> Data {
        try await stack.read(id, maximumBytes: maximumBytes)
    }

    /// Applies backpressure until the peer acknowledges all supplied bytes.
    public func write(_ data: Data) async throws {
        try await stack.write(id, data: data)
    }

    /// Waits for writes already submitted to the stack to be acknowledged,
    /// leaving the write side open. Individual writes already await their ACKs.
    public func drain() async throws {
        try await stack.drain(id)
    }

    /// Sends FIN after prior writes and waits for its acknowledgement.
    public func closeWrite() async throws {
        try await stack.closeWrite(id)
    }

    /// Closes the application stream, sending FIN after queued bytes. Incoming
    /// bytes are discarded while the transport completes its closing handshake.
    public func close() async {
        await stack.closeConnection(id)
    }

    internal func abort() async {
        await stack.abortConnection(id)
    }
}

public final class TailcatListener: Sendable {
    public let port: UInt16
    public let localAddress: Data
    private let stack: IPStack
    private let id: UUID

    internal init(stack: IPStack, id: UUID, port: UInt16, localAddress: Data) {
        self.stack = stack
        self.id = id
        self.port = port
        self.localAddress = localAddress
    }

    public func accept() async throws -> TailcatConnection {
        try await stack.accept(id)
    }

    public func close() async {
        await stack.closeListener(id)
    }
}

public struct TailcatDatagram: Sendable, Equatable {
    public let data: Data
    public let peer: Data
    public let port: UInt16

    public init(data: Data, peer: Data, port: UInt16) {
        self.data = data
        self.peer = peer
        self.port = port
    }
}

public final class TailcatUDPSocket: Sendable {
    public let port: UInt16
    private let stack: IPStack
    private let id: UUID

    internal init(stack: IPStack, id: UUID, port: UInt16) {
        self.stack = stack
        self.id = id
        self.port = port
    }

    public func send(_ data: Data, to peer: Data, port: UInt16) async throws {
        try await stack.sendUDP(id, data: data, peer: peer, port: port)
    }

    public func receive() async throws -> TailcatDatagram {
        try await stack.receiveUDP(id)
    }

    public func close() async {
        await stack.closeUDP(id)
    }
}