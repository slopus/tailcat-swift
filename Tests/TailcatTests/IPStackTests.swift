import Foundation
import XCTest
@testable import Tailcat

private actor PacketLink {
    struct Faults: Sendable {
        var dropSYN = false
        var dropSYNACK = false
        var dropData = false
        var dropACK = false
        var dropFIN = false
        var reorder = false
        var duplicate = false
        var reorderACKs = false
        var dropReopenWindow = false
        var dropFINACK = false
        var rejectSYN = false
        var rejectCorruptSYN = false
    }

    private var a: IPStack?
    private var b: IPStack?
    private var faults: Faults
    private var held: Data?
    private var heldACK: Data?
    private var sawData = false
    private var sawFIN = false
    private(set) var sawZeroWindow = false
    private(set) var drops = 0

    init(faults: Faults = Faults()) { self.faults = faults }

    func attach(_ a: IPStack, _ b: IPStack) { self.a = a; self.b = b }

    func send(_ data: Data, fromA: Bool) async {
        guard let target = fromA ? b : a else { return }
        if data.count >= 60 && data[6] == 6 {
            let flags = data[53]
            let count = data.count - 40 - Int(data[52] >> 4) * 4
            if flags & 0x12 == 0x02 && faults.rejectSYN {
                faults.rejectSYN = false
                await target.rejectTCP(peer: Data(data[8..<24]), body: Data(data.dropFirst(40)))
                return
            }
            if flags & 0x12 == 0x02 && faults.rejectCorruptSYN {
                faults.rejectCorruptSYN = false
                var body = Data(data.dropFirst(40))
                body[16] ^= 1
                await target.rejectTCP(peer: Data(data[8..<24]), body: body)
            }
            if data[54] == 0 && data[55] == 0 { sawZeroWindow = true }
            if fromA && flags & 1 != 0 { sawFIN = true }
            if !fromA && flags == 0x10 && sawZeroWindow &&
                (data[54] != 0 || data[55] != 0) && faults.dropReopenWindow {
                faults.dropReopenWindow = false; drops += 1; return
            }
            if !fromA && flags == 0x10 && sawFIN && faults.dropFINACK {
                faults.dropFINACK = false; drops += 1; return
            }
            if flags & 0x12 == 0x02 && faults.dropSYN {
                faults.dropSYN = false; drops += 1; return
            }
            if flags & 0x12 == 0x12 && faults.dropSYNACK {
                faults.dropSYNACK = false; drops += 1; return
            }
            if count > 0 { sawData = true }
            if count > 0 && fromA && faults.dropData {
                faults.dropData = false; drops += 1; return
            }
            if count == 0 && flags == 0x10 && !fromA && sawData && faults.dropACK {
                faults.dropACK = false; drops += 1; return
            }
            if flags & 1 != 0 && faults.dropFIN {
                faults.dropFIN = false; drops += 1; return
            }
            if !fromA && count == 0 && flags == 0x10 && sawData && faults.reorderACKs {
                if let previous = heldACK {
                    heldACK = nil
                    faults.reorderACKs = false
                    await target.receive(data)
                    await target.receive(previous)
                    return
                }
                heldACK = data
                return
            }
            if count > 0 && fromA && faults.reorder {
                if let previous = held {
                    held = nil
                    faults.reorder = false
                    await target.receive(data)
                    await target.receive(previous)
                    return
                }
                held = data
                return
            }
            if count > 0 && faults.duplicate { await target.receive(data) }
        }
        await target.receive(data)
    }
}

private actor PacketCapture {
    var packet: Data?
    func record(_ packet: Data) { self.packet = packet }
}

private actor CompletionFlag {
    private(set) var completed = false
    func finish() { completed = true }
}

final class IPStackTests: XCTestCase {
    private let addressA = Data([0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0] + [UInt8](repeating: 0, count: 9) + [1])
    private let addressB = Data([0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0] + [UInt8](repeating: 0, count: 9) + [2])

    private func pair(_ faults: PacketLink.Faults = .init()) async -> (IPStack, IPStack, PacketLink) {
        let link = PacketLink(faults: faults)
        let a = IPStack(address: addressA) { await link.send($0, fromA: true) }
        let b = IPStack(address: addressB) { await link.send($0, fromA: false) }
        await link.attach(a, b)
        return (a, b, link)
    }

    private func deadline<T: Sendable>(_ operation: @escaping @Sendable () async throws -> T) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(nanoseconds: 25_000_000_000)
                throw TailcatTransportError.timedOut
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    private func drain(_ stream: TailcatConnection) async throws -> Data {
        var result = Data()
        while true {
            let chunk = try await stream.read(maximumBytes: 7777)
            if chunk.isEmpty { return result }
            result.append(chunk)
        }
    }

    func testHalfCloseDrainsRequestAndBufferedResponse() async throws {
        let (a, b, _) = await pair()
        let listener = try await b.listen(port: 80)
        let peer = addressB
        let request = Data((0..<180_000).map { UInt8(truncatingIfNeeded: $0) })
        let response = Data(repeating: 0x7f, count: 91_234)
        try await deadline {
            async let accepted = listener.accept()
            let client = try await a.connect(peer: peer, port: 80)
            let server = try await accepted
            XCTAssertEqual(client.remoteAddress, peer)
            XCTAssertEqual(client.remotePort, 80)
            let requestWriter = Task {
                try await client.write(request)
                try await client.closeWrite()
            }
            let received = try await self.drain(server)
            XCTAssertEqual(received, request)
            try await requestWriter.value
            let responseWriter = Task {
                try await server.write(response)
                try await server.closeWrite()
            }
            let receivedResponse = try await self.drain(client)
            XCTAssertEqual(receivedResponse, response)
            try await responseWriter.value
            // EOF remains observable after already buffered bytes are drained.
            let eof = try await client.read()
            XCTAssertTrue(eof.isEmpty)
        }
        await a.close(); await b.close()
    }

    func testRetransmitsLostHandshakeDataACKAndFIN() async throws {
        let faults = PacketLink.Faults(dropSYN: true, dropSYNACK: true, dropData: true,
                                     dropACK: true, dropFIN: true)
        let (a, b, link) = await pair(faults)
        let listener = try await b.listen(port: 443)
        let peer = addressB
        let payload = Data(repeating: 0x31, count: 23_456)
        try await deadline {
            let client = try await a.connect(peer: peer, port: 443)
            let server = try await listener.accept()
            let writer = Task {
                try await client.write(payload)
                try await client.closeWrite()
            }
            let received = try await self.drain(server)
            XCTAssertEqual(received, payload)
            try await writer.value
            let count = await link.drops
            XCTAssertEqual(count, 5)
        }
        await a.close(); await b.close()
    }

    func testReorderedAndDuplicatedSegmentsPreserveByteStream() async throws {
        let (a, b, _) = await pair(.init(reorder: true, duplicate: true, reorderACKs: true))
        let listener = try await b.listen(port: 123)
        let peer = addressB
        let bytes = Data((0..<400_000).map { UInt8(truncatingIfNeeded: $0 * 31) })
        try await deadline {
            let client = try await a.connect(peer: peer, port: 123)
            let server = try await listener.accept()
            let writer = Task {
                try await client.write(bytes)
                try await client.closeWrite()
            }
            let actual = try await self.drain(server)
            XCTAssertEqual(actual, bytes)
            try await writer.value
        }
        await a.close(); await b.close()
    }

    func testZeroWindowBackpressureAndReopen() async throws {
        let (a, b, link) = await pair()
        let listener = try await b.listen(port: 321)
        let peer = addressB
        let bytes = Data(repeating: 0xa7, count: 300_000)
        try await deadline {
            let client = try await a.connect(peer: peer, port: 321)
            let server = try await listener.accept()
            let writer = Task {
                try await client.write(bytes)
                try await client.closeWrite()
            }
            for _ in 0..<200 {
                if await link.sawZeroWindow { break }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
            let sawZero = await link.sawZeroWindow
            XCTAssertTrue(sawZero)
            let received = try await self.drain(server)
            XCTAssertEqual(received, bytes)
            try await writer.value
        }
        await a.close(); await b.close()
    }

    func testMultipleClientsTransferMegabytes() async throws {
        let (a, b, _) = await pair()
        let listener = try await b.listen(port: 999)
        let peer = addressB
        let payload = Data((0..<2_000_000).map { UInt8(truncatingIfNeeded: $0) })
        try await deadline {
            try await withThrowingTaskGroup(of: Void.self) { group in
                for _ in 0..<3 {
                    group.addTask {
                        let client = try await a.connect(peer: peer, port: 999)
                        try await client.write(payload)
                        try await client.closeWrite()
                    }
                    group.addTask {
                        let server = try await listener.accept()
                        let received = try await self.drain(server)
                        XCTAssertEqual(received, payload)
                    }
                }
                try await group.waitForAll()
            }
        }
        await a.close(); await b.close()
    }

    func testLostWindowUpdateAndFinalFINAcknowledgementRecover() async throws {
        let (a, b, link) = await pair(.init(dropReopenWindow: true, dropFINACK: true))
        let listener = try await b.listen(port: 81)
        let peer = addressB
        let bytes = Data(repeating: 0x7b, count: 90_000)
        try await deadline {
            let client = try await a.connect(peer: peer, port: 81)
            let server = try await listener.accept()
            let writer = Task {
                try await client.write(bytes)
                try await client.closeWrite()
            }
            for _ in 0..<200 {
                if await link.sawZeroWindow { break }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
            let zero = await link.sawZeroWindow
            XCTAssertTrue(zero)
            // Exactly one read advertises a reopened window; lose that update
            // and require the sender's persist probe to make progress.
            var received = try await server.read(maximumBytes: 65_535)
            XCTAssertEqual(received.count, 65_535)
            // Remaining data fits the reopened buffer. FIN's ACK is also lost,
            // so closeWrite must recover by retransmitting FIN after peer EOF.
            try await writer.value
            received.append(try await self.drain(server))
            XCTAssertEqual(received, bytes)
            let drops = await link.drops
            XCTAssertEqual(drops, 2)
        }
        await a.close(); await b.close()
    }

    func testDrainWaitsForACKsAndLeavesWriteSideOpen() async throws {
        let (a, b, link) = await pair()
        let listener = try await b.listen(port: 82)
        let peer = addressB
        let payload = Data(repeating: 0x32, count: 100_000)
        try await deadline {
            let client = try await a.connect(peer: peer, port: 82)
            let server = try await listener.accept()
            let writer = Task { try await client.write(payload) }
            for _ in 0..<200 {
                if await link.sawZeroWindow { break }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
            let flag = CompletionFlag()
            let drainer = Task { try await client.drain(); await flag.finish() }
            try await Task.sleep(nanoseconds: 10_000_000)
            let completed = await flag.completed
            XCTAssertFalse(completed)
            var received = Data()
            while received.count < payload.count { received.append(try await server.read()) }
            XCTAssertEqual(received, payload)
            try await writer.value
            try await drainer.value
            try await client.write(Data([1, 2, 3]))
            let trailing = try await server.read()
            XCTAssertEqual(trailing, Data([1, 2, 3]))
            await client.close()
            let eof = try await server.read()
            XCTAssertTrue(eof.isEmpty)
        }
        await a.close(); await b.close()
    }

    func testCloseFlushesQueuedBytesAndDiscardsIncomingWithoutReset() async throws {
        let (a, b, link) = await pair()
        let listener = try await b.listen(port: 83)
        let peer = addressB
        let payload = Data(repeating: 0x42, count: 180_000)
        try await deadline {
            let client = try await a.connect(peer: peer, port: 83)
            let server = try await listener.accept()
            let writer = Task { try await client.write(payload) }
            for _ in 0..<200 {
                if await link.sawZeroWindow { break }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
            await client.close()
            // Closing must ACK and discard incoming data, so the peer can
            // finish even when its response exceeds the receive window.
            let response = Task {
                try await server.write(Data(repeating: 0x19, count: 200_000))
                try await server.closeWrite()
            }
            let received = try await self.drain(server)
            XCTAssertEqual(received, payload)
            try await writer.value
            try await response.value
            do { _ = try await client.read(); XCTFail("Expected local close") }
            catch { XCTAssertEqual(error as? TailcatTransportError, .closed) }
        }
        await a.close(); await b.close()
    }

    func testRefusedConnectionAndCancellationWakeWaiters() async throws {
        let (a, b, _) = await pair()
        do {
            _ = try await deadline { try await a.connect(peer: self.addressB, port: 9) }
            XCTFail("Expected refusal")
        } catch { XCTAssertEqual(error as? TailcatTransportError, .connectionRefused) }
        let listener = try await b.listen(port: 23)
        let waiter = Task { try await listener.accept() }
        waiter.cancel()
        do { _ = try await waiter.value; XCTFail("Expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
        let client = try await a.connect(peer: addressB, port: 23)
        let server = try await listener.accept()
        let read = Task { try await server.read() }
        read.cancel()
        do { _ = try await read.value; XCTFail("Expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
        await client.close()
        let eof = try await deadline { try await server.read() }
        XCTAssertTrue(eof.isEmpty)
        await a.close(); await b.close()
    }

    func testUDPBoundariesSourceIdentityAndEmptyDatagram() async throws {
        let (a, b, _) = await pair()
        let sender = try await a.udp()
        let receiver = try await b.udp(port: 53)
        for payload in [Data(), Data([1, 2, 3]), Data(repeating: 0x55, count: 1232)] {
            try await sender.send(payload, to: addressB, port: 53)
            let received = try await deadline { try await receiver.receive() }
            XCTAssertEqual(received.data, payload)
            XCTAssertEqual(received.peer, addressA)
            XCTAssertEqual(received.port, sender.port)
        }
        do {
            try await sender.send(Data(repeating: 0, count: 1233), to: addressB, port: 53)
            XCTFail("Expected MTU rejection")
        } catch { XCTAssertEqual(error as? TailcatTransportError, .datagramTooLarge) }
        let pending = Task { try await receiver.receive() }
        await receiver.close()
        do { _ = try await pending.value; XCTFail("Expected close") }
        catch { XCTAssertEqual(error as? TailcatTransportError, .closed) }
        await a.close(); await b.close()
    }

    func testExplicitSYNRejectionAndAcceptedStreamAbort() async throws {
        let (a, b, _) = await pair(.init(rejectSYN: true))
        let listener = try await b.listen(port: 80)
        do {
            _ = try await deadline { try await a.connect(peer: self.addressB, port: 80) }
            XCTFail("Expected explicit refusal despite bound listener")
        } catch { XCTAssertEqual(error as? TailcatTransportError, .connectionRefused) }
        let stillListening = await b.hasTCPListener(port: 80)
        XCTAssertTrue(stillListening)
        let client = try await a.connect(peer: addressB, port: 80)
        let server = try await listener.accept()
        let active = await b.hasTCPFlow(peer: addressA, localPort: 80, remotePort: client.localPort)
        XCTAssertTrue(active)
        await server.abort()
        let removed = await b.hasTCPFlow(peer: addressA, localPort: 80, remotePort: client.localPort)
        XCTAssertFalse(removed)
        do {
            _ = try await deadline { try await client.read() }
            XCTFail("Expected peer reset")
        } catch { XCTAssertEqual(error as? TailcatTransportError, .connectionReset) }
        await a.close(); await b.close()
    }

    func testExplicitRejectionIgnoresBadTCPChecksum() async throws {
        let (a, b, _) = await pair(.init(rejectCorruptSYN: true))
        let listener = try await b.listen(port: 80)
        let client = try await deadline { try await a.connect(peer: self.addressB, port: 80) }
        let server = try await listener.accept()
        try await client.write(Data([1, 2, 3]))
        let received = try await server.read()
        XCTAssertEqual(received, Data([1, 2, 3]))
        await a.close(); await b.close()
    }

    func testRejectsCorruptChecksumWrongDestinationAndTruncatedIPv6() async throws {
        let capture = PacketCapture()
        let a = IPStack(address: addressA) { await capture.record($0) }
        let b = IPStack(address: addressB) { _ in }
        let sender = try await a.udp()
        let receiver = try await b.udp(port: 53)
        try await sender.send(Data([1, 2, 3]), to: addressB, port: 53)
        let captured = await capture.packet
        let packet = try XCTUnwrap(captured)
        var corrupt = packet
        corrupt[48] ^= 0xff
        await b.receive(corrupt)
        var wrongDestination = packet
        wrongDestination[39] ^= 1
        await b.receive(wrongDestination)
        await b.receive(Data(packet.dropLast()))
        var missingChecksum = packet
        missingChecksum[46] = 0; missingChecksum[47] = 0
        await b.receive(missingChecksum)
        // If any invalid packet were accepted, it would precede this marker.
        try await sender.send(Data([4, 5, 6]), to: addressB, port: 53)
        let marker = await capture.packet
        await b.receive(try XCTUnwrap(marker))
        let result = try await deadline { try await receiver.receive() }
        XCTAssertEqual(result.data, Data([4, 5, 6]))
        await a.close(); await b.close()
    }

    func testUDPIdleTimeoutAndPersistentListeningSocket() async throws {
        let (a, b, _) = await pair()
        let expiring = try await a.udp(idleTimeout: 0.02)
        let persistent = try await b.udp(port: 53, idleTimeout: nil)
        do {
            _ = try await deadline { try await expiring.receive() }
            XCTFail("Expected idle timeout")
        } catch { XCTAssertEqual(error as? TailcatTransportError, .timedOut) }
        let fresh = try await a.udp()
        try await fresh.send(Data([0x42]), to: addressB, port: persistent.port)
        let datagram = try await deadline { try await persistent.receive() }
        XCTAssertEqual(datagram.data, Data([0x42]))
        await a.close(); await b.close()
    }

    func testDisconnectClosesPeerStreamsAndClearsQueuedDatagrams() async throws {
        let (a, b, _) = await pair()
        let listener = try await b.listen(port: 80)
        let client = try await a.connect(peer: addressB, port: 80)
        let server = try await listener.accept()
        let sender = try await a.udp()
        let receiver = try await b.udp(port: 53, idleTimeout: nil)
        try await sender.send(Data([1]), to: addressB, port: 53)
        await b.disconnect(peer: addressA)
        do { _ = try await server.read(); XCTFail("Expected close") }
        catch { XCTAssertEqual(error as? TailcatTransportError, .closed) }
        do { _ = try await deadline { try await client.read() }; XCTFail("Expected reset") }
        catch { XCTAssertEqual(error as? TailcatTransportError, .connectionReset) }
        try await sender.send(Data([2]), to: addressB, port: 53)
        let result = try await deadline { try await receiver.receive() }
        XCTAssertEqual(result.data, Data([2]))
        await a.close(); await b.close()
    }
}