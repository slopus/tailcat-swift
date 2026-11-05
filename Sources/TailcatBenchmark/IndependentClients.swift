import Foundation
import Tailcat

extension TailcatBenchmark {
    private struct IndependentSample: Codable, Sendable {
        var source: String
        var destination: String
        var runtime = "swift"
        var relay = TailcatBenchmark.relayIdentity
        var relayFirst: Bool
        var attempt: Int
        var phase: String
        var sessionReused = false
        var connectionTraceID: String
        var connectMs: Double?
        var firstEchoMs: Double?
        var pathAtFirstEcho: String?
        var handshakeToConnectReturnMs: Double?
        var firstClientEchoesDuringSecondConnect: Int?
        var distinctNodeIdentities: Bool?
        var distinctDiscoveryIdentities: Bool?
        var distinctRelayConnections: Bool?
        var distinctUDPPorts: Bool?
        var firstSurvivedSecondClose: Bool?
        var events = [StartupTrace.Event]()
        var error: String?

        mutating func finish(_ trace: StartupTrace) {
            events = trace.snapshot()
            if let established = events.first(where: { $0.name == "wireGuardEstablished" }),
               let returned = events.first(where: { $0.name == "connectReturned" }) {
                handshakeToConnectReturnMs = returned.elapsedMs - established.elapsedMs
            }
        }
        func json() -> String {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            return String(decoding: (try? encoder.encode(self)) ?? Data("{}".utf8), as: UTF8.self)
        }
    }

    private actor EchoCounter {
        var completed = [Double]()
        var stopping = false
        func stop() { stopping = true }
        func increment() { if completed.count < 2048 { completed.append(TailcatBenchmark.now()) } }
        func count(from start: Double, through end: Double) -> Int {
            completed.filter { $0 >= start && $0 <= end }.count
        }
    }

    /// Two independent client identities, WireGuard sessions, UDP sockets and DERP
    /// connections. The first remains alive and exchanges data during the second dial.
    public static func runIndependentClients(target: String, relayFirst: Bool, source: String,
                                             destination: String, attempt: Int,
                                             emit: @escaping @Sendable (String) -> Void) async {
        let firstTrace = StartupTrace(), secondTrace = StartupTrace()
        var firstSample = IndependentSample(source: source, destination: destination, relayFirst: relayFirst,
                                            attempt: attempt, phase: "cold_first_independent_client", connectionTraceID: firstTrace.id)
        var secondSample = IndependentSample(source: source, destination: destination, relayFirst: relayFirst,
                                             attempt: attempt, phase: "warm_process_second_independent_client", connectionTraceID: secondTrace.id)
        var first: TailcatClient?, second: TailcatClient?
        var firstStream: TailcatConnection?, secondStream: TailcatConnection?
        var heartbeat: Task<Void, Error>?
        var measuringSecond = false
        do {
            var configuration = TailcatClient.Configuration()
            configuration.relayFirst = relayFirst
            configuration.startupTrace = firstTrace
            let firstStart = now()
            let retained = try await TailcatClient.connect(to: target, configuration: configuration)
            first = retained
            firstSample.connectMs = (now() - firstStart) * 1000
            let retainedStream = try await retained.openTCP(port: 8080)
            firstStream = retainedStream
            try await independentEcho(retainedStream, sequence: 0)
            firstTrace.record("firstEcho")
            firstSample.firstEchoMs = (now() - firstStart) * 1000
            firstSample.pathAtFirstEcho = await retained.path == .relay ? "relay" : "direct"

            let counter = EchoCounter()
            heartbeat = Task {
                var sequence = 1
                while !Task.isCancelled {
                    if await counter.stopping { break }
                    try await independentEcho(retainedStream, sequence: sequence)
                    await counter.increment(); sequence += 1
                    try await Task.sleep(nanoseconds: 50_000_000)
                }
            }
            measuringSecond = true
            configuration.startupTrace = secondTrace
            let secondStart = now()
            let connected = try await TailcatClient.connect(to: target, configuration: configuration)
            let secondReturned = now()
            second = connected
            secondSample.connectMs = (secondReturned - secondStart) * 1000
            secondSample.firstClientEchoesDuringSecondConnect = await counter.count(from: secondStart, through: secondReturned)
            let connectedStream = try await connected.openTCP(port: 8080)
            secondStream = connectedStream
            try await independentEcho(connectedStream, sequence: 10_000)
            secondTrace.record("firstEcho")
            secondSample.firstEchoMs = (now() - secondStart) * 1000
            secondSample.pathAtFirstEcho = await connected.path == .relay ? "relay" : "direct"
            secondSample.distinctNodeIdentities = await retained.publicKey != connected.publicKey
            secondSample.distinctDiscoveryIdentities = try await retained.discoveryPublicKey != connected.discoveryPublicKey

            // UDP may be deliberately deferred by relayFirst. This observation is
            // outside the startup timing and does not hold up the second dial.
            let observationDeadline = now() + 5
            while now() < observationDeadline,
                  firstTrace.snapshot().first(where: { $0.name == "udpBound" }) == nil ||
                  secondTrace.snapshot().first(where: { $0.name == "udpBound" }) == nil {
                try await Task.sleep(nanoseconds: 20_000_000)
            }
            let firstEvents = firstTrace.snapshot(), secondEvents = secondTrace.snapshot()
            if let one = firstEvents.first(where: { $0.name == "udpBound" })?.detail,
               let two = secondEvents.first(where: { $0.name == "udpBound" })?.detail {
                secondSample.distinctUDPPorts = one != two
            }
            let firstRelays = Set(firstEvents.filter { $0.name == "relayConnectionCreated" }.compactMap(\.detail))
            let secondRelays = Set(secondEvents.filter { $0.name == "relayConnectionCreated" }.compactMap(\.detail))
            secondSample.distinctRelayConnections = !firstRelays.isEmpty && !secondRelays.isEmpty && firstRelays.isDisjoint(with: secondRelays)
            await counter.stop()
            try await heartbeat?.value
            heartbeat = nil
            await connectedStream.close(); secondStream = nil
            await connected.close(); second = nil
            try await independentEcho(retainedStream, sequence: 20_000)
            secondSample.firstSurvivedSecondClose = true
        } catch {
            if measuringSecond { secondSample.error = String(describing: error) }
            else { firstSample.error = String(describing: error); secondSample.error = "first client did not finish startup" }
        }
        heartbeat?.cancel()
        // Closing wakes any pending echo before joining its task.
        await secondStream?.close(); await second?.close()
        await firstStream?.close(); await first?.close()
        _ = await heartbeat?.result
        firstSample.finish(firstTrace); secondSample.finish(secondTrace)
        emit(firstSample.json()); emit(secondSample.json())
    }

    private static func independentEcho(_ stream: TailcatConnection, sequence: Int) async throws {
        try await bounded(seconds: 10) {
            var bytes = payload(32, seed: sequence)
            withUnsafeBytes(of: UInt64(sequence).bigEndian) { bytes.replaceSubrange(0..<8, with: $0) }
            try await stream.write(bytes)
            guard try await readExactly(stream, count: bytes.count) == bytes else { throw BenchmarkError.corruptEcho }
        }
    }
}