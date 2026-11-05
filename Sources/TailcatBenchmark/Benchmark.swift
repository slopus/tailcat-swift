import Foundation
import Tailcat

/// App-level echo benchmark shared by the CLI and physical-device runner.
/// It does not modify Tailcat's encrypted wire protocol.
public enum TailcatBenchmark {
    public static let regionID = 301
    public static let relayIdentity = "tc301a.ipn.dev:443 (region 301 NYC)"
    public static let payloadBytes = 262_144

    public struct Sample: Codable, Sendable {
        public var source: String
        public var destination: String
        public var runtime = "swift"
        public var diagnosticTracing = ProcessInfo.processInfo.environment["TAILCAT_TRACE"] == "1"
        #if DEBUG
        public var buildConfiguration = "debug"
        #else
        public var buildConfiguration = "release"
        #endif
        public var os = ProcessInfo.processInfo.operatingSystemVersionString
        public var relay = TailcatBenchmark.relayIdentity
        public var relayFirst: Bool
        public var attempt: Int
        public var phase: String
        public var sessionReused: Bool
        public var timestamp = ISO8601DateFormatter().string(from: Date())
        public var connectMs: Double = 0
        public var firstApplicationByteMs: Double?
        public var firstEchoMs: Double?
        public var initialPath: String?
        public var steadyPath: String?
        public var directObservedMs: Double?
        public var directCensored = false
        public var rttMs = [Double]()
        public var throughputBytes = TailcatBenchmark.payloadBytes
        public var throughputMs: Double?
        public var throughputMiBps: Double?
        public var recoveryEchoMs = [Double]()
        public var recoveryPathBefore: String?
        public var recoveryPathAfter: String?
        public var recoveryDirectMs: Double?
        public var recoveryDirectCensored: Bool?
        public var error: String?

        public func json() -> String {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            return String(decoding: (try? encoder.encode(self)) ?? Data("{}".utf8), as: UTF8.self)
        }
    }

    public static func now() -> Double { ProcessInfo.processInfo.systemUptime }
    private static func milliseconds(since start: Double) -> Double { (now() - start) * 1000 }
    private static func path(_ value: ConnectionPath) -> String {
        switch value { case .relay: return "relay"; case let .direct(endpoint): return "direct:\(endpoint)" }
    }

    /// Runs a fresh encrypted connection, then a second stream on that same client.
    public static func run(target: String, relayFirst: Bool, source: String, destination: String,
                           attempt: Int, emit: @escaping @Sendable (String) -> Void) async {
        var configuration = TailcatClient.Configuration()
        configuration.relayFirst = relayFirst
        configuration.connectTimeout = 30
        let start = now()
        var sample = Sample(source: source, destination: destination, relayFirst: relayFirst,
                            attempt: attempt, phase: "cold_new_client", sessionReused: false)
        var client: TailcatClient?
        do {
            let connected = try await TailcatClient.connect(to: target, configuration: configuration)
            client = connected
            sample.connectMs = milliseconds(since: start)
            let cold = sample
            sample = try await bounded(seconds: 100) {
                try await measure(connected, start: start, sample: cold, recover: true)
            }
            emit(sample.json())
            let warm = Sample(source: source, destination: destination, relayFirst: relayFirst,
                              attempt: attempt, phase: "warm_reused_client_second_stream", sessionReused: true)
            do {
                let warmStart = now()
                let measured = try await bounded(seconds: 70) {
                    try await measure(connected, start: warmStart, sample: warm, recover: false)
                }
                emit(measured.json())
            } catch { var failed = warm; failed.error = String(describing: error); emit(failed.json()) }
            await connected.close()
        } catch { sample.error = String(describing: error); emit(sample.json()); await client?.close() }
    }

    private static func measure(_ client: TailcatClient, start: Double, sample initial: Sample,
                                recover: Bool) async throws -> Sample {
        var sample = initial
        sample.initialPath = path(await client.path)
        let observation = Task { try await observeDirect(client, start: start) }
        defer { observation.cancel() }
        let stream = try await client.openTCP(port: 8080)
        do {
            let ping = payload(32, seed: 1)
            async let initialWrite: Void = stream.write(ping)
            let first = try await stream.read(maximumBytes: 1)
            guard first.count == 1 else { throw BenchmarkError.unexpectedEOF }
            sample.firstApplicationByteMs = milliseconds(since: start)
            let rest = try await readExactly(stream, count: 31)
            guard first + rest == ping else { throw BenchmarkError.corruptEcho }
            sample.firstEchoMs = milliseconds(since: start)
            try await initialWrite
            sample.directObservedMs = try await observation.value
            sample.directCensored = sample.directObservedMs == nil
            sample.steadyPath = path(await client.path)
            for sequence in 0..<20 {
                let begin = now(), ping = payload(32, seed: sequence + 2)
                try await stream.write(ping)
                guard try await readExactly(stream, count: 32) == ping else { throw BenchmarkError.corruptEcho }
                sample.rttMs.append(milliseconds(since: begin))
            }
            let bytes = payload(payloadBytes, seed: 37), transferStart = now()
            async let writer: Void = stream.write(bytes)
            let received = try await readExactly(stream, count: bytes.count)
            try await writer
            guard received == bytes else { throw BenchmarkError.corruptEcho }
            let duration = milliseconds(since: transferStart)
            sample.throughputMs = duration
            sample.throughputMiBps = Double(bytes.count) / 1_048_576 / (duration / 1000)
            if recover {
                sample.recoveryPathBefore = path(await client.path)
                let reset = now()
                await client.notifyNetworkChanged()
                let recoveryObservation = Task { try await observeDirect(client, start: reset) }
                defer { recoveryObservation.cancel() }
                for sequence in 0..<10 {
                    let begin = now(), ping = payload(32, seed: sequence + 100)
                    try await stream.write(ping)
                    guard try await readExactly(stream, count: 32) == ping else { throw BenchmarkError.corruptEcho }
                    sample.recoveryEchoMs.append(milliseconds(since: begin))
                }
                sample.recoveryPathAfter = path(await client.path)
                sample.recoveryDirectMs = try await recoveryObservation.value
                sample.recoveryDirectCensored = sample.recoveryDirectMs == nil
            }
            await stream.close()
            return sample
        } catch { await stream.close(); throw error }
    }

    private static func observeDirect(_ client: TailcatClient, start: Double) async throws -> Double? {
        let deadline = now() + 15
        while now() < deadline {
            if case .direct = await client.path { return milliseconds(since: start) }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        return nil
    }

    static func payload(_ count: Int, seed: Int) -> Data {
        Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ seed) })
    }

    static func readExactly(_ stream: TailcatConnection, count: Int) async throws -> Data {
        var result = Data()
        while result.count < count {
            let part = try await stream.read(maximumBytes: count - result.count)
            guard !part.isEmpty else { throw BenchmarkError.unexpectedEOF }
            result.append(part)
        }
        return result
    }

    static func bounded<T: Sendable>(seconds: Double, operation: @escaping @Sendable () async throws -> T) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { tasks in
            tasks.addTask { try await operation() }
            tasks.addTask { try await Task.sleep(nanoseconds: UInt64(seconds * 1e9)); throw BenchmarkError.timeout }
            defer { tasks.cancelAll() }
            return try await tasks.next()!
        }
    }
    enum BenchmarkError: Error { case unexpectedEOF, corruptEcho, timeout }
}

public actor TailcatBenchmarkServer {
    private let server: TailcatServer
    private var acceptTask: Task<Void, Never>?

    public init(relayFirst: Bool) {
        var configuration = TailcatServer.Configuration()
        configuration.regionID = TailcatBenchmark.regionID
        configuration.relayFirst = relayFirst
        server = TailcatServer(configuration: configuration)
    }

    public func start() async throws -> String {
        let listener = try await server.listen(port: 8080)
        acceptTask = Task {
            while !Task.isCancelled {
                guard let stream = try? await listener.accept() else { break }
                Task {
                    do {
                        while true {
                            let bytes = try await stream.read()
                            if bytes.isEmpty { break }
                            try await stream.write(bytes)
                        }
                        try await stream.closeWrite()
                    } catch {}
                    await stream.close()
                }
            }
        }
        return try await server.address.description
    }

    public func close() async { acceptTask?.cancel(); await server.close() }
}