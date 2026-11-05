import Foundation
import TailcatBenchmark
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

@main
struct BenchCLI {
    static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.contains("--trace") { setenv("TAILCAT_TRACE", "1", 1) }
        func option(_ name: String, default fallback: String = "") -> String {
            guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return fallback }
            return arguments[index + 1]
        }
        let mode = option("--mode", default: "off") == "on"
        let source = option("--source", default: "mac")
        let emit: @Sendable (String) -> Void = { FileHandle.standardOutput.write(Data(($0 + "\n").utf8)) }
        if arguments.contains("--server") {
            let server = TailcatBenchmarkServer(relayFirst: mode)
            do {
                let address = try await server.start()
                let ready: [String: Any] = ["type": "ready", "source": source, "relayFirst": mode,
                                           "address": address, "relay": TailcatBenchmark.relayIdentity,
                                           "pid": ProcessInfo.processInfo.processIdentifier]
                emit(String(decoding: try JSONSerialization.data(withJSONObject: ready, options: [.sortedKeys]), as: UTF8.self))
                let duration = UInt64(option("--seconds", default: "7200")) ?? 7200
                await waitForStop(seconds: duration)
                await server.close()
            } catch { emit("{\"error\":\"server startup failed\"}"); await server.close() }
        } else {
            let target = option("--target")
            guard !target.isEmpty else {
                emit("Usage: tailcat-bench --server --mode on|off --source mac OR --target tc... --destination linux --attempt 1")
                return
            }
            if arguments.contains("--second-independent") || arguments.contains("--independent-clients") {
                await TailcatBenchmark.runIndependentClients(target: target, relayFirst: mode, source: source,
                                                            destination: option("--destination", default: "unknown"),
                                                            attempt: Int(option("--attempt", default: "1")) ?? 1, emit: emit)
            } else {
                await TailcatBenchmark.run(target: target, relayFirst: mode, source: source,
                                       destination: option("--destination", default: "unknown"),
                                       attempt: Int(option("--attempt", default: "1")) ?? 1, emit: emit)
            }
        }
    }

    private static func waitForStop(seconds: UInt64) async {
        let terminate = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
        let stopped = AsyncStream<Void> { continuation in
            terminate.setEventHandler { continuation.yield(()); continuation.finish() }
            interrupt.setEventHandler { continuation.yield(()); continuation.finish() }
        }
        terminate.resume(); interrupt.resume()
        defer { terminate.cancel(); interrupt.cancel() }
        await withTaskGroup(of: Void.self) { tasks in
            tasks.addTask { try? await Task.sleep(nanoseconds: min(seconds, 86_400) * 1_000_000_000) }
            tasks.addTask { for await _ in stopped { break } }
            _ = await tasks.next(); tasks.cancelAll()
        }
    }
}