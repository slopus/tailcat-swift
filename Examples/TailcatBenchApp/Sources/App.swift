import SwiftUI
import TailcatBenchmark
import Darwin

@main
struct TailcatBenchApp: App {
    var body: some Scene { WindowGroup { BenchmarkView() } }
}

struct BenchmarkView: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var status = "Starting benchmark…"
    @State private var server: TailcatBenchmarkServer?
    @State private var running = true
    var body: some View {
        ScrollView { Text(status).font(.system(.caption, design: .monospaced)).textSelection(.enabled).padding() }
            .task { await run() }
            .onChange(of: scenePhase) { _, phase in
                UIApplication.shared.isIdleTimerDisabled = phase == .active && (running || server != nil)
            }
            .onDisappear { UIApplication.shared.isIdleTimerDisabled = false }
    }

    @MainActor private func run() async {
        UIApplication.shared.isIdleTimerDisabled = true
        defer {
            running = false
            if server == nil { UIApplication.shared.isIdleTimerDisabled = false }
        }
        let arguments = ProcessInfo.processInfo.arguments
        if arguments.contains("--trace") { setenv("TAILCAT_TRACE", "1", 1) }
        func option(_ name: String, fallback: String = "") -> String {
            guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return fallback }
            return arguments[index + 1]
        }
        let mode = option("--mode", fallback: "off") == "on"
        let runID = option("--run-id", fallback: "latest").filter { $0.isLetter || $0.isNumber || $0 == "-" }
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let output = documents.appendingPathComponent("\(runID).jsonl")
        let sink = BenchmarkOutput(output)
        if arguments.contains("--server") {
            let instance = TailcatBenchmarkServer(relayFirst: mode)
            server = instance
            do {
                let address = try await instance.start()
                let ready: [String: Any] = ["type": "ready", "source": "iphone", "relayFirst": mode,
                                           "address": address, "relay": TailcatBenchmark.relayIdentity]
                let json = String(decoding: try JSONSerialization.data(withJSONObject: ready, options: [.sortedKeys]), as: UTF8.self)
                sink.append(json); status = json
            } catch { status = String(describing: error); sink.append("{\"error\":\"server startup failed\"}") }
        }
        let target = option("--target")
        if !target.isEmpty {
            if arguments.contains("--second-independent") || arguments.contains("--independent-clients") {
                await TailcatBenchmark.runIndependentClients(target: target, relayFirst: mode, source: "iphone",
                                                            destination: option("--destination", fallback: "unknown"),
                                                            attempt: Int(option("--attempt", fallback: "1")) ?? 1) { sink.append($0) }
            } else {
                await TailcatBenchmark.run(target: target, relayFirst: mode, source: "iphone",
                                       destination: option("--destination", fallback: "unknown"),
                                       attempt: Int(option("--attempt", fallback: "1")) ?? 1) { line in
                sink.append(line)
                }
            }
            sink.append("{\"type\":\"complete\",\"source\":\"iphone\"}")
            status = (try? String(contentsOf: output, encoding: .utf8)) ?? "Finished"
        }
        if target.isEmpty, !arguments.contains("--server") { status = "Launch with --server or --target tc…; --mode on|off" }
    }
}

private final class BenchmarkOutput: @unchecked Sendable {
    private let url: URL
    private let lock = NSLock()
    init(_ url: URL) { self.url = url }
    func append(_ line: String) {
        lock.lock(); defer { lock.unlock() }
        let bytes = Data((line + "\n").utf8)
        if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil) }
        if let file = try? FileHandle(forWritingTo: url) {
            defer { try? file.close() }
            _ = try? file.seekToEnd(); try? file.write(contentsOf: bytes)
        }
        FileHandle.standardOutput.write(bytes)
    }
}