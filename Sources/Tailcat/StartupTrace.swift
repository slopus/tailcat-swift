import Foundation

/// Opt-in, package-only timing for the benchmark. Never retains key or packet data.
/// Every client owns its trace; normal connections allocate no recorder.
package final class StartupTrace: @unchecked Sendable {
    package struct Event: Codable, Sendable {
        package let name: String
        package let elapsedMs: Double
        package let detail: String?
    }

    package let id = UUID().uuidString
    private var started: Double?
    private let lock = NSLock()
    private var events = [Event]()
    package static let capacity = 96

    package init() {}

    package func record(_ name: String, detail: String? = nil) {
        lock.lock(); defer { lock.unlock() }
        guard events.count < Self.capacity else { return }
        let now = ProcessInfo.processInfo.systemUptime
        if started == nil { started = now }
        events.append(Event(name: String(name.prefix(64)),
                            elapsedMs: (now - started!) * 1000,
                            detail: detail.map { String($0.prefix(128)) }))
    }

    package func snapshot() -> [Event] {
        lock.lock(); defer { lock.unlock() }
        return events
    }
}