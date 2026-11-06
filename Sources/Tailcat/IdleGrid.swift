// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation

/// Marks every 30 s of system uptime, shared by every client and relay in
/// the process. Idle upkeep (keepalives, rekeys, relay pings, housekeeping)
/// waits for the next mark, so a process with several clients wakes the
/// radio once per mark instead of once per client, each on its own phase.
internal enum IdleGrid {
    static let period: TimeInterval = 30
    /// How near after a mark still counts as at it: a one-second tick lands within it.
    static let width: TimeInterval = 1.5

    static func untilNextMark(now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> TimeInterval {
        period - now.truncatingRemainder(dividingBy: period) + 0.05
    }

    static func atMark(now: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        now.truncatingRemainder(dividingBy: period) < width
    }
}
