// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct DERPMapCacheEntry: Sendable {
    public let data: Data
    public let etag: String
    public let storedAt: Date
    public init(data: Data, etag: String = "", storedAt: Date = Date()) { self.data = data; self.etag = etag; self.storedAt = storedAt }
}

public protocol DERPMapCache: Sendable {
    func load(url: URL) async -> DERPMapCacheEntry?
    func store(url: URL, entry: DERPMapCacheEntry) async throws
}

public actor MemoryDERPMapCache: DERPMapCache {
    public static let shared = MemoryDERPMapCache()
    private var entries: [URL: DERPMapCacheEntry] = [:]
    public init() {}
    public func load(url: URL) -> DERPMapCacheEntry? { entries[url] }
    public func store(url: URL, entry: DERPMapCacheEntry) { entries[url] = entry }
}

public struct DERPMap: Sendable, Decodable {
    public static let defaultURL = URL(string: "https://tailcat.dev/derpmap.json")!
    public var regions: [Int: DERPRegion]
    public init(regions: [Int: DERPRegion]) { self.regions = regions }
    private enum CodingKeys: String, CodingKey { case regions = "Regions" }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let map = try c.decode([String: DERPRegion].self, forKey: .regions)
        regions = [:]
        for (key, region) in map {
            guard let id = Int(key), id > 0, id == region.regionID else { throw TailcatError.invalidAddress("invalid DERP map region ID") }
            regions[id] = region
        }
    }
    /// Cache entries are fresh for one hour, then ETag-revalidated. Failed fetches use stale data.
    public static func fetch(url: URL = defaultURL, cache: any DERPMapCache = MemoryDERPMapCache.shared, forServer: Bool = false) async throws -> DERPMap {
        let cached = await cache.load(url: url)
        let cachedMap = cached.flatMap { try? JSONDecoder().decode(DERPMap.self, from: $0.data) }
        if let entry = cached, let map = cachedMap, Date().timeIntervalSince(entry.storedAt) < 3600 { return map }
        var request = URLRequest(url: url); request.timeoutInterval = 10
        request.setValue(forServer ? "server" : "client", forHTTPHeaderField: "Tailcat-Mode")
        if let etag = cached?.etag, !etag.isEmpty { request.setValue(etag, forHTTPHeaderField: "If-None-Match") }
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            try Task.checkCancellation()
            guard let http = response as? HTTPURLResponse else { throw TailcatError.noRelay }
            if http.statusCode == 304, let entry = cached, let map = cachedMap {
                try? await cache.store(url: url, entry: DERPMapCacheEntry(data: entry.data, etag: entry.etag))
                return map
            }
            guard http.statusCode == 200, data.count <= 4_194_304 else { throw TailcatError.noRelay }
            let map = try JSONDecoder().decode(DERPMap.self, from: data)
            guard !map.regions.isEmpty else { throw TailcatError.noRelay }
            try? await cache.store(url: url, entry: DERPMapCacheEntry(data: data, etag: http.value(forHTTPHeaderField: "ETag") ?? ""))
            return map
        } catch {
            try Task.checkCancellation()
            if let map = cachedMap { return map }
            throw error
        }
    }

    /// Select the first region to answer an HTTPS probe, bounding concurrent requests.
    public func nearestRegion() async throws -> DERPRegion {
        let candidates = regions.values.filter { $0.nodes.contains { !$0.stunOnly } }.sorted { $0.regionID < $1.regionID }
        guard !candidates.isEmpty else { throw TailcatError.noRelay }
        // Probe every region, with a short timeout. This deliberately avoids a control-plane dependency.
        return try await withThrowingTaskGroup(of: DERPRegion?.self) { group in
            for region in candidates {
                group.addTask {
                    guard let node = region.nodes.first(where: { !$0.stunOnly && !$0.hostName.isEmpty }),
                          var components = URLComponents(string: "https://\(node.hostName)/derp/latency-check") else { return nil }
                    if node.derpPort > 0 { components.port = node.derpPort }
                    guard let url = components.url else { return nil }
                    var request = URLRequest(url: url); request.timeoutInterval = 3; request.httpMethod = "HEAD"
                    do {
                        let (_, response) = try await URLSession.shared.data(for: request)
                        guard let http = response as? HTTPURLResponse, (200..<500).contains(http.statusCode) else { return nil }
                        return region
                    } catch { return nil }
                }
            }
            while let result = try await group.next() {
                if let region = result { group.cancelAll(); return region }
            }
            try Task.checkCancellation()
            return candidates[Int.random(in: candidates.indices)]
        }
    }
}

extension TailcatAddress {
    public func expanded(mapURL: URL = DERPMap.defaultURL, cache: any DERPMapCache = MemoryDERPMapCache.shared, forServer: Bool = false) async throws -> Self {
        if !regions.isEmpty {
            guard regions.count == 1, !regions[0].nodes.filter({ !$0.stunOnly }).isEmpty else { throw TailcatError.invalidAddress("exactly one usable region is required") }
            return self
        }
        guard regionID != 0 else { throw TailcatError.invalidAddress("missing region") }
        let map = try await DERPMap.fetch(url: mapURL, cache: cache, forServer: forServer)
        let region: DERPRegion
        if regionID == -1 { region = try await map.nearestRegion() }
        else if let found = map.regions[regionID] { region = found }
        else { throw TailcatError.noRelay }
        var result = self; result.regions = [region]; return result
    }
    /// Pin relay details so future connections require no DERP map fetch.
    public func resolved(mapURL: URL = DERPMap.defaultURL, cache: any DERPMapCache = MemoryDERPMapCache.shared) async throws -> Self {
        if !regions.isEmpty { return self }
        var result = try await expanded(mapURL: mapURL, cache: cache)
        result.regions[0].nodes = Array(result.regions[0].nodes.filter { !$0.stunOnly }.prefix(2)); result.regionID = 0
        return result
    }
}