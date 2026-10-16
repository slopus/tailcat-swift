import XCTest
@testable import Tailcat

final class DERPMapTests: XCTestCase {
    private let json = Data("""
    {"Regions":{"7":{"RegionID":7,"RegionCode":"test","Nodes":[
      {"HostName":"one.example"},{"HostName":"two.example"},{"HostName":"three.example"}
    ]}}}
    """.utf8)

    func testFreshCacheAvoidsNetworkAndResolvesCompactAddress() async throws {
        let url = try XCTUnwrap(URL(string: "unsupported://tailcat-map/fresh"))
        let cache = MemoryDERPMapCache()
        await cache.store(url: url, entry: DERPMapCacheEntry(data: json, etag: "opaque"))
        let key = try NodePublicKey(rawValue: Data(repeating: 1, count: 32))
        let address = try TailcatAddress(serverPublicKey: key, regionID: 7)
        let resolved = try await address.resolved(mapURL: url, cache: cache)
        XCTAssertEqual(resolved.regionID, 0)
        XCTAssertEqual(resolved.regions[0].nodes.map(\.hostName), ["one.example", "two.example"])
        let offline = try await resolved.expanded(mapURL: url, cache: MemoryDERPMapCache())
        XCTAssertEqual(offline, resolved)
    }

    func testStaleCacheSurvivesFetchFailureButMalformedCacheDoesNot() async throws {
        let url = try XCTUnwrap(URL(string: "unsupported://tailcat-map/stale"))
        let cache = MemoryDERPMapCache()
        await cache.store(url: url, entry: DERPMapCacheEntry(data: json, storedAt: Date().addingTimeInterval(-7200)))
        let map = try await DERPMap.fetch(url: url, cache: cache)
        XCTAssertEqual(map.regions[7]?.nodes.count, 3)
        await cache.store(url: url, entry: DERPMapCacheEntry(data: Data("invalid".utf8)))
        do { _ = try await DERPMap.fetch(url: url, cache: cache); XCTFail("malformed cache accepted") } catch {}
    }
}