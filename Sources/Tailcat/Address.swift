// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
import Foundation

public struct DERPNode: Codable, Sendable, Equatable {
    public var name: String
    public var regionID: Int
    public var hostName: String
    public var certName: String
    public var ipv4: String
    public var ipv6: String
    public var stunPort: Int
    public var derpPort: Int
    public var insecureForTests: Bool
    public var stunOnly: Bool
    public init(name: String = "", regionID: Int = 0, hostName: String, certName: String = "", ipv4: String = "", ipv6: String = "", stunPort: Int = 0, derpPort: Int = 0, insecureForTests: Bool = false, stunOnly: Bool = false) {
        self.name = name; self.regionID = regionID; self.hostName = hostName; self.certName = certName
        self.ipv4 = ipv4; self.ipv6 = ipv6; self.stunPort = stunPort; self.derpPort = derpPort
        self.insecureForTests = insecureForTests; self.stunOnly = stunOnly
    }
    enum CodingKeys: String, CodingKey {
        case name = "Name", regionID = "RegionID", hostName = "HostName", certName = "CertName", ipv4 = "IPv4", ipv6 = "IPv6", stunPort = "STUNPort", derpPort = "DERPPort", insecureForTests = "InsecureForTests", stunOnly = "STUNOnly"
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(name: try c.decodeIfPresent(String.self, forKey: .name) ?? "", regionID: try c.decodeIfPresent(Int.self, forKey: .regionID) ?? 0, hostName: try c.decodeIfPresent(String.self, forKey: .hostName) ?? "", certName: try c.decodeIfPresent(String.self, forKey: .certName) ?? "", ipv4: try c.decodeIfPresent(String.self, forKey: .ipv4) ?? "", ipv6: try c.decodeIfPresent(String.self, forKey: .ipv6) ?? "", stunPort: try c.decodeIfPresent(Int.self, forKey: .stunPort) ?? 0, derpPort: try c.decodeIfPresent(Int.self, forKey: .derpPort) ?? 0, insecureForTests: try c.decodeIfPresent(Bool.self, forKey: .insecureForTests) ?? false, stunOnly: try c.decodeIfPresent(Bool.self, forKey: .stunOnly) ?? false)
    }
}

public struct DERPRegion: Codable, Sendable, Equatable {
    public var regionID: Int
    public var regionCode: String
    public var regionName: String
    public var nodes: [DERPNode]
    public init(regionID: Int, regionCode: String = "", regionName: String = "", nodes: [DERPNode]) {
        self.regionID = regionID; self.regionCode = regionCode; self.regionName = regionName; self.nodes = nodes
    }
    enum CodingKeys: String, CodingKey { case regionID = "RegionID", regionCode = "RegionCode", regionName = "RegionName", nodes = "Nodes" }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(regionID: try c.decode(Int.self, forKey: .regionID), regionCode: try c.decodeIfPresent(String.self, forKey: .regionCode) ?? "", regionName: try c.decodeIfPresent(String.self, forKey: .regionName) ?? "", nodes: try c.decodeIfPresent([DERPNode].self, forKey: .nodes) ?? [])
    }
}

/// Contains the server identity, discovery key, PSK, and relay. Treat it as a secret.
public struct TailcatAddress: Sendable, Equatable, CustomStringConvertible, Codable {
    public var serverPublicKey: NodePublicKey
    public var serverDiscoPublicKey: Data?
    public var presharedKey: PresharedKey?
    public var regions: [DERPRegion]
    public var regionID: Int
    public init(serverPublicKey: NodePublicKey, serverDiscoPublicKey: Data? = nil, presharedKey: PresharedKey? = nil, regions: [DERPRegion] = [], regionID: Int = 0) throws {
        if let k = serverDiscoPublicKey, k.count != 32 { throw TailcatError.invalidKey }
        self.serverPublicKey = serverPublicKey; self.serverDiscoPublicKey = serverDiscoPublicKey
        self.presharedKey = presharedKey; self.regions = regions; self.regionID = regionID
    }
    public init(_ text: String) throws {
        guard text.hasPrefix("tc"), text.count <= 90_000 else { throw TailcatError.invalidAddress("expected tc prefix") }
        var base64 = String(text.dropFirst(2))
        guard base64.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else { throw TailcatError.invalidAddress("invalid base64url") }
        base64 = base64.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64), let map = try CBOR.decode(data).dictionary, let key = map["p"]?.bytes else { throw TailcatError.invalidAddress("missing node public key") }
        serverPublicKey = try NodePublicKey(rawValue: key)
        serverDiscoPublicKey = nil; presharedKey = nil; regions = []; regionID = 0
        if let v = map["k"] { guard let b = v.bytes, b.count == 32 else { throw TailcatError.invalidKey }; serverDiscoPublicKey = b }
        if let v = map["q"] { guard let b = v.bytes else { throw TailcatError.invalidKey }; presharedKey = try PresharedKey(rawValue: b) }
        if let v = map["i"] { guard let id = v.integer else { throw TailcatError.invalidAddress("invalid region ID") }; regionID = id }
        if let v = map["r"] {
            guard let list = v.array else { throw TailcatError.invalidAddress("invalid regions") }
            for (index, item) in list.enumerated() {
                guard let r = item.dictionary else { throw TailcatError.invalidAddress("null or invalid region") }
                let rawID = r["i"]?.integer ?? 0; let id = rawID == 0 ? index + 1 : rawID
                var nodes: [DERPNode] = []
                if let value = r["N"] {
                    guard let entries = value.array else { throw TailcatError.invalidAddress("invalid nodes") }
                    for entry in entries {
                        guard let n = entry.dictionary else { throw TailcatError.invalidAddress("null or invalid node") }
                        let host = n["h"]?.text ?? ""
                        let nodeID = n["i"]?.integer ?? 0
                        nodes.append(DERPNode(name: n["n"]?.text ?? host, regionID: nodeID == 0 ? id : nodeID, hostName: host, certName: n["t"]?.text ?? "", ipv4: n["4"]?.text ?? "", ipv6: n["6"]?.text ?? "", stunPort: n["s"]?.integer ?? 0, derpPort: n["d"]?.integer ?? 0, insecureForTests: n["x"]?.bool ?? false))
                    }
                }
                regions.append(DERPRegion(regionID: id, regionCode: r["c"]?.text ?? String(id), regionName: r["m"]?.text ?? "", nodes: nodes))
            }
        }
    }
    public var description: String {
        var fields: [(String, CBOR)] = [("p", .bytes(serverPublicKey.rawValue))]
        if let k = serverDiscoPublicKey, k.contains(where: { $0 != 0 }) { fields.append(("k", .bytes(k))) }
        if let k = presharedKey, !k.isZero { fields.append(("q", .bytes(k.rawValue))) }
        if !regions.isEmpty {
            let rs = regions.map { region -> CBOR in
                let nodes = region.nodes.filter { !$0.stunOnly }.map { node -> CBOR in
                    var n: [(String, CBOR)] = []
                    if node.hostName.isEmpty && !node.name.isEmpty { n.append(("n", .text(node.name))) }
                    if !node.hostName.isEmpty { n.append(("h", .text(node.hostName))) }
                    if !node.certName.isEmpty { n.append(("t", .text(node.certName))) }
                    if !node.ipv4.isEmpty { n.append(("4", .text(node.ipv4))) }
                    if !node.ipv6.isEmpty { n.append(("6", .text(node.ipv6))) }
                    if node.stunPort != 0 { n.append(("s", .integer(Int64(node.stunPort)))) }
                    if node.derpPort != 0 { n.append(("d", .integer(Int64(node.derpPort)))) }
                    if node.insecureForTests { n.append(("x", .bool(true))) }
                    return .map(n)
                }
                return .map(nodes.isEmpty ? [] : [("N", .array(nodes))])
            }
            fields.append(("r", .array(rs)))
        }
        if regionID != 0 { fields.append(("i", .integer(Int64(regionID)))) }
        return "tc" + CBOR.map(fields).encode().base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    public init(from decoder: Decoder) throws { try self.init(decoder.singleValueContainer().decode(String.self)) }
    public func encode(to encoder: Encoder) throws { var c = encoder.singleValueContainer(); try c.encode(description) }
}