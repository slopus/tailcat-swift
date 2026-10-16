import XCTest
@testable import Tailcat

final class AddressTests: XCTestCase {
    func testIndependentUpstreamAddressAndIdentity() throws {
        let key = try NodePrivateKey(rawValue: XCTUnwrap(Data(tailcatHex: "0002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f60")))
        XCTAssertEqual(try key.publicKey.rawValue.tailcatHex, "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c")
        XCTAssertEqual(try key.discoPublicKey.tailcatHex, "0b625209067cf41fd90fedfc16dfd17c5b02cbd02aa5a8597b5e7faea9035063")
        let psk = try PresharedKey(rawValue: Data((0..<32).map { 255 - UInt8($0) }))
        let address = try TailcatAddress(serverPublicKey: key.publicKey, serverDiscoPublicKey: key.discoPublicKey, presharedKey: psk, regionID: 302)
        let golden = "tcpGFwWCAHo3y8FCCTyLdV3BsQ6Gy0JjdK0WqoU-0L38CyuG0cfGFrWCALYlIJBnz0H9kP7fwW39F8WwLL0CqlqFl7Xn-uqQNQY2FxWCD__v38-_r5-Pf29fTz8vHw7-7t7Ovq6ejn5uXk4-Lh4GFpGQEu"
        XCTAssertEqual(address.description, golden)
        XCTAssertEqual(try TailcatAddress(golden), address)
        XCTAssertEqual(try key.publicKey.address.tailcatHex, "fd7a115ca1e007a37cbc142093c8b755")
    }

    func testEmbeddedAddressRestoresElidedFields() throws {
        let key = try NodePublicKey(rawValue: Data(repeating: 1, count: 32))
        let region = DERPRegion(regionID: 302, regionCode: "x", regionName: "Name", nodes: [DERPNode(name: "redundant", regionID: 302, hostName: "relay.example", certName: "certificate.example", ipv4: "192.0.2.1", stunPort: -1, derpPort: 8443)])
        let address = try TailcatAddress(serverPublicKey: key, regions: [region])
        let decoded = try TailcatAddress(address.description)
        XCTAssertEqual(decoded.regions[0].regionID, 1)
        XCTAssertEqual(decoded.regions[0].regionCode, "1")
        XCTAssertEqual(decoded.regions[0].nodes[0].name, "relay.example")
        XCTAssertEqual(decoded.regions[0].nodes[0].certName, "certificate.example")
        XCTAssertEqual(decoded.regions[0].nodes[0].stunPort, -1)
        XCTAssertEqual(decoded.regions[0].nodes[0].regionID, 1)
        XCTAssertEqual(decoded.description, address.description)
    }

    func testMalformedCBORAndAddressRejection() throws {
        let invalid: [Data] = [Data([0xa1, 0x61, 0x70, 0x58, 0x20]), Data([0xbf]), Data([0xa2, 0x61, 0x70, 0xf6, 0x61, 0x70, 0xf6]), Data([0x61, 0xff]), Data([0x00, 0x00])]
        for data in invalid { XCTAssertThrowsError(try CBOR.decode(data)) }
        XCTAssertThrowsError(try TailcatAddress("not-a-tailcat-address"))
        XCTAssertThrowsError(try TailcatAddress("tc===="))
        let nullRegion = CBOR.map([("p", .bytes(Data(repeating: 1, count: 32))), ("r", .array([.null]))]).encode()
        XCTAssertThrowsError(try TailcatAddress("tc" + nullRegion.base64EncodedString().replacingOccurrences(of: "=", with: "")))
        for size in [0, 1, 31, 33, 256] { XCTAssertThrowsError(try NodePublicKey(rawValue: Data(repeating: 0, count: size))) }
    }
}