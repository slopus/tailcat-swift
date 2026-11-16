import XCTest
@testable import Tailcat

final class STUNTests: XCTestCase {
    private func hex(_ string: String) -> Data {
        let bytes = Array(string.utf8)
        return Data(stride(from: 0, to: bytes.count, by: 2).map {
            UInt8(String(bytes: bytes[$0..<($0 + 2)], encoding: .utf8)!, radix: 16)!
        })
    }

    func testTailscaleBindingRequest() throws {
        // Independently calculated with Python's zlib.crc32. The 20-byte
        // body includes SOFTWARE tailnode and the final XORed CRC-32.
        let transaction = hex("000102030405060708090a0b")
        let request = try STUN.request(transaction: transaction)
        XCTAssertEqual(request,
                       hex("000100142112a442000102030405060708090a0b802200087461696c6e6f6465802800048aabad90"))
        XCTAssertEqual(request.count, 40)
        XCTAssertEqual(Int(request[2]) * 256 + Int(request[3]), request.count - 20)
        XCTAssertThrowsError(try STUN.request(transaction: Data(repeating: 0, count: 11)))
        XCTAssertThrowsError(try STUN.request(transaction: Data(repeating: 0, count: 13)))
    }

    func testRFC5769IPv6Response() throws {
        // RFC 5769 section 2.3; IPv4 is covered by TransportTests' section 2.2 vector.
        let transaction = hex("b7e7a701bc34d686fa87dfae")
        let response = hex("010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf11784c97c8292c275bfe3ed4180280004c8fb0b4c")
        XCTAssertEqual(try STUN.response(response, transaction: transaction),
                       try DiscoveryEndpoint("[2001:db8:1234:5678:11:2233:4455:6677]:32853"))
        XCTAssertThrowsError(try STUN.response(response, transaction: Data(repeating: 0, count: 12)))
        XCTAssertThrowsError(try STUN.response(Data(response.dropLast()), transaction: transaction))
    }
}