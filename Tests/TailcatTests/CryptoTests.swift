import Foundation
import XCTest
@testable import Tailcat

final class CryptoTests: XCTestCase {
    private func hex(_ string: String) -> Data {
        let text = Array(string.filter { !$0.isWhitespace })
        return Data(stride(from: 0, to: text.count, by: 2).map { UInt8(String(text[$0...$0+1]), radix: 16)! })
    }

    func testSHA256AndHMACVectors() {
        XCTAssertEqual(TailcatCrypto.sha256(Data("abc".utf8)), hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
        XCTAssertEqual(TailcatCrypto.sha256(Data()), hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        XCTAssertEqual(TailcatCrypto.hmacSHA256(key: Data(repeating: 0x0b, count: 20), message: Data("Hi There".utf8)), hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))
        XCTAssertEqual(TailcatCrypto.hmacSHA256(key: Data(repeating: 0xaa, count: 131), message: Data("Test Using Larger Than Block-Size Key - Hash Key First".utf8)), hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"))
    }

    func testBlake2sVectors() {
        XCTAssertEqual(TailcatCrypto.blake2s(Data()), hex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"))
        XCTAssertEqual(TailcatCrypto.blake2s(Data("abc".utf8)), hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"))
        // Official BLAKE2s keyed KAT: key 00..1f, message 00..02.
        XCTAssertEqual(TailcatCrypto.blake2s(Data([0,1,2]), key: Data(0..<32)), hex("1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b"))
        // Python hashlib reference for parameterized 128-bit digest, not a prefix.
        XCTAssertEqual(TailcatCrypto.blake2s(Data("abc".utf8), key: Data(0..<32), digestLength: 16), hex("61ba5f165c194692e09d12520cc4c74a"))
    }

    func testX25519RFC7748() throws {
        let alicePrivate = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let alicePublic = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        let bobPrivate = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let bobPublic = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        XCTAssertEqual(try TailcatCrypto.publicKey(privateKey: alicePrivate), alicePublic)
        XCTAssertEqual(try TailcatCrypto.publicKey(privateKey: bobPrivate), bobPublic)
        let shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        XCTAssertEqual(try TailcatCrypto.sharedSecret(privateKey: alicePrivate, publicKey: bobPublic), shared)
        XCTAssertEqual(try TailcatCrypto.sharedSecret(privateKey: bobPrivate, publicKey: alicePublic), shared)
        XCTAssertThrowsError(try TailcatCrypto.sharedSecret(privateKey: alicePrivate, publicKey: Data(repeating: 0, count: 32)))
        XCTAssertThrowsError(try TailcatCrypto.sharedSecret(privateKey: alicePrivate, publicKey: Data([1] + [UInt8](repeating: 0, count: 31))))
        XCTAssertThrowsError(try TailcatCrypto.publicKey(privateKey: Data()))
    }

    func testChaCha20Poly1305RFC8439() throws {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        let nonce = hex("070000004041424344454647"), aad = hex("50515253c0c1c2c3c4c5c6c7")
        let plaintext = Data("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        let expected = hex("""
            d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
            3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
            92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3
            ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691
            """)
        XCTAssertEqual(try TailcatCrypto.seal(plaintext, key: key, nonce: nonce, authenticating: aad), expected)
        XCTAssertEqual(try TailcatCrypto.open(expected, key: key, nonce: nonce, authenticating: aad), plaintext)
        var corrupted = expected; corrupted[0] ^= 1
        XCTAssertThrowsError(try TailcatCrypto.open(corrupted, key: key, nonce: nonce, authenticating: aad))
        XCTAssertThrowsError(try TailcatCrypto.open(expected, key: key, nonce: nonce, authenticating: Data()))
        let empty = try TailcatCrypto.seal(Data(), key: key, nonce: nonce)
        XCTAssertEqual(try TailcatCrypto.open(empty, key: key, nonce: nonce), Data())
    }

    func testXChaChaDraftVector() throws {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        let nonce = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
        let aad = hex("50515253c0c1c2c3c4c5c6c7")
        let plaintext = Data("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        let expected = hex("""
            bd6d179d3e83d43b9576579493c0e939 572a1700252bfaccbed2902c21396cbb
            731c7f1b0b4aa6440bf3a82f4eda7e39 ae64c6708c54c216cb96b72e1213b452
            2f8c9ba40db5d945b11b69b982c1bb9e 3f3fac2bc369488f76b2383565d3fff9
            21f9664c97637da9768812f615c68b13 b52e
            c0875924c1c7987947deafd8780acf49
            """)
        XCTAssertEqual(try TailcatCrypto.xSeal(plaintext, key: key, nonce: nonce, authenticating: aad), expected)
        XCTAssertEqual(try TailcatCrypto.xOpen(expected, key: key, nonce: nonce, authenticating: aad), plaintext)
    }
}