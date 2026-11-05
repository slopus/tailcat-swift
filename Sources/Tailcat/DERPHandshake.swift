import Foundation

/// Existing DERP TLS metadata and authentication framing; no cached session state.
enum DERPHandshake {
    static func metadataServerKey(commonName: String, serialNumber: Data) -> Data? {
        // The serial is a positive, one-byte protocol version encoded as an
        // ASN.1 INTEGER (a leading zero is needed for versions 128...255).
        let serial = Array(serialNumber)
        let validVersion = serial.count == 1 && serial[0] > 0 && serial[0] < 128 ||
            serial.count == 2 && serial[0] == 0 && serial[1] >= 128
        guard validVersion, commonName.count == 71, commonName.hasPrefix("derpkey"),
              let key = Data(tailcatHex: String(commonName.dropFirst(7))), key.count == 32,
              key.contains(where: { $0 != 0 }) else { return nil }
        return key
    }

    static func serverKey(greeting: Data, expected: Data? = nil) throws -> Data {
        guard greeting.count >= 40, greeting.count <= 1024,
              greeting.prefix(8) == Data("DERP🔑".utf8) else { throw TransportError.malformedPacket }
        let key = Data(greeting.dropFirst(8).prefix(32))
        guard expected == nil || expected == key else {
            throw TransportError.connectionFailed("DERP TLS metadata key mismatch")
        }
        return key
    }

    static func clientInfo(privateKey: Data, serverKey: Data) throws -> Data {
        let nonce = NaClBox.random(24)
        let info = Data("{\"version\":2,\"CanAckPings\":true}".utf8)
        let auth = try NaClBox.publicKey(for: privateKey) + nonce +
            NaClBox.seal(info, nonce: nonce, publicKey: serverKey, privateKey: privateKey)
        return try DERPFrame.encode(type: 2, payload: auth)
    }
}