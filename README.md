# tailcat-swift

A direct port of [tailscale/tailcat](https://github.com/tailscale/tailcat) to Swift.

The goal is to embed tailcat directly in iOS and macOS apps. It is meant to be used as a
library that works like a TCP socket: an app opens a connection and reads and writes bytes on it.
The port is pure Swift with no third-party dependencies, so it can be added to an app without
extra packages or binaries.

This project follows the upstream design and behavior as closely as possible. See the original
repository for background and protocol details.

The `Tailcat` Swift package targets iOS 15+ and macOS 12+. It contains the address codec,
DERP client, discovery and STUN, WireGuard, and a userspace IPv6 TCP/UDP stack. Apple builds
use system CryptoKit and Network frameworks. There is no Go runtime, C bridge, binary
dependency, external package, Tailscale account, or VPN entitlement.

Add this repository as a Swift Package dependency and select the `Tailcat` product. The
[SwiftUI example](Examples/TailcatDemo) embeds the local package and builds on Linux with xtool.

From an async context, start a server and share its address privately:

```swift
import Tailcat

let server = TailcatServer()
let listener = try await server.listen(port: 8080)
let address = try await server.address
// Share address.description with the other app.

let stream = try await listener.accept()
let request = try await stream.read()
try await stream.write(request)
try await stream.closeWrite()
await stream.close()
await server.close()
```

The client connects once and can open multiple independent streams:

```swift
let client = try await TailcatClient.connect(to: address)
let stream = try await client.openTCP(port: 8080)
try await stream.write(Data("hello".utf8))
try await stream.closeWrite()
var response = Data()
while true {
    let bytes = try await stream.read()
    if bytes.isEmpty { break } // TCP EOF
    response.append(bytes)
}
await stream.close()
await client.close()
```

`read` returns available bytes and suspends when none are available. Writes apply backpressure
until acknowledged. `drain()` waits for pending writes without sending FIN; `closeWrite()`
waits for FIN acknowledgement while keeping reads open. `close()` finishes queued writes
and closes the local stream; server/client shutdown closes all owned sockets and wakes
pending operations. Cancel a Swift task to cancel its pending read, write, accept, or connect.
Explicitly close servers, clients, and listeners when their owning app feature ends.

For datagrams, use `server.listenUDP(port:)`, `listener.accept()`, and
`client.openUDP(port:)`. Each accepted UDP connection identifies one client source IP and
port. `read()` and `write(_:)` preserve boundaries; an empty `Data` is a valid datagram.
The maximum payload is 1,232 bytes. Incoming flows expire after two minutes of inactivity,
configurable with `udpIdleTimeout`; the listening socket remains available.

Configure a stable `NodePrivateKey`, a custom `DERPRegion`, `allowClient`, or service callbacks
through `TailcatServer.Configuration` before startup. A new random PSK is enabled by default;
addresses containing it are bearer secrets. Persist the private key and PSK in app storage
to retain the same address identity across launches. `disablePresharedKey` supports legacy
peers. Addresses without a discovery public key parse, but cannot connect to current peers.

`KeySet` provides a concurrent allow-list. Admission hooks run independently for each new
identity. Removing a key affects future admissions; call `disconnectClient` to revoke an
existing peer too. `peerKey(for:)` attributes both TCP streams and UDP flows to their
authenticated node identity. Explicit listeners take precedence over `onTCP` / `onUDP`;
callback selectors run for every new flow.

`client.openTCP(to:)` and `openUDP(to:)` accept a `TailcatEndpoint` for forwarding through
the server. IPv4 uses upstream's `64:ff9b::/96` mapping. Configure `onTCPForward` /
`onUDPForward` handlers on the server to implement the destination service or proxy;
`allowProxy` can restrict targets. Endpoint APIs take IP addresses; resolve hostnames in
the app. `proxyConnections` copies two Tailcat streams while preserving half-close.

DERP bootstraps discovery and remains available when UDP cannot connect. The transport
authenticates discovered endpoint bindings independently of its selected outgoing path.
Apple network-path changes refresh discovery automatically; `resetNetworkPaths()` also
lets an app request an immediate return to relay. `client.path` and `server.path(to:)`
report the current route. DERP reconnects and tries alternate nodes in the advertised
region. `TailcatAddress.resolved()` embeds relay details; compact addresses use a fetched
DERP map with one-hour caching, ETag revalidation, and stale-cache fallback.

Run native protocol tests on Linux or macOS:

```sh
swift test --build-system native
```

With xtool's Darwin SDK installed, build Apple targets entirely on Linux:

```sh
swift build --build-system native --swift-sdk darwin --triple arm64-apple-ios
swift build --build-system native --swift-sdk darwin --triple arm64-apple-macosx
cd Examples/TailcatDemo
xtool dev build
```

[Protocol notes](Documentation/Protocol.md) describe the upstream inventory, verification,
resource limits, and differences. Linux executes the portable crypto, protocol state
machines, and a restricted loopback relay backend for interoperability tests. Production
TLS networking targets Apple platforms. Linux cross-builds prove compilation and app
packaging; they do not execute an Apple OS runtime.

This port covers the embeddable networking library. The upstream CLI's SSH/SFTP, file
browser, command execution, SOCKS command, and web/WASM packaging are outside this package.
Like upstream, this project makes no API or wire-format stability promise.

## License

BSD 3-Clause, the same license as upstream tailcat. See [LICENSE](LICENSE), which keeps the
original Tailscale copyright notice.
