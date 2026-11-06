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

### Optional relay-first connections

Set `relayFirst` on either or both peers to establish the encrypted session over DERP
without waiting for UDP binding, interface enumeration, or STUN discovery. The default
remains `false`; peers using either setting interoperate without a wire-format change.

```swift
var serverOptions = TailcatServer.Configuration()
serverOptions.relayFirst = true
let server = TailcatServer(configuration: serverOptions)
let listener = try await server.listen(port: 8080)
let address = try await server.address

var clientOptions = TailcatClient.Configuration()
clientOptions.relayFirst = true
let client = try await TailcatClient.connect(to: address, configuration: clientOptions)
let stream = try await client.openTCP(port: 8080)

await client.retryDirect()                  // Background probe; keep the current route.
await server.retryDirect(to: client.publicKey) // Omit `to:` to probe all peers.
await client.notifyNetworkChanged()         // Discard stale routes and rebind/reconnect.
await server.notifyNetworkChanged()
// resetNetworkPaths() is an alias for notifyNetworkChanged().
```

When the app needs one tunnel to a known peer, it can retain a connected client and
reuse it for `openTCP` calls or keep a stream open.
The client keeps its DERP connection open, including while data uses direct UDP;
opening another stream does not reconnect to the relay. Close the client when the
app no longer needs that connection. There is no separate shared-node or relay-pool
API, and `relayFirst` does not eliminate initial TCP/TLS, relay authentication, or
WireGuard setup for a newly created client.

Apps that need independent relay connections can call `connect(to:)` again while the
first client is alive. Each call still owns its node/discovery identity (unless an
explicit private key is supplied), WireGuard session, UDP socket and DERP connection.
Do not supply the same private key to concurrently independent clients: their relay
identities would collide. There is no traffic pooling or shared encryption state.
Where a verified TLS 1.3 relay
advertises DERP fast start, the new socket sends its HTTP upgrade and fresh ClientInfo
together, removing a handshake round trip. The relay key is read from the peer certificates
while the TLS handshake waits for verification, so fast-start sockets skip TLS session
resumption (a resumed session carries no certificates). Older relays use the ordinary upgrade;
a failed fast-start attempt retries once on a fresh ordinary socket and disables fast
start for that transport. Client completion is signalled by authenticated WireGuard
establishment, without a 100 ms polling delay. These changes need no new public option
and preserve the `relayFirst` default and authentication rules.

The default benchmark's cold samples create a fresh client. Warm samples open a second TCP stream
on the existing client and WireGuard session. Both differ from message RTT on an
already-open stream, which does not include another TCP handshake. Use the benchmark's
`--second-independent` mode to measure a second separate client in the same process.

Client connection completion still requires an authenticated WireGuard session, not just
a relay socket. After initial encrypted confirmation, discovery can upgrade the same
session and open streams to UDP only after an authenticated, transaction-matched Pong.
`client.path` and `server.path(to:)` expose the selected route. Relay reception stays
active while direct is selected; a relay outage does not itself close a working direct
session. No API forces an unvalidated endpoint into service.

An authenticated changed endpoint announcement can retire an obsolete direct route.
After a local network reset, failed UDP send or expired selected route, an established
peer sends an encrypted empty WireGuard transport packet over DERP before further
application traffic. This existing keepalive format tells the peer to retire its old
route and revalidate, without waiting for STUN or a new endpoint announcement. Initial
handshake confirmations, unauthenticated packets and older reset-marker counters cannot
trigger that fallback. Ordinary relayed application packets do not demote a direct
route, so asymmetric promotion does not cause repeated path switching. Receiving a
reset hint does not send another hint back. This uses existing wire messages, not a
new packet type; peers without this recovery behavior simply process the keepalive.
Prompt one-sided return-route recovery requires an updated peer. An older library
still interoperates, but uses its existing discovery/liveness behavior after a reset;
it does not interpret the keepalive as a route-withdrawal notification.

Apple's `NWPathMonitor` automatically requests recovery when its path signature changes.
Apps can also call `notifyNetworkChanged()` after resume or network events the monitor
does not distinguish; non-Apple hosts must supply those notifications themselves. It
clears remote candidates, inbound endpoint bindings and pending probes, rebinds UDP,
reconnects DERP, and discovers fresh paths without replacing the WireGuard/IP-stack session.
`retryDirect()` only requests a probe and does not invalidate a healthy route. Repeated
requests coalesce; shutdown prevents late discovery results from installing routes.

UDP send errors immediately fall back to DERP. Silent loss falls back once the last
validated Pong is 30 seconds old; direct probes run about every 10 seconds, and ordinary
sends do not extend that deadline. Failed UDP setup retries on the five-second maintenance
tick. DERP reconnect uses exponential backoff capped at 30 seconds. A blocked OS lookup
can delay later direct discovery (only one discovery worker is retained), but not relay
traffic in relay-first mode. Startup still needs a usable relay and may need address-map
resolution; this is not an offline connection guarantee. TCP retransmission can bridge
brief route changes, but long outages can time out; UDP datagrams are not made reliable.

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
