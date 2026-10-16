# Protocol and compatibility

Reference: tailscale/tailcat commit `52fbad323e9d352f1febb623e0975368e9a8cbdd`.
The implementation is native Swift and has no third-party package dependencies.

| Upstream component | Swift implementation and behavior |
| --- | --- |
| `wire.go`, `ConnInfo`, `Addr` | Bounded CBOR and unpadded base64url with `tc` prefix; fields `p`, `k`, `q`, `r`, `i`; embedded node fields and elided IDs/names restored |
| Node and discovery keys | Curve25519; discovery private key derived with HMAC-SHA256 over `github.com/tailscale/tailcat disco key v1`, then clamped; IPv6 is `fd7a:115c:a1e0::/48` plus the first ten node-public-key bytes |
| DERP map expansion | Embedded/custom regions, region ID lookup, automatic HTTPS-latency selection with fallback; configurable map URL and cache, one-hour freshness, ETag and stale fallback |
| DERP | TLS HTTP upgrade, authenticated NaCl client/server info, bounded frame codec, ping/pong, keepalive, restart and peer-gone frames, token bucket, reconnect and region-node failover |
| Bootstrap | Raw `meow` ping and `meowed` acknowledgement always travel over DERP; advertised identity must match the authenticated relay source; zero discovery keys rejected |
| Discovery | `TS💬` wrapper and NaCl box; ping/pong transaction correlation, relay-bound CallMeMaybe, IPv4/IPv6 endpoint exchange, STUN XOR-mapped addresses, periodic probes and relay fallback |
| WireGuard | Noise IKpsk2, BLAKE2s, Curve25519, ChaCha20-Poly1305, MAC1/MAC2, XChaCha cookie replies, TAI64N replay checks, overlapping current/previous/next keypairs, 8,192-packet replay window, rekey and persistent keepalive |
| IPv6 | Tunnel MTU 1,280, validated transport checksums and destination; server binds every decrypted client source IP to its authenticated node key; forwarding responses remain bound to the server's WireGuard identity |
| TCP | Client/server handshake, accept, byte streams, segmentation/MSS, retransmission and congestion window, ordering, duplicate suppression, receive windows, zero-window probes, FIN/EOF, graceful close, drain, cancellation |
| UDP | Connected client sockets and per-source accepted flows, maximum 1,232-byte payload, empty datagrams, bounded queues, configurable incoming idle timeout |
| Library services | Explicit and ephemeral-port listeners, per-flow callbacks, per-key asynchronous admission, disconnect, TCP/UDP peer attribution, served-port filtering, IPv4 NAT64 and IPv6 target forwarding, stream proxy helper |

Apple builds use SDK CryptoKit for Curve25519, SHA-256/HMAC, and ChaCha20-Poly1305.
BLAKE2s and XSalsa20-Poly1305 are Swift implementations. Portable Swift primitives let the
same protocol state machines run in Linux tests. System POSIX socket interfaces provide
UDP; Network.framework provides production DERP TLS. Neither Go nor external crypto
libraries are part of the package.

The server admits up to 1,024 peer identities, including at most 128 pending tunnel
authentications. Pending entries rotate oldest first and expire after 30 seconds, so
public meow packets cannot permanently occupy admission capacity. Up to 128 admission
hooks run concurrently, one per identity. Established peers without authenticated
traffic expire after five minutes; connected peers refresh this with 25-second keepalives.

UDP ingress is bounded before actor delivery: 256 datagrams of at most 2,048 bytes, with
one consumer. Discovery keeps at most 128 endpoints per peer and expires authenticated
inbound bindings after two minutes. WireGuard authenticates every delivered datagram,
including when an endpoint matches more than one configured identity. Other queue bounds
include 128 pending accepts, 256 queued UDP datagrams/flow, and 256 KiB pending tunnel
data/peer. Each IP stack admits up to 1,024 TCP states. Forwarding is bounded to 128 target
IP stacks and 256 automatic service listeners; inactive targets with no TCP states are
reclaimed after five minutes (or the configured UDP timeout, if longer).

TCP negotiates an ordinary unscaled receive window and MSS. SACK and timestamps are not
advertised. IPv6 extension parsing is bounded; non-atomic fragments are not reassembled.
The 1,280-byte MTU and TCP MSS avoid fragmentation for supported writes. NAT port-mapping
protocols such as UPnP/PCP are not implemented; DERP remains available where endpoint
exchange and UDP probes cannot establish a direct route. Hostname resolution belongs to
the embedding app. Public DERP relays are subject to upstream's terms and availability.

Verification includes RFC crypto vectors, independently generated upstream address/NaCl
fixtures, both WireGuard handshake roles and cookie/replay/rekey cases, multi-megabyte TCP
streams, dropped SYN/SYN-ACK/data/ACK/FIN, duplicate and reordered segments, lost window
updates, zero windows, graceful close and reset, empty/max-size UDP, stalled-start
cancellation, policy changes between flows, forwarding, and slow admission isolation.
Opt-in relay tests exercise authenticated DERP, node failover, asymmetric IPv4/IPv6 direct
paths and fallback. `InteropTests` can run against an independent upstream echo peer:

```sh
TAILCAT_UPSTREAM_ADDRESS='tc…' swift test --build-system native --filter InteropTests.testUpstreamEcho
```

Linux's test-only DERP backend requires `insecureForTests` and a loopback destination;
it never enables production plaintext relay connections. The upstream echo fixture and
reference generators are verification tools, excluded from the Swift package and Git.
Apple runtime behavior still requires an actual iOS/macOS device; xtool cross-builds
validate Apple SDK compilation and package the SwiftUI embedding example on Linux.

Validation on Linux with Swift 6.4.1 and xtool's Darwin SDK:

| Check | Result |
| --- | --- |
| Complete native suite with live relay/upstream peer enabled | 52 tests discovered, 51 passed, 1 skipped dedicated long-running server fixture, zero failures |
| Swift client to independent upstream server | 256 KiB TCP with FIN/EOF, UDP 1/31/1,232 bytes passed |
| Independent upstream client to Swift server | 2 MiB TCP with FIN/EOF, UDP 1/31/1,232 bytes, direct discovery passed |
| Shared-peer concurrency | Four simultaneous TCP streams of 256 KiB with FIN and eight 1,232-byte UDP datagrams passed |
| Malformed discovery isolation | Valid control before and after, advertised-node mismatch rejection, zero-discovery-key rejection passed; fresh-peer TCP/UDP/direct transfer after probes passed |
| Apple compilation | `arm64-apple-ios` and `arm64-apple-macosx` library cross-builds passed |
| SwiftUI embedding | `xtool dev build` packaged the local-library example as `TailcatDemo.app` |

The dedicated server fixture ran separately for independent tests and was stopped after
verification. No Apple device or simulator runtime was used for these final checks.