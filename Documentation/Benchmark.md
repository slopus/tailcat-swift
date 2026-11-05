# Relay-first benchmark runner

Build the optimized native runner on macOS:

```sh
swift build --build-system native -c release --product tailcat-bench
.build/release/tailcat-bench --server --mode off --source mac
# The server prints a JSON ready record with its private Tailcat address.
.build/release/tailcat-bench --target 'tc…' --mode off --source mac --destination linux --attempt 1
```

Use `--mode on` on both endpoints for the opt-in comparison. Servers use fixed region
301 NYC, `tc301a.ipn.dev`, TLS 443/STUN 3478 from the normal DERP map. The server runs for
two hours by default (`--seconds` overrides it). Addresses contain bearer secrets; keep
raw readiness logs private. Production DERP TLS is supported on Apple platforms. The
Linux Swift backend is restricted to loopback test relays and is not a public-relay
benchmark endpoint.

The application protocol is raw TCP echo on port 8080, interoperable with the Kotlin
runner. Each client invocation emits two JSON samples: a new encrypted connection and
a new stream on the same still-connected client. The warm sample does not establish a
new relay connection. Timings use a monotonic clock; UTC timestamps identify runs.

Each sample records connection completion, first echoed byte from before connect (or
before opening the reused-client stream), full 32-byte echo time, initial/current route,
first observed validated direct route (20 ms polling, 15-second observation timeout),
20 sequential 32-byte RTTs, and a concurrent 256 KiB write/read with exact byte comparison.
Throughput is one echoed payload's byte count divided by total transfer duration, not
the sum of upload and download. A new-session sample also calls `notifyNetworkChanged()`
and sends ten numbered echoes on the same stream, recording recovery timings and route.
This safely tests package-level socket/relay recovery; it does not toggle host networking
or simulate an actual OS interface outage. A missing direct observation is censored, not
zero latency. Errors are retained in JSON and must not be dropped from summaries.
Recovery route observation starts independently immediately after notification; it is
not timed after the echo loop. `--trace` enables diagnostic route/socket metadata on
stderr; traced diagnostic trials should be kept separate from performance comparisons.

Run five fresh-client trials per directed pair and mode, alternating mode order where
practical. Report median and range, not a five-sample p95. Run measurements without
concurrent builds or tests and record endpoint load/runtime/configuration. Direct route
establishment during a trial is expected; warm and steady-state observations must retain
their actual path labels.

## Second independent client

Add `--second-independent` to a client invocation (also supported by the iPhone app).
This is a separate experiment from opening another TCP stream on an existing client.
It emits `cold_first_independent_client` and `warm_process_second_independent_client`,
both with `sessionReused=false`. The first client carries numbered echo traffic while
the second creates a new identity, WireGuard session, UDP socket and DERP connection
to the same server. Closing the second must leave the first client's stream usable.

Samples include `connectMs`, `firstEchoMs`, `handshakeToConnectReturnMs`, a random
`connectionTraceID`, and a bounded `events` array of `{name, elapsedMs, detail?}`.
Event times start at `connectStarted`; TCP and TLS are one combined Apple networking
phase, not separately measured handshakes. Details contain socket IDs or ports, never
keys, packet contents or tunnel addresses. The second row records distinct-identity
and socket checks, the count of first-client echoes during its connect, and
`firstSurvivedSecondClose`. Deferred UDP binding is observed for up to five seconds
after the startup timings; a missing observation remains absent rather than a success.
Candidate samples also include `pathAtFirstEcho` (`relay` or `direct`); older baseline
samples without this field have an unknown path.

The package-only recorder is opt-in to this mode; ordinary library users have no
recorder. Keep baseline executables and source archives immutable, interleave baseline
and candidate trials, and do not mix these rows with the default reused-client test.
This startup mode does not run the default long recovery/throughput stages.

## Physical iPhone runner

The `Examples/TailcatBenchApp` app shares the same benchmark implementation. Generate its
Xcode project with XcodeGen on the authorized Mac, then build Release with existing
development signing and deploy to the attached physical iPhone. Launch arguments match
the CLI (`--server` or `--target`, `--mode`, `--destination`, `--attempt`). Add a unique
`--run-id`; the app appends JSONL to `Documents/<run-id>.jsonl` and stdout, and emits a
`type=complete` marker when a client run finishes. Export the file with `devicectl device
copy from --domain-type appDataContainer --domain-identifier
dev.happy.tailcatbench.relayfirst`. Keep the app in the foreground while it serves or
benchmarks; it disables idle sleep during that foreground run. The app is development
tooling, not an App Store target.