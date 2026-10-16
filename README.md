# tailcat-swift

A direct port of [tailscale/tailcat](https://github.com/tailscale/tailcat) to Swift.

The goal is to embed tailcat directly in iOS and macOS apps. It is meant to be used as a
library that works like a TCP socket: an app opens a connection and reads and writes bytes on it.
The port is pure Swift with no third-party dependencies, so it can be added to an app without
extra packages or binaries.

This project follows the upstream design and behavior as closely as possible. See the original
repository for background and protocol details.

## License

BSD 3-Clause, the same license as upstream tailcat. See [LICENSE](LICENSE), which keeps the
original Tailscale copyright notice.
