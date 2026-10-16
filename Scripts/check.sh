#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
swift_bin="${TAILCAT_SWIFT:-swift}"
"$swift_bin" test --build-system native
"$swift_bin" build --build-system native --scratch-path .context/build-ios --swift-sdk darwin --triple arm64-apple-ios
"$swift_bin" build --build-system native --scratch-path .context/build-macos --swift-sdk darwin --triple arm64-apple-macosx