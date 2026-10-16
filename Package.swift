// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "tailcat-swift",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [.library(name: "Tailcat", targets: ["Tailcat"])],
    targets: [
        .target(name: "Tailcat"),
        .testTarget(name: "TailcatTests", dependencies: ["Tailcat"])
    ]
)