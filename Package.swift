// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "tailcat-swift",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "Tailcat", targets: ["Tailcat"]),
        .library(name: "TailcatBenchmark", targets: ["TailcatBenchmark"]),
        .executable(name: "tailcat-bench", targets: ["TailcatBench"])
    ],
    targets: [
        .target(name: "Tailcat"),
        .target(name: "TailcatBenchmark", dependencies: ["Tailcat"]),
        .executableTarget(name: "TailcatBench", dependencies: ["TailcatBenchmark"]),
        .testTarget(name: "TailcatTests", dependencies: ["Tailcat"])
    ]
)