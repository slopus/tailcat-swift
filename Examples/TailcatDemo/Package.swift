// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "TailcatDemo",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "TailcatDemo", targets: ["TailcatDemo"])],
    dependencies: [.package(name: "tailcat-swift", path: "../..")],
    targets: [.target(name: "TailcatDemo", dependencies: [.product(name: "Tailcat", package: "tailcat-swift")])]
)