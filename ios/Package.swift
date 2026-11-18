// swift-tools-version: 6.1
import PackageDescription
let package = Package(name: "PQMailCore", platforms: [.iOS(.v16), .macOS(.v13)], products: [.library(name: "PQMailCore", targets: ["PQMailCore"])], dependencies: [.package(url: "https://github.com/Yubico/yubikit-swift", revision: "e19212f2efbca9af280e57542e669885de5acdc1")], targets: [.binaryTarget(name: "CNative", path: "Frameworks/PQNative.xcframework"), .target(name: "PQMailCore", dependencies: ["CNative", .product(name: "YubiKit", package: "yubikit-swift")]), .testTarget(name: "PQMailCoreTests", dependencies: ["PQMailCore"])])
