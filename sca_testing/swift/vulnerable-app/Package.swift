// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "VulnerableApp",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "VulnerableApp",
            targets: ["VulnerableApp"]),
    ],
    dependencies: [
        // Vulnerable packages with known security issues

        // Alamofire - older version with vulnerabilities
        .package(url: "https://github.com/Alamofire/Alamofire.git", from: "4.9.0"), // Has CVE-2019-8331

        // SwiftyJSON - older version with parsing vulnerabilities
        .package(url: "https://github.com/SwiftyJSON/SwiftyJSON.git", from: "4.0.0"),

        // Kingfisher - older version with image loading vulnerabilities
        .package(url: "https://github.com/onevcat/Kingfisher.git", from: "5.0.0"),

        // Realm - older version with data corruption issues
        .package(url: "https://github.com/realm/realm-swift.git", from: "5.0.0"),

        // SnapKit - older version (less critical but for testing)
        .package(url: "https://github.com/SnapKit/SnapKit.git", from: "4.0.0"),

        // RxSwift - older version with memory leak issues
        .package(url: "https://github.com/ReactiveX/RxSwift.git", from: "5.0.0"),

        // Healthy packages (recent stable versions)

        // SwiftLint - recent stable version
        .package(url: "https://github.com/realm/SwiftLint.git", from: "0.50.0"),

        // Vapor - recent stable version
        .package(url: "https://github.com/vapor/vapor.git", from: "4.70.0"),

        // AsyncHTTPClient - recent stable version
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.15.0"),

        // Swift Argument Parser - recent stable version
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.2.0"),

        // Swift Log - recent stable version
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),

        // Swift Crypto - recent stable version
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.5.0"),
    ],
    targets: [
        .target(
            name: "VulnerableApp",
            dependencies: [
                "Alamofire",
                "SwiftyJSON",
                "Kingfisher",
                .product(name: "RealmSwift", package: "realm-swift"),
                "SnapKit",
                "RxSwift",
                .product(name: "SwiftLintFramework", package: "SwiftLint"),
                .product(name: "Vapor", package: "vapor"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]),
        .testTarget(
            name: "VulnerableAppTests",
            dependencies: ["VulnerableApp"]),
    ]
)
