// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "LanguageGauntlet",
    platforms: [.macOS(.v12)],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),
    ],
    targets: [
        .target(
            name: "Domain",
            path: "Sources/LanguageGauntlet/Domain"
        ),
        .target(
            name: "Runtime",
            path: "Sources/LanguageGauntlet/Runtime"
        ),
        .target(
            name: "Storage",
            dependencies: ["Domain", "Runtime"],
            path: "Sources/LanguageGauntlet/Storage"
        ),
        .target(
            name: "Pipeline",
            dependencies: ["Domain", "Storage"],
            path: "Sources/LanguageGauntlet/Pipeline"
        ),
        .target(
            name: "Routing",
            dependencies: ["Domain"],
            path: "Sources/LanguageGauntlet/Routing"
        ),
        .executableTarget(
            name: "LanguageGauntlet",
            dependencies: [
                "Domain",
                "Pipeline",
                "Routing",
                .product(name: "Vapor", package: "vapor"),
            ],
            path: "Sources/LanguageGauntlet/App"
        )
    ]
)
