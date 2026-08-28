// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "agent-creds",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "agentcreds", targets: ["agentcreds"]),
        .executable(name: "agentcredsd", targets: ["agentcredsd"]),
        .library(name: "AgentCredsCore", targets: ["AgentCredsCore"]),
    ],
    targets: [
        .target(name: "AgentCredsCore"),
        .executableTarget(name: "agentcreds", dependencies: ["AgentCredsCore"]),
        .executableTarget(name: "agentcredsd", dependencies: ["AgentCredsCore"]),
        .testTarget(name: "AgentCredsCoreTests", dependencies: ["AgentCredsCore"]),
    ]
)
