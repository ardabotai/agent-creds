// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "agent-creds",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .executable(name: "agentcreds", targets: ["agentcreds"]),
        .executable(name: "agentcredsd", targets: ["agentcredsd"]),
        .library(name: "CompanionProtocol", targets: ["CompanionProtocol"]),
        .library(name: "AgentCredsCore", targets: ["AgentCredsCore"]),
    ],
    targets: [
        .target(name: "CompanionProtocol"),
        .target(name: "AgentCredsCore"),
        .executableTarget(name: "agentcreds", dependencies: ["AgentCredsCore"]),
        .executableTarget(name: "agentcredsd", dependencies: ["AgentCredsCore", "CompanionProtocol"]),
        .testTarget(name: "AgentCredsDaemonTests", dependencies: ["agentcredsd", "AgentCredsCore", "CompanionProtocol"]),
        .testTarget(name: "AgentCredsCoreTests", dependencies: ["AgentCredsCore"]),
    ]
)
