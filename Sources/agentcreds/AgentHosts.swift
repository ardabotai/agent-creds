import Foundation
import AgentCredsCore

/// Registration for the agent hosts people actually use. Each host discovers
/// MCP servers differently, so `agentcreds setup` detects what is installed and
/// writes the right config for each rather than making the user find the docs.
struct AgentHost {
    let id: String
    let display: String
    /// True when this host looks installed on the machine.
    let isPresent: () -> Bool
    /// Registers the MCP server. Returns a human-readable status line.
    let register: (_ executable: String) -> String

    static var home: URL { FileManager.default.homeDirectoryForCurrentUser }

    static func exists(_ path: String) -> Bool {
        FileManager.default.fileExists(atPath: home.appendingPathComponent(path).path)
    }

    /// Merges a key into an existing JSON config without disturbing the rest.
    static func mergeJSON(at url: URL, container: String, key: String,
                          value: [String: Any]) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        var root: [String: Any] = [:]
        if let data = try? Data(contentsOf: url),
           let parsed = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
            root = parsed
        }
        var servers = root[container] as? [String: Any] ?? [:]
        servers[key] = value
        root[container] = servers
        let data = try JSONSerialization.data(withJSONObject: root,
                                              options: [.prettyPrinted, .sortedKeys])
        try data.write(to: url, options: .atomic)
    }

    static let all: [AgentHost] = [
        AgentHost(
            id: "claude-code",
            display: "Claude Code",
            isPresent: { which("claude") != nil || exists(".claude") },
            register: { executable in
                guard let claude = which("claude") else {
                    return "Claude Code config found but the `claude` CLI is not on PATH — register manually:\n      claude mcp add -s user agentcreds -- \(executable) mcp --client claude-code"
                }
                if shell(claude, ["mcp", "list"]).output.contains("agentcreds") {
                    return "Claude Code — already registered"
                }
                let result = shell(claude, ["mcp", "add", "-s", "user", "agentcreds",
                                            "--", executable, "mcp", "--client", "claude-code"])
                return result.status == 0
                    ? "Claude Code — MCP server registered"
                    : "Claude Code — registration failed: \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))"
            }),

        AgentHost(
            id: "codex",
            display: "Codex",
            isPresent: { which("codex") != nil || exists(".codex") },
            register: { executable in
                let url = home.appendingPathComponent(".codex/config.toml")
                let existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
                if existing.contains("[mcp_servers.agentcreds]") {
                    return "Codex — already registered"
                }
                // Append-only: parsing and rewriting a user's TOML risks losing
                // comments and formatting, and this block is self-contained.
                let block = """

                [mcp_servers.agentcreds]
                command = "\(executable)"
                args = ["mcp", "--client", "codex"]

                """
                do {
                    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                            withIntermediateDirectories: true)
                    try (existing + block).write(to: url, atomically: true, encoding: .utf8)
                    return "Codex — MCP server added to ~/.codex/config.toml"
                } catch {
                    return "Codex — could not write config.toml: \(error)"
                }
            }),

        AgentHost(
            id: "opencode",
            display: "opencode",
            isPresent: { which("opencode") != nil || exists(".config/opencode") },
            register: { executable in
                let url = home.appendingPathComponent(".config/opencode/opencode.json")
                do {
                    try mergeJSON(at: url, container: "mcp", key: "agentcreds", value: [
                        "type": "local",
                        "command": [executable, "mcp", "--client", "opencode"],
                        "enabled": true,
                    ])
                    return "opencode — MCP server added to ~/.config/opencode/opencode.json"
                } catch {
                    return "opencode — could not write opencode.json: \(error)"
                }
            }),

        AgentHost(
            id: "cursor",
            display: "Cursor",
            isPresent: { exists(".cursor") || FileManager.default.fileExists(atPath: "/Applications/Cursor.app") },
            register: { executable in
                let url = home.appendingPathComponent(".cursor/mcp.json")
                do {
                    try mergeJSON(at: url, container: "mcpServers", key: "agentcreds", value: [
                        "command": executable,
                        "args": ["mcp", "--client", "cursor"],
                    ])
                    return "Cursor — MCP server added to ~/.cursor/mcp.json"
                } catch {
                    return "Cursor — could not write mcp.json: \(error)"
                }
            }),
    ]

    /// Config snippet for any host we do not configure automatically.
    static func manualInstructions(executable: String) -> String {
        """
        For any other MCP-capable agent, register this stdio server:
            command: \(executable)
            args:    ["mcp", "--client", "<your-agent>"]
        """
    }
}
