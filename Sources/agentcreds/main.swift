import Foundation
import AgentCredsCore

// agentcreds — CLI: MCP shim for agents, plus direct vault management.

let arguments = Array(CommandLine.arguments.dropFirst())

func usage() -> Never {
    print("""
    agentcreds — AI-first secret store

    USAGE:
      agentcreds setup [--agent <id>]  register the MCP server with your agent host(s)
                                       auto-detects claude-code, codex, opencode, cursor
      agentcreds skill                 print the agent guidance (pipe into AGENTS.md)
      agentcreds doctor                check that everything is wired up
      agentcreds mcp --client <name>   MCP stdio shim (register in your agent host)
      agentcreds add <name> --host <api.host.com> [--host …] [--kind opaque|oauthRefresh|awsRoot|githubApp]
                            [--header <X-Api-Key> [--header-prefix "token "]] [--basic-user <username>]
                                       at least one --host is required (no hosts = no egress path)
      agentcreds ls
      agentcreds rm <name>
      agentcreds identity [--email <email>] [--username <name>]
                                       identity used for {{acred:email}} / {{acred:username}} and signups
      agentcreds audit [--limit N]     show the approval / release history
      agentcreds run --with <name>[:ENV_VAR] [--with …] -- <cmd> [args…]
                                       Touch ID, then run <cmd> with secrets in its env
                                       (default var name derived: github/token -> GITHUB_TOKEN)

    The daemon (agentcredsd) must be running for `mcp`.
    Register with Claude Code:
      claude mcp add agentcreds -- agentcreds mcp --client claude-code
    """)
    exit(64)
}

func flagValue(_ flag: String, in args: [String]) -> String? {
    guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
    return args[i + 1]
}

func flagValues(_ flag: String, in args: [String]) -> [String] {
    var values: [String] = []
    var i = 0
    while i < args.count - 1 {
        if args[i] == flag { values.append(args[i + 1]); i += 1 }
        i += 1
    }
    return values
}

/// The ceremony for CLI-initiated release — the same one the daemon runs.
func approveLocally(reason: String) -> Bool {
    ApprovalCeremony.approve(reason: reason) { detail in
        FileHandle.standardError.write(Data("agentcreds: approval unavailable: \(detail)\n".utf8))
    }
}

func openVault() throws -> VaultStore { try VaultStore.openDefault() }

extension String {
    func ifEmpty(_ fallback: String) -> String { isEmpty ? fallback : self }
}

/// Absolute path to this binary, so MCP registration survives PATH changes.
func executablePath() -> String {
    if let path = Bundle.main.executablePath { return path }
    return URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path
}

@discardableResult
func shell(_ launchPath: String, _ arguments: [String]) -> (status: Int32, output: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: launchPath)
    process.arguments = arguments
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    do { try process.run() } catch { return (-1, "\(error)") }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
}

func which(_ tool: String) -> String? {
    let result = shell("/usr/bin/env", ["which", tool])
    let path = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
    return result.status == 0 && !path.isEmpty ? path : nil
}

var skillURL: URL {
    FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".claude/skills/\(AgentSkill.name)/SKILL.md")
}

func daemonReachable() -> Bool {
    guard let fd = try? UnixSocket.connect(to: IPCPaths.socketPath) else { return false }
    close(fd)
    return true
}

func proxyListening() -> Bool {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else { return false }
    defer { close(fd) }
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = UInt16(EgressProxy.port).bigEndian
    addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    return withUnsafePointer(to: &addr) { p in
        p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
        }
    }
}

func mcpRegistered() -> Bool {
    guard let claude = which("claude") else { return false }
    return shell(claude, ["mcp", "list"]).output.contains("agentcreds")
}



/// Starts the daemon if it is not already up, then waits for its socket.
/// Without this a fresh install fails its very first agent call, since nothing
/// has launched agentcredsd yet.
func startDaemonIfNeeded() -> Int32? {
    if let fd = try? UnixSocket.connect(to: IPCPaths.socketPath) { return fd }
    let daemon = URL(fileURLWithPath: executablePath())
        .deletingLastPathComponent().appendingPathComponent("agentcredsd")
    guard FileManager.default.isExecutableFile(atPath: daemon.path) else { return nil }
    let process = Process()
    process.executableURL = daemon
    // Detach the daemon's stdio. It must never inherit ours: our stdout IS the
    // MCP JSON-RPC channel, and an inherited pipe also stays open after this
    // shim exits, hanging whatever is reading us.
    let logURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Logs/agent-creds.log")
    if !FileManager.default.fileExists(atPath: logURL.path) {
        FileManager.default.createFile(atPath: logURL.path, contents: nil)
    }
    if let log = try? FileHandle(forWritingTo: logURL) {
        try? log.seekToEnd()
        process.standardOutput = log
        process.standardError = log
    } else {
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
    }
    process.standardInput = FileHandle.nullDevice
    guard (try? process.run()) != nil else { return nil }
    for _ in 0..<50 {                       // up to ~5s for launch + Keychain unlock
        usleep(100_000)
        if let fd = try? UnixSocket.connect(to: IPCPaths.socketPath) { return fd }
    }
    return nil
}

func runShim(client: String) -> Never {
    guard let fd = startDaemonIfNeeded() else {
        FileHandle.standardError.write(Data("agentcreds: could not reach or start the daemon (\(IPCPaths.socketPath)). Run `agentcreds doctor`.\n".utf8))
        exit(1)
    }
    let socketHandle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)

    var helloData = try! JSONEncoder().encode(ClientHello(client: client))
    helloData.append(UInt8(ascii: "\n"))
    socketHandle.write(helloData)

    let stdout = FileHandle.standardOutput
    let stdin = FileHandle.standardInput

    Thread.detachNewThread {
        while true {
            let data = socketHandle.availableData
            if data.isEmpty { exit(0) }
            stdout.write(data)
        }
    }
    while true {
        let data = stdin.availableData
        if data.isEmpty { exit(0) }
        socketHandle.write(data)
    }
}

guard let command = arguments.first else { usage() }
let rest = Array(arguments.dropFirst())

do {
    switch command {
    case "mcp":
        runShim(client: flagValue("--client", in: rest) ?? "unknown-agent")

    case "add":
        guard let name = rest.first, !name.hasPrefix("--") else { usage() }
        let kind = SecretKind(rawValue: flagValue("--kind", in: rest) ?? "opaque") ?? .opaque
        let hosts = flagValues("--host", in: rest)
        guard !hosts.isEmpty else {
            print("At least one --host is required — a secret with no hosts has no egress path.")
            print("e.g. agentcreds add \(name) --host api.github.com")
            exit(64)
        }
        let injection: CredentialInjection
        if let username = flagValue("--basic-user", in: rest) {
            injection = .basic(username: username)
        } else if let header = flagValue("--header", in: rest) {
            injection = .header(name: header, prefix: flagValue("--header-prefix", in: rest) ?? "")
        } else {
            injection = .bearer
        }
        guard let raw = getpass("Value for “\(name)” (input hidden): ") else { exit(1) }
        let value = String(cString: raw)
        guard !value.isEmpty else {
            print("Empty value; aborted.")
            exit(1)
        }
        try openVault().save(name: name, kind: kind, value: Data(value.utf8),
                             policy: SecretPolicy(allowedHosts: hosts, injection: injection))
        print("Saved “\(name)” (\(kind.rawValue)) for hosts \(hosts.joined(separator: ", ")).")

    case "ls":
        let items = try openVault().list()
        if items.isEmpty {
            print("Vault is empty. Add a secret with: agentcreds add <name>")
        } else {
            for item in items {
                print("\(item.name)  [\(item.kind.rawValue)]")
            }
        }

    case "rm":
        guard let name = rest.first else { usage() }
        try openVault().delete(name: name)
        print("Deleted “\(name)”.")

    case "identity":
        var identity = Identity.load()
        let email = flagValue("--email", in: rest)
        let username = flagValue("--username", in: rest)
        if email == nil && username == nil {
            print("email:    \(identity.email ?? "(not set)")")
            print("username: \(identity.username ?? "(not set)")")
        } else {
            if let email { identity.email = email }
            if let username { identity.username = username }
            try identity.save()
            print("Identity updated.")
        }

    case "skill":
        print(AgentSkill.markdown)

    case "setup":
        let executable = executablePath()
        let only = flagValue("--agent", in: rest)

        // The guidance an agent needs: not how to call the tools (the schemas
        // cover that) but WHEN to reach for them, and never to ask for a secret
        // in chat. Canonical copy lives with the vault; hosts get it in their
        // own format.
        let guidanceURL = IPCPaths.ensureDirectory().appendingPathComponent("AGENT.md")
        try Data(AgentSkill.markdown.utf8).write(to: guidanceURL, options: .atomic)

        var lines: [String] = []
        let hosts = AgentHost.all.filter { host in
            if let only { return host.id == only }
            return host.isPresent()
        }

        if hosts.isEmpty {
            if let only {
                print("Unknown or unavailable agent “\(only)”. Known: \(AgentHost.all.map(\.id).joined(separator: ", "))")
                exit(64)
            }
            lines.append("No supported agent host detected.")
        }

        for host in hosts {
            lines.append(host.register(executable))
            if host.id == "claude-code" {
                try FileManager.default.createDirectory(at: skillURL.deletingLastPathComponent(),
                                                        withIntermediateDirectories: true)
                try Data(AgentSkill.markdown.utf8).write(to: skillURL, options: .atomic)
                lines.append("Claude Code — skill installed at ~/.claude/skills/agent-creds/")
            }
        }

        for line in lines { print("  ✓ \(line)") }
        // Hosts that read AGENTS.md rather than skills get a pointer to the
        // canonical copy instead of us rewriting their instruction file.
        if hosts.contains(where: { $0.id == "codex" || $0.id == "opencode" }) {
            print("")
            print("  Codex / opencode read AGENTS.md rather than skills. To give them the")
            print("  same guidance, append it to your AGENTS.md:")
            print("      agentcreds skill >> ~/.codex/AGENTS.md")
            print("  (the MCP tool descriptions work without this; it mainly stops an agent")
            print("   from asking you to paste a secret into the chat)")
        }
        print("")
        print("Next:")
        if Identity.load().email == nil {
            print("  agentcreds identity --email you@example.com")
        }
        print("  agentcreds add <name> --host <api.host.com>     # store your first credential")
        print("  agentcreds doctor                              # verify everything")
        if !daemonReachable() {
            print("")
            print("The daemon is not running. Start it with ./install.sh, or run agentcredsd directly.")
        }

    case "doctor":
        struct Check { let ok: Bool; let label: String; let fix: String? }
        let identity = Identity.load()
        let secretCount = (try? openVault().list().count) ?? 0
        let checks: [Check] = [
            Check(ok: daemonReachable(), label: "Daemon running (\(IPCPaths.socketPath))",
                  fix: "start it: ./install.sh  — or run agentcredsd"),
            Check(ok: proxyListening(), label: "Egress proxy on 127.0.0.1:\(EgressProxy.port)",
                  fix: "the daemon owns this port; if the daemon is up, check ~/Library/Logs/agent-creds.log"),
            Check(ok: FileManager.default.fileExists(atPath: skillURL.path),
                  label: "Agent skill installed", fix: "run: agentcreds setup"),
            Check(ok: AgentHost.all.contains { $0.isPresent() },
                  label: "Agent host detected (\(AgentHost.all.filter { $0.isPresent() }.map(\.display).joined(separator: ", ").ifEmpty("none")))",
                  fix: "install Claude Code, Codex, opencode, or Cursor"),
            Check(ok: mcpRegistered(), label: "MCP server registered with Claude Code",
                  fix: "run: agentcreds setup"),
            Check(ok: identity.email != nil, label: "Identity set (\(identity.email ?? "not set"))",
                  fix: "run: agentcreds identity --email you@example.com"),
            Check(ok: secretCount > 0, label: "Vault has \(secretCount) secret(s)",
                  fix: "add one: agentcreds add github/token --host api.github.com"),
        ]
        for check in checks {
            print("  \(check.ok ? "✓" : "✗")  \(check.label)")
            if !check.ok, let fix = check.fix { print("       → \(fix)") }
        }
        let failed = checks.filter { !$0.ok }.count
        print("")
        print(failed == 0 ? "All good — your agent can use the vault." : "\(failed) item(s) need attention.")
        exit(failed == 0 ? 0 : 1)

    case "audit":
        let limit = flagValue("--limit", in: rest).flatMap { Int($0) } ?? 50
        let events = try AuditLog.shared.recent(limit: limit)
        if events.isEmpty {
            print("No audit events yet.")
        } else {
            let formatter = ISO8601DateFormatter()
            for event in events {
                let secret = event.secretName.map { " \($0)" } ?? ""
                let decision = event.decision.map { " [\($0)]" } ?? ""
                print("\(formatter.string(from: event.timestamp))  \(event.client)  \(event.action)\(secret)\(decision)")
            }
        }

    case "run":
        guard let dashIndex = rest.firstIndex(of: "--"), dashIndex + 1 < rest.count else {
            print("Usage: agentcreds run --with <name>[:ENV_VAR] [--with …] -- <cmd> [args…]")
            exit(64)
        }
        let options = Array(rest[..<dashIndex])
        let command = Array(rest[(dashIndex + 1)...])
        let specs = flagValues("--with", in: options)
        guard !specs.isEmpty else {
            print("At least one --with <name> is required.")
            exit(64)
        }
        let vault = try openVault()
        var plan: [(envVar: String, record: SecretRecord)] = []
        for spec in specs {
            // Keep empty pieces: "" and ":FOO" are user errors, not a crash or a
            // silent lookup of the wrong secret.
            let parts = spec.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            let name = String(parts[0])
            guard !name.isEmpty else {
                FileHandle.standardError.write(Data("agentcreds: --with needs a secret name, e.g. --with github/token[:GITHUB_TOKEN]\n".utf8))
                exit(64)
            }
            let override = parts.count > 1 ? String(parts[1]) : ""
            let envVar = override.isEmpty ? EnvName.derive(from: name) : override
            guard let record = try vault.record(named: name) else {
                FileHandle.standardError.write(Data("agentcreds: no secret named “\(name)”\n".utf8))
                exit(1)
            }
            plan.append((envVar, record))
        }
        let summary = plan.map { "\($0.record.name) → $\($0.envVar)" }.joined(separator: ", ")
        guard approveLocally(reason: "inject \(summary) into “\(command.joined(separator: " "))”") else {
            FileHandle.standardError.write(Data("agentcreds: denied\n".utf8))
            exit(1)
        }
        var environment = ProcessInfo.processInfo.environment
        for (envVar, record) in plan {
            guard let value = String(data: try vault.revealValue(of: record), encoding: .utf8) else {
                FileHandle.standardError.write(Data("agentcreds: “\(record.name)” is not valid UTF-8 and cannot be passed in the environment\n".utf8))
                exit(1)
            }
            environment[envVar] = value
        }
        AuditLog.shared.record(client: "agentcreds-cli", action: "run",
                               secretName: plan.map(\.record.name).joined(separator: ", "),
                               decision: "injected")
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        child.arguments = command
        child.environment = environment
        try child.run()
        child.waitUntilExit()
        exit(child.terminationStatus)

    default:
        usage()
    }
} catch {
    FileHandle.standardError.write(Data("agentcreds: \(error)\n".utf8))
    exit(1)
}
