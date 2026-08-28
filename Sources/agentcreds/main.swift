import Foundation
import AgentCredsCore

// agentcreds — CLI: MCP shim for agents, plus direct vault management.

let arguments = Array(CommandLine.arguments.dropFirst())

func usage() -> Never {
    print("""
    agentcreds — AI-first secret store

    USAGE:
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

func runShim(client: String) -> Never {
    let fd: Int32
    do {
        fd = try UnixSocket.connect(to: IPCPaths.socketPath)
    } catch {
        FileHandle.standardError.write(Data("agentcreds: cannot reach daemon at \(IPCPaths.socketPath) — is agentcredsd running? (\(error))\n".utf8))
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
