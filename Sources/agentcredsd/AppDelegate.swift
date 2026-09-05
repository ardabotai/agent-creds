import AppKit
import AgentCredsCore

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private var server: SocketServer?
    private var proxy: ProxyServer?
    let passkeyCeremony = PasskeyCeremony()

    private var vault: VaultStore?
    private var uiModel: VaultUIModel?
    private var vaultWindow: VaultWindowController?
    private var menu: NSMenu!

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            if let image = NSImage(systemSymbolName: "key.fill", accessibilityDescription: "agent-creds") {
                image.isTemplate = true
                button.image = image
            } else {
                button.title = "🔑"
            }
        }

        menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu
        rebuildMenu(placeholder: true)

        // Singleton: a second daemon would unlink and steal the first one's
        // socket, silently splitting agents across two vault handles.
        if let existing = try? UnixSocket.connect(to: IPCPaths.socketPath) {
            close(existing)
            NSLog("agent-creds: another daemon is already running; exiting")
            NSApp.terminate(nil)
            return
        }

        do {
            let kekProvider = try KEKResolver.provider(ceremony: passkeyCeremony)
            let vault = try VaultStore(kekProvider: kekProvider)
            let server = try SocketServer(vault: vault,
                                          kekPromptsItself: kekProvider.promptsEveryTime)
            server.start()
            self.server = server
            let proxy = try ProxyServer(vault: vault)
            proxy.start()
            self.proxy = proxy
            self.vault = vault
            let model = VaultUIModel(vault: vault, passkeyCeremony: passkeyCeremony)
            self.uiModel = model
            self.vaultWindow = VaultWindowController(model: model)
            rebuildMenu(placeholder: false)
            NSLog("agent-creds listening at \(IPCPaths.socketPath); egress proxy on 127.0.0.1:\(EgressProxy.port)")
        } catch UnixSocketError.alreadyInUse(let path) {
            NSLog("agent-creds: another daemon already owns \(path); exiting")
            NSApp.terminate(nil)
        } catch {
            NSLog("agent-creds failed to start: \(error)")
            NSApp.terminate(nil)
        }
    }

    func menuWillOpen(_ menu: NSMenu) {
        uiModel?.refresh()
        rebuildMenu(placeholder: false)
    }

    private func rebuildMenu(placeholder: Bool) {
        menu.removeAllItems()

        let status = NSMenuItem(title: uiModel?.statusLine ?? "Starting agent-creds…",
                                action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)
        menu.addItem(.separator())

        let openItem = NSMenuItem(title: "Open Vault…", action: #selector(openVaultWindow), keyEquivalent: "o")
        openItem.target = self
        openItem.isEnabled = uiModel != nil
        menu.addItem(openItem)

        let secretsItem = NSMenuItem(title: "Secrets", action: nil, keyEquivalent: "")
        let secretsMenu = NSMenu(title: "Secrets")
        if placeholder || uiModel == nil {
            secretsMenu.addItem(NSMenuItem(title: "Loading…", action: nil, keyEquivalent: ""))
        } else if let secrets = uiModel?.secrets, !secrets.isEmpty {
            for secret in secrets.prefix(20) {
                let hosts = secret.allowedHosts.isEmpty ? "deny-all" : secret.allowedHosts.joined(separator: ", ")
                let title = "\(secret.name)  [\(secret.kind.rawValue)]  ·  \(hosts)"
                let item = NSMenuItem(title: title, action: #selector(openVaultWindow), keyEquivalent: "")
                item.target = self
                item.toolTip = "Hosts: \(hosts)"
                secretsMenu.addItem(item)
            }
            if secrets.count > 20 {
                secretsMenu.addItem(NSMenuItem(title: "…and \(secrets.count - 20) more in Open Vault",
                                               action: nil, keyEquivalent: ""))
            }
        } else {
            let empty = NSMenuItem(title: "Vault is empty — Add Secret in Open Vault…",
                                   action: #selector(openVaultWindow), keyEquivalent: "")
            empty.target = self
            secretsMenu.addItem(empty)
        }
        secretsMenu.addItem(.separator())
        let addItem = NSMenuItem(title: "Add Secret…", action: #selector(openVaultAdd), keyEquivalent: "n")
        addItem.target = self
        addItem.isEnabled = uiModel != nil
        secretsMenu.addItem(addItem)
        secretsItem.submenu = secretsMenu
        menu.addItem(secretsItem)

        let identityTitle: String
        if let email = Identity.load().email, !email.isEmpty {
            identityTitle = "Identity: \(email)"
        } else {
            identityTitle = "Identity: not set"
        }
        let identityItem = NSMenuItem(title: identityTitle, action: #selector(openIdentity), keyEquivalent: "i")
        identityItem.target = self
        identityItem.isEnabled = uiModel != nil
        menu.addItem(identityItem)

        let auditItem = NSMenuItem(title: "Recent Audit", action: nil, keyEquivalent: "")
        let auditMenu = NSMenu(title: "Recent Audit")
        let events = (try? AuditLog.shared.recent(limit: 8)) ?? []
        if events.isEmpty {
            auditMenu.addItem(NSMenuItem(title: "No events yet", action: nil, keyEquivalent: ""))
        } else {
            let formatter = DateFormatter()
            formatter.dateStyle = .none
            formatter.timeStyle = .short
            for event in events.reversed() {
                let secret = event.secretName.map { " \($0)" } ?? ""
                let decision = event.decision.map { " [\($0)]" } ?? ""
                let title = "\(formatter.string(from: event.timestamp))  \(event.client)  \(event.action)\(secret)\(decision)"
                auditMenu.addItem(NSMenuItem(title: title, action: nil, keyEquivalent: ""))
            }
        }
        auditMenu.addItem(.separator())
        let openAudit = NSMenuItem(title: "Open Full Audit…", action: #selector(openAudit), keyEquivalent: "")
        openAudit.target = self
        openAudit.isEnabled = uiModel != nil
        auditMenu.addItem(openAudit)
        auditItem.submenu = auditMenu
        menu.addItem(auditItem)

        menu.addItem(.separator())

        let protectItem = NSMenuItem(title: KEKConfig.load().source == .passkey
                                        ? "Vault protected by passkey"
                                        : "Protect vault with a passkey…",
                                     action: #selector(protectWithPasskey), keyEquivalent: "")
        protectItem.target = self
        protectItem.isEnabled = KEKConfig.load().source != .passkey
        menu.addItem(protectItem)

        let doctorItem = NSMenuItem(title: "Run Doctor…", action: #selector(runDoctor), keyEquivalent: "d")
        doctorItem.target = self
        menu.addItem(doctorItem)

        let setupItem = NSMenuItem(title: "Run Setup…", action: #selector(runSetup), keyEquivalent: "")
        setupItem.target = self
        menu.addItem(setupItem)

        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit agent-creds",
                                action: #selector(NSApplication.terminate(_:)),
                                keyEquivalent: "q"))
    }

    @objc private func openVaultWindow() {
        vaultWindow?.show(tab: .secrets)
    }

    @objc private func openVaultAdd() {
        vaultWindow?.show(tab: .secrets)
        // Present the add sheet after the window is up.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { [weak self] in
            NotificationCenter.default.post(name: .agentCredsPresentAddSecret, object: self?.uiModel)
        }
    }

    @objc private func openIdentity() {
        vaultWindow?.show(tab: .identity)
    }

    @objc private func openAudit() {
        vaultWindow?.show(tab: .audit)
    }

    @objc private func protectWithPasskey() {
        Thread.detachNewThread { [weak self] in
            guard let self else { return }
            let result = AppDelegate.runPasskeyEnrollment(ceremony: self.passkeyCeremony)
            DispatchQueue.main.async {
                self.uiModel?.refresh()
                let alert = NSAlert()
                switch result {
                case .success(let outcome):
                    alert.messageText = "Vault protected by passkey"
                    alert.informativeText = "Re-wrapped \(outcome.secretsRewrapped) secret(s) under a key that only exists during a passkey approval. Restart agent-creds to use it."
                case .failure(let error):
                    alert.alertStyle = .warning
                    alert.messageText = "Could not protect the vault"
                    alert.informativeText = "\(error)"
                }
                alert.runModal()
            }
        }
    }

    @objc private func runDoctor() {
        runCLIAndPresent(arguments: ["doctor"], title: "agentcreds doctor")
    }

    @objc private func runSetup() {
        runCLIAndPresent(arguments: ["setup"], title: "agentcreds setup")
    }

    private func runCLIAndPresent(arguments: [String], title: String) {
        guard let path = AppDelegate.resolveAgentcredsPath() else {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "agentcreds CLI not found"
            alert.informativeText = "Install with Homebrew (`brew install ardabotai/tap/agent-creds`) or ./install.sh, then try again."
            alert.runModal()
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = arguments
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            do {
                try process.run()
                process.waitUntilExit()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8) ?? "(no output)"
                DispatchQueue.main.async {
                    let alert = NSAlert()
                    alert.messageText = title
                    alert.informativeText = output.trimmingCharacters(in: .whitespacesAndNewlines)
                    if process.terminationStatus != 0 {
                        alert.alertStyle = .warning
                    }
                    alert.runModal()
                }
            } catch {
                DispatchQueue.main.async {
                    let alert = NSAlert()
                    alert.alertStyle = .warning
                    alert.messageText = "Could not run \(title)"
                    alert.informativeText = "\(error)"
                    alert.runModal()
                }
            }
        }
    }

    static func resolveAgentcredsPath() -> String? {
        var candidates: [String] = []
        if let exe = Bundle.main.executableURL {
            candidates.append(exe.deletingLastPathComponent().appendingPathComponent("agentcreds").path)
            // Dev: .build/debug/agentcredsd → sibling agentcreds
            candidates.append(exe.deletingLastPathComponent().appendingPathComponent("agentcreds").path)
        }
        candidates += [
            NSHomeDirectory() + "/.local/bin/agentcreds",
            "/opt/homebrew/bin/agentcreds",
            "/usr/local/bin/agentcreds",
        ]
        // Also look next to a bare executable launched from .build/release
        if let argv0 = CommandLine.arguments.first {
            let dir = URL(fileURLWithPath: argv0).deletingLastPathComponent()
            candidates.insert(dir.appendingPathComponent("agentcreds").path, at: 0)
        }
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// Shared by the menu item and the `agentcreds passkey enroll` control command.
    static func runPasskeyEnrollment(ceremony: PasskeyCeremony)
        -> Result<PasskeyEnrollment.Result, Error> {
        let relyingParty = ProcessInfo.processInfo.environment["AGENTCREDS_RELYING_PARTY"]
            ?? PasskeyDefaults.relyingParty
        let userName = Identity.load().email ?? NSUserName()
        do {
            return .success(try PasskeyEnrollment.enroll(relyingParty: relyingParty,
                                                         userName: userName, ceremony: ceremony))
        } catch {
            return .failure(error)
        }
    }
}

extension Notification.Name {
    static let agentCredsPresentAddSecret = Notification.Name("agentCredsPresentAddSecret")
}
