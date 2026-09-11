import AppKit
import AgentCredsCore
import CompanionProtocol
import CoreImage

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private var server: SocketServer?
    private var proxy: ProxyServer?
    private var companion: CompanionServer?
    private var pairingInProgress = false
    private var approvals: CompanionApprovals?
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
            let approvals = CompanionApprovals(vault: vault)
            self.approvals = approvals
            let companion = CompanionServer(vault: vault, approvals: approvals)
            self.companion = companion
            Task.detached {
                do {
                    if try CompanionStateStorage.keychain.load() != nil {
                        try companion.enableRelay(url: RelayAddress.productionURL, storage: .keychain)
                    }
                } catch { NSLog("agent-creds: relay unavailable; use Pair iPhone to retry") }
            }
            let server = try SocketServer(vault: vault, approvals: approvals)
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

    @MainActor
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

        let pairItem = NSMenuItem(title: "Pair iPhone…", action: #selector(pairCompanion), keyEquivalent: "")
        pairItem.target = self
        menu.addItem(pairItem)
        let revokeItem = NSMenuItem(title: "Disconnect All Companions", action: #selector(revokeCompanions), keyEquivalent: "")
        revokeItem.target = self
        menu.addItem(revokeItem)

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
                    alert.informativeText = "Re-wrapped \(outcome.secretsRewrapped) secret(s) under a key that only exists during a passkey approval. Passkey protection is active now."
                case .failure(let error):
                    alert.alertStyle = .warning
                    alert.messageText = "Could not protect the vault"
                    alert.informativeText = "\(error)"
                }
                alert.runModal()
            }
        }
    }

    @objc private func pairCompanion() {
        guard !pairingInProgress, let companion else { return }
        pairingInProgress = true
        Task { @MainActor in
        defer { pairingInProgress = false }
        do {
            let invite = try await Task.detached {
                try companion.enableRelay(url: RelayAddress.productionURL, storage: .keychain)
                return try companion.invite()
            }.value
            let alert = NSAlert()
            alert.messageText = "Pair your iPhone"
            alert.informativeText = "In agent-creds on your iPhone, tap Scan Mac Code. Both devices need internet access. This code expires in 10 minutes and can enroll one iPhone. Confirm trust on your Mac after scanning. Trusted pairing survives restarts; revoke it anytime from this menu."
            let filter = CIFilter(name: "CIQRCodeGenerator")!
            filter.setValue(Data(invite.qrString.utf8), forKey: "inputMessage")
            filter.setValue("M", forKey: "inputCorrectionLevel")
            if let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 6, y: 6)) {
                let image = NSImage(size: output.extent.size)
                image.addRepresentation(NSCIImageRep(ciImage: output))
                let view = NSImageView(frame: NSRect(x: 0, y: 0, width: 300, height: 300))
                view.image = image; view.imageScaling = .scaleProportionallyUpOrDown
                alert.accessoryView = view
            }
            alert.addButton(withTitle: "Done")
            alert.addButton(withTitle: "Copy Pairing Code")
            NSApp.activate(ignoringOtherApps: true)
            if alert.runModal() == .alertSecondButtonReturn {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(invite.qrString, forType: .string)
            }
        } catch {
            let alert = NSAlert(); alert.messageText = "Could not pair"; alert.informativeText = error.localizedDescription; alert.runModal()
        }
    }

    }
    @objc private func revokeCompanions() {
        guard let companion else { return }
        Task { @MainActor in
            let persisted = await Task.detached { companion.revokeAll() }.value
            if !persisted {
                let alert = NSAlert(); alert.messageText = "Could not save revocation"
                alert.informativeText = "Access was stopped for this session, but Keychain could not save the change. Retry revocation before restarting the Mac app."
                alert.runModal()
            }
        }
    }
    func applicationWillTerminate(_ notification: Notification) { companion?.stopRelay() }

    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls { openApproval(url) }
    }

    func application(_ application: NSApplication, continue userActivity: NSUserActivity,
                     restorationHandler: @escaping ([NSUserActivityRestoring]) -> Void) -> Bool {
        guard let url = userActivity.webpageURL, ApprovalLink.requestID(from: url) != nil else { return false }
        openApproval(url); return true
    }

    private func openApproval(_ url: URL) {
        guard let id = ApprovalLink.requestID(from: url), let approvals,
              let request = approvals.list().first(where: { $0.id == id }), request.effectiveStatus() == .pending else {
            let alert = NSAlert(); alert.messageText = "Request unavailable"; alert.informativeText = "This request expired, was already decided, or belongs to another Mac session."; alert.runModal(); return
        }
        Thread.detachNewThread {
            let outcome = ApprovalDialog.present(CredentialApproval(client: request.agent, credentialName: request.credentialName, hosts: request.hosts, purpose: request.purpose))
            switch outcome {
            case .approved(let duration): try? approvals.decide(id: id, approved: true, duration: min(duration, request.maximumDuration))
            case .denied: try? approvals.decide(id: id, approved: false, duration: 1)
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
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
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
