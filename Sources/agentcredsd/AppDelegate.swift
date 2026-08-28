import AppKit
import AgentCredsCore

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var server: SocketServer?
    private var proxy: ProxyServer?
    let passkeyCeremony = PasskeyCeremony()

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "🔑"
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "agent-creds is running", action: nil, keyEquivalent: ""))
        menu.addItem(.separator())
        let protectItem = NSMenuItem(title: KEKConfig.load().source == .passkey
                                        ? "Vault protected by passkey"
                                        : "Protect vault with a passkey…",
                                     action: #selector(protectWithPasskey), keyEquivalent: "")
        protectItem.target = self
        protectItem.isEnabled = KEKConfig.load().source != .passkey
        menu.addItem(protectItem)
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit agent-creds",
                                action: #selector(NSApplication.terminate(_:)),
                                keyEquivalent: "q"))
        statusItem.menu = menu

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
            NSLog("agent-creds listening at \(IPCPaths.socketPath); egress proxy on 127.0.0.1:\(EgressProxy.port)")
        } catch UnixSocketError.alreadyInUse(let path) {
            NSLog("agent-creds: another daemon already owns \(path); exiting")
            NSApp.terminate(nil)
        } catch {
            NSLog("agent-creds failed to start: \(error)")
            NSApp.terminate(nil)
        }
    }

    @objc private func protectWithPasskey() {
        Thread.detachNewThread { [weak self] in
            guard let self else { return }
            let result = AppDelegate.runPasskeyEnrollment(ceremony: self.passkeyCeremony)
            DispatchQueue.main.async {
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
