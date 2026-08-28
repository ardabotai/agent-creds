import AppKit
import AgentCredsCore

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var server: SocketServer?
    private var proxy: ProxyServer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "🔑"
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "agent-creds is running", action: nil, keyEquivalent: ""))
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
            let vault = try VaultStore.openDefault()
            let server = try SocketServer(vault: vault)
            server.start()
            self.server = server
            let proxy = try ProxyServer(vault: vault)
            proxy.start()
            self.proxy = proxy
            NSLog("agent-creds listening at \(IPCPaths.socketPath); egress proxy on 127.0.0.1:\(EgressProxy.port)")
        } catch {
            NSLog("agent-creds failed to start: \(error)")
            NSApp.terminate(nil)
        }
    }
}
