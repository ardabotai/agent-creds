import AppKit
import AgentCredsCore

/// Secure out-of-band intake: the user pastes a secret directly into the
/// daemon's own window, so it never transits the agent's context or the chat.
final class CaptureController {
    /// Blocking; called from a connection thread while the agent's tools/call
    /// waits. Returns the pasted value, or nil if the user cancelled.
    func capture(client: String, name: String, purpose: String) -> String? {
        var result: String?
        let semaphore = DispatchSemaphore(value: 0)
        DispatchQueue.main.async {
            result = self.runPanel(client: client, name: name, purpose: purpose)
            semaphore.signal()
        }
        semaphore.wait()
        return result
    }

    private func runPanel(client: String, name: String, purpose: String) -> String? {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Provide secret “\(name)”"
        alert.informativeText = "\(client) needs “\(name)”\nPurpose: \(purpose)\n\nPaste the value below. It is saved to your encrypted vault — the agent never sees it, only a temporary credential minted from it."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Save to Vault")
        alert.addButton(withTitle: "Cancel")

        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 340, height: 24))
        field.placeholderString = "Paste or AutoFill secret value"
        // Marks this as a password input to the system, so the field offers
        // Apple Passwords AutoFill (key icon -> "Passwords…" picker, gated by
        // Touch ID) while focused. The fill lands directly in our field — the
        // agent never sees it. Site-specific suggestions (not just the picker)
        // additionally need the signed bundle + associated domains (Phase 2).
        field.contentType = .password
        let openPasswords = NSButton(title: "Open Apple Passwords…", target: self,
                                     action: #selector(openApplePasswords))
        openPasswords.bezelStyle = .inline
        let stack = NSStackView(views: [field, openPasswords])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.frame = NSRect(x: 0, y: 0, width: 340, height: 64)
        alert.accessoryView = stack
        alert.window.initialFirstResponder = field

        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let value = field.stringValue
        return value.isEmpty ? nil : value
    }

    /// Apple Passwords has no read API for third-party apps (items are ACL'd to
    /// Apple), so assisted copy-paste is the deepest integration possible.
    @objc private func openApplePasswords() {
        if !NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Passwords.app")) {
            if let url = URL(string: "x-apple.systempreferences:com.apple.Passwords-Settings.extension") {
                NSWorkspace.shared.open(url)
            }
        }
    }
}
