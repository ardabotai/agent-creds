import AppKit
import AgentCredsCore

/// What the user is being asked to allow. Everything here except `purpose`
/// comes from our own records — `purpose` is the agent's claim and is presented
/// as such, because an injected agent will write whatever gets it a yes.
struct CredentialApproval {
    let client: String
    let credentialName: String
    let hosts: [String]
    let purpose: String

    enum Outcome {
        case approved(ttlSeconds: Int)
        case denied
    }
}

/// The decision surface. A bare Touch ID reason string is one line with no
/// duration choice; this shows what is being released, to whom, for how long,
/// and marks the agent-written part as untrusted.
enum ApprovalDialog {
    private static let durations: [(label: String, seconds: Int)] = [
        ("This once (2 minutes)", 120),
        ("15 minutes", 900),
        ("1 hour", 3600),
        ("8 hours", 28800),
    ]

    static func present(_ request: CredentialApproval) -> CredentialApproval.Outcome {
        var outcome = CredentialApproval.Outcome.denied
        let semaphore = DispatchSemaphore(value: 0)
        DispatchQueue.main.async {
            outcome = runModal(request)
            semaphore.signal()
        }
        semaphore.wait()
        return outcome
    }

    private static func runModal(_ request: CredentialApproval) -> CredentialApproval.Outcome {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "\(request.client) wants to use “\(request.credentialName)”"
        alert.informativeText = request.hosts.isEmpty
            ? "It will be used on your behalf. You will not see the value, and neither will the agent."
            : "Usable only against \(request.hosts.joined(separator: ", ")). The agent never sees the value."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Approve")
        alert.addButton(withTitle: "Deny")

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10

        // The agent's stated reason, visually demoted and explicitly labeled.
        let purposeLabel = NSTextField(wrappingLabelWithString: "“\(request.purpose)”")
        purposeLabel.font = .systemFont(ofSize: 12)
        purposeLabel.textColor = .secondaryLabelColor
        purposeLabel.preferredMaxLayoutWidth = 330
        let caveat = NSTextField(labelWithString: "▲ Written by the agent — a claim, not a fact")
        caveat.font = .systemFont(ofSize: 10)
        caveat.textColor = .systemRed
        stack.addArrangedSubview(purposeLabel)
        stack.addArrangedSubview(caveat)

        let durationRow = NSStackView()
        durationRow.orientation = .horizontal
        durationRow.spacing = 8
        let durationLabel = NSTextField(labelWithString: "Allow for:")
        durationLabel.font = .systemFont(ofSize: 12)
        let popup = NSPopUpButton(frame: .zero, pullsDown: false)
        popup.addItems(withTitles: durations.map(\.label))
        popup.selectItem(at: 0)          // shortest by default: defaults are policy
        durationRow.addArrangedSubview(durationLabel)
        durationRow.addArrangedSubview(popup)
        stack.addArrangedSubview(durationRow)

        stack.frame = NSRect(x: 0, y: 0, width: 340, height: 88)
        alert.accessoryView = stack

        guard alert.runModal() == .alertFirstButtonReturn else { return .denied }
        return .approved(ttlSeconds: durations[popup.indexOfSelectedItem].seconds)
    }
}
