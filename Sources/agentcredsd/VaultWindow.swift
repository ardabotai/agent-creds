import AppKit
import SwiftUI
import AgentCredsCore

/// Owns the lightweight management window. Kept as AppKit so the accessory
/// (LSUIElement) menubar daemon can raise a proper key window on demand.
final class VaultWindowController: NSWindowController, NSWindowDelegate {
    private let model: VaultUIModel

    init(model: VaultUIModel) {
        self.model = model
        let root = VaultRootView(model: model)
        let hosting = NSHostingController(rootView: root)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 720, height: 480),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false)
        window.title = "agent-creds"
        window.contentViewController = hosting
        window.center()
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 560, height: 360)
        super.init(window: window)
        window.delegate = self
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func show(tab: VaultUIModel.Tab? = nil) {
        if let tab { model.selectedTab = tab }
        model.refresh()
        NSApp.activate(ignoringOtherApps: true)
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
    }
}

struct VaultRootView: View {
    @ObservedObject var model: VaultUIModel
    @State private var showingAdd = false
    @State private var pendingDelete: String?
    @State private var formError: String?

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            NavigationSplitView {
                List(selection: $model.selectedTab) {
                    ForEach(VaultUIModel.Tab.allCases) { tab in
                        Label(tab.rawValue, systemImage: icon(for: tab))
                            .tag(tab)
                    }
                }
                .listStyle(.sidebar)
                .frame(minWidth: 160)
            } detail: {
                detail
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    .padding()
            }
            if let banner = model.banner {
                Divider()
                HStack {
                    Text(banner)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                    Spacer()
                    Button("Dismiss") { model.banner = nil }
                        .buttonStyle(.borderless)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(.quaternary.opacity(0.4))
            }
        }
        .frame(minWidth: 560, minHeight: 360)
        .sheet(isPresented: $showingAdd) {
            AddSecretSheet(model: model, isPresented: $showingAdd)
        }
        .onReceive(NotificationCenter.default.publisher(for: .agentCredsPresentAddSecret)) { _ in
            showingAdd = true
        }
        .alert("Delete secret?", isPresented: Binding(
            get: { pendingDelete != nil },
            set: { if !$0 { pendingDelete = nil } }
        )) {
            Button("Cancel", role: .cancel) { pendingDelete = nil }
            Button("Delete", role: .destructive) {
                if let name = pendingDelete {
                    do { try model.deleteSecret(named: name) }
                    catch { formError = error.localizedDescription }
                }
                pendingDelete = nil
            }
        } message: {
            Text("“\(pendingDelete ?? "")” will be removed from the vault. This cannot be undone.")
        }
        .alert("Could not complete action", isPresented: Binding(
            get: { formError != nil },
            set: { if !$0 { formError = nil } }
        )) {
            Button("OK", role: .cancel) { formError = nil }
        } message: {
            Text(formError ?? "")
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "key.fill")
                .font(.title2)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text("agent-creds")
                    .font(.headline)
                Text(model.statusLine)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                model.refresh()
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .help("Reload vault metadata, identity, and audit")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    @ViewBuilder
    private var detail: some View {
        switch model.selectedTab {
        case .secrets:
            secretsPane
        case .identity:
            identityPane
        case .passkey:
            passkeyPane
        case .audit:
            auditPane
        }
    }

    private var secretsPane: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Vault secrets")
                    .font(.title3.weight(.semibold))
                Spacer()
                Button {
                    showingAdd = true
                } label: {
                    Label("Add Secret…", systemImage: "plus")
                }
                .keyboardShortcut("n", modifiers: [.command])
            }
            Text("Names, kinds, and host allowlists only. Values never appear here — use Add Secret for secure entry.")
                .font(.caption)
                .foregroundStyle(.secondary)

            if model.secrets.isEmpty {
                ContentUnavailableView(
                    "Vault is empty",
                    systemImage: "tray",
                    description: Text("Add a secret with at least one allowed host. Empty allowlists deny every host."))
            } else {
                Table(model.secrets) {
                    TableColumn("Name") { item in
                        Text(item.name)
                            .font(.body.monospaced())
                    }
                    .width(min: 120, ideal: 180)
                    TableColumn("Kind") { item in
                        Text(item.kind.rawValue)
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 80, ideal: 100)
                    TableColumn("Allowed hosts") { item in
                        Text(item.allowedHosts.isEmpty ? "deny-all (no hosts)" : item.allowedHosts.joined(separator: ", "))
                            .foregroundStyle(item.allowedHosts.isEmpty ? .red : .primary)
                    }
                    TableColumn("") { item in
                        Button(role: .destructive) {
                            pendingDelete = item.name
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                        .help("Remove “\(item.name)”")
                    }
                    .width(36)
                }
            }
        }
    }

    private var identityPane: some View {
        Form {
            Section {
                TextField("Email", text: $model.identityEmail)
                    .textContentType(.emailAddress)
                TextField("Username", text: $model.identityUsername)
                    .textContentType(.username)
            } header: {
                Text("Signup identity")
            } footer: {
                Text("Used by begin_signup placeholders ({{acred:email}}, {{acred:username}}). Never a secret.")
            }
            Section {
                Button("Save Identity") {
                    do { try model.saveIdentity() }
                    catch { formError = error.localizedDescription }
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .formStyle(.grouped)
    }

    private var passkeyPane: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Vault key protection")
                .font(.title3.weight(.semibold))
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    labeled("KEK source", model.kekConfig.source.rawValue)
                    if model.kekConfig.source == .passkey {
                        labeled("Relying party", model.kekConfig.relyingParty ?? "—")
                        Text("Every release derives the key from a passkey assertion — there is no stored key to fall back on.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("The key is stored in the Keychain and the biometric gate is procedural. Enroll a passkey to make approval cryptographic.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                        Button("Protect vault with a passkey…") {
                            Task { await model.enrollPasskey() }
                        }
                        .disabled(model.kekConfig.source == .passkey)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }
            Text("Passkey mode requires the signed agent-creds.app bundle with associated domains. A local swift build stays on the Keychain KEK.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private var auditPane: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Recent audit")
                    .font(.title3.weight(.semibold))
                Spacer()
                Button("Refresh") { model.refresh() }
            }
            Text("Approvals, denials, and releases. Secret names only — never values.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if model.auditEvents.isEmpty {
                ContentUnavailableView("No audit events yet", systemImage: "list.bullet.rectangle")
            } else {
                List(model.auditEvents.indices, id: \.self) { index in
                    let event = model.auditEvents[index]
                    VStack(alignment: .leading, spacing: 2) {
                        HStack {
                            Text(event.action)
                                .font(.body.weight(.medium))
                            if let decision = event.decision {
                                Text(decision)
                                    .font(.caption)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(.quaternary, in: Capsule())
                            }
                            Spacer()
                            Text(event.timestamp, style: .relative)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        HStack(spacing: 8) {
                            Text(event.client)
                                .foregroundStyle(.secondary)
                            if let secret = event.secretName {
                                Text("·")
                                    .foregroundStyle(.tertiary)
                                Text(secret)
                                    .font(.body.monospaced())
                            }
                        }
                        .font(.caption)
                    }
                    .padding(.vertical, 2)
                }
                .listStyle(.inset)
            }
        }
    }

    private func labeled(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.body.monospaced())
        }
    }

    private func icon(for tab: VaultUIModel.Tab) -> String {
        switch tab {
        case .secrets: return "lock.rectangle.stack"
        case .identity: return "person.crop.circle"
        case .passkey: return "person.badge.key"
        case .audit: return "list.bullet.rectangle"
        }
    }
}

struct AddSecretSheet: View {
    @ObservedObject var model: VaultUIModel
    @Binding var isPresented: Bool

    @State private var name = ""
    @State private var hosts = ""
    @State private var kind: SecretKind = .opaque
    @State private var value = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Add secret")
                .font(.title2.weight(.semibold))
            Text("Paste the value into the secure field. It is written to the encrypted vault and never shown again in this UI.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Form {
                TextField("Name (e.g. github/token)", text: $name)
                TextField("Allowed hosts (comma-separated, required)", text: $hosts)
                Picker("Kind", selection: $kind) {
                    ForEach(SecretKind.allCases, id: \.self) { item in
                        Text(item.rawValue).tag(item)
                    }
                }
                SecureField("Secret value", text: $value)
                    .textContentType(.password)
            }
            .formStyle(.grouped)

            if let error {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.callout)
            }

            HStack {
                Spacer()
                Button("Cancel") {
                    value = ""
                    isPresented = false
                }
                .keyboardShortcut(.cancelAction)
                Button("Save to Vault") {
                    save()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                          || hosts.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }.isEmpty
                          || value.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 460)
    }

    private func save() {
        let hostList = hosts.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
        do {
            try model.addSecret(name: name, kind: kind, hosts: hostList, value: value)
            value = ""
            isPresented = false
        } catch {
            self.error = error.localizedDescription
            // Clear the secure field on failure so the value does not linger in UI state longer than needed.
            value = ""
        }
    }
}
