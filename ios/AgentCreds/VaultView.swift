import SwiftUI
import CompanionProtocol

struct VaultView: View {
    @Bindable var store: CompanionStore
    @State private var adding = false
    @State private var editing: VaultItem?
    @State private var search = ""
    var body: some View {
        NavigationStack {
            List {
                Section { Text("Credential values stay hidden. Review or change where each credential can be used.").font(.subheadline).foregroundStyle(.secondary) }
                ForEach((store.snapshot?.items ?? []).filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.hosts.contains(where: { $0.localizedCaseInsensitiveContains(search) }) }) { item in
                    Button { editing = item } label: {
                        HStack(spacing: 14) {
                            Image(systemName: "key.horizontal").frame(width: 36, height: 36).background(.tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
                            VStack(alignment: .leading, spacing: 4) { Text(item.name).font(.headline).foregroundStyle(.primary); Text(item.hosts.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
                            Spacer(); Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
                        }.padding(.vertical, 5)
                    }.buttonStyle(.plain)
                }
            }.navigationTitle("Vault").searchable(text: $search, prompt: "Name or destination")
                .toolbar { ToolbarItem(placement: .primaryAction) { Button { adding = true } label: { Label("Add credential", systemImage: "plus") }.accessibilityIdentifier("addCredential") } }
                .overlay { if store.snapshot?.items.isEmpty == true { ContentUnavailableView("Your vault is empty", systemImage: "key", description: Text("Add your first credential to get started.")) } }
                .refreshable { await store.refresh() }
                .sheet(isPresented: $adding) { CredentialEditor(store: store, existing: nil) }
                .sheet(item: $editing) { item in CredentialEditor(store: store, existing: item) }
        }
    }
}

struct CredentialEditor: View {
    @Bindable var store: CompanionStore
    let existing: VaultItem?
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var phase
    @State private var name = ""
    @State private var hosts = ""
    @State private var value = ""
    @State private var authentication = "bearer"
    @State private var username = ""
    @State private var headerName = "X-Api-Key"
    @State private var headerPrefix = ""
    @State private var confirmingDelete = false
    var body: some View {
        NavigationStack {
            Form {
                Section("Credential") {
                    TextField("Name", text: $name).textInputAutocapitalization(.never).autocorrectionDisabled().disabled(existing != nil).accessibilityIdentifier("credentialName")
                    if existing == nil { SecureField("Secret value", text: $value).textContentType(.newPassword).accessibilityIdentifier("credentialValue") }
                    else {
                        SecureField("Replacement value (optional)", text: $value).textContentType(.newPassword)
                        Label("Leave blank to keep the stored value", systemImage: "lock.fill").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section {
                    TextField("api.example.com, example.com", text: $hosts, axis: .vertical).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL).accessibilityIdentifier("credentialHosts")
                } header: { Text("Allowed hosts") } footer: { Text("Use hostnames without https:// or paths. These hosts and their subdomains can receive this credential.") }
                Section("Authentication") {
                    Picker("Type", selection: $authentication) { Text("Bearer token").tag("bearer"); Text("Custom header").tag("header"); Text("Basic").tag("basic") }
                    if authentication == "basic" { TextField("Username", text: $username).textInputAutocapitalization(.never).autocorrectionDisabled() }
                    if authentication == "header" { TextField("Header name", text: $headerName).textInputAutocapitalization(.never).autocorrectionDisabled(); TextField("Prefix (optional)", text: $headerPrefix).textInputAutocapitalization(.never).autocorrectionDisabled() }
                }
                Section {
                    if store.busy { ProgressView(store.isDemo || store.hasOwnerControl ? "Saving…" : "Confirm the change on your Mac…") }
                    else { Text(store.isDemo ? "Demo only: entered values are discarded." : (store.hasOwnerControl ? "Authorize with Face ID or your passcode. No additional Mac confirmation is needed." : "Authenticate on this device, then confirm on your Mac. Enable independent iPhone control in Devices.")).font(.caption).foregroundStyle(.secondary) }
                }
                if existing != nil { Section { Button("Delete credential", role: .destructive) { confirmingDelete = true } } }
            }.navigationTitle(existing == nil ? "Add credential" : "Credential settings").navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { value = ""; dismiss() }.disabled(store.busy) }
                    ToolbarItem(placement: .confirmationAction) { Button("Save") { Task { await save() } }.disabled(store.busy || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || hosts.isEmpty || (existing == nil && value.isEmpty)) }
                }
                .interactiveDismissDisabled(store.busy)
                .confirmationDialog("Delete this credential permanently?", isPresented: $confirmingDelete, titleVisibility: .visible) {
                    Button("Delete credential", role: .destructive) { Task { if await store.perform(CompanionCommand(action: .delete, item: existing)) { dismiss() } } }
                } message: { Text("This removes it from the Mac vault. Existing issued handles keep their original expiration.") }
                .onAppear {
                    if let item = existing { name = item.name; hosts = item.hosts.joined(separator: ", "); authentication = item.authentication; username = item.username; headerName = item.headerName; headerPrefix = item.headerPrefix }
                }
                .onChange(of: phase) { _, state in if state == .background { value = "" } }
        }
    }
    private func save() async {
        let item = VaultItem(id: existing?.id ?? UUID(), name: name.trimmingCharacters(in: .whitespacesAndNewlines), kind: existing?.kind ?? "opaque",
                             hosts: hosts.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }, authentication: authentication, headerName: headerName, headerPrefix: headerPrefix, username: username)
        let success = await store.perform(CompanionCommand(action: existing == nil ? .add : .updatePolicy, item: item, value: existing == nil || !value.isEmpty ? value : nil))
        value = ""
        if success { dismiss() }
    }
}
