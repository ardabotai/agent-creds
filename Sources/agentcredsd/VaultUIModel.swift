import Foundation
import Combine
import AgentCredsCore

/// Shared state for the menubar and the management window. Never holds plaintext
/// secret values — only names, kinds, hosts, identity, and audit metadata.
@MainActor
final class VaultUIModel: ObservableObject {
    enum Tab: String, CaseIterable, Identifiable {
        case secrets = "Secrets"
        case identity = "Identity"
        case passkey = "Passkey"
        case audit = "Audit"
        var id: String { rawValue }
    }

    let vault: VaultStore
    private let passkeyCeremony: PasskeyCeremony

    @Published var enrolling = false
    private var refreshing = false
    private var refreshRequested = false
    private let audit: AuditLog
    @Published var secrets: [SecretMetadata] = []
    @Published var identityEmail: String = ""
    @Published var identityUsername: String = ""
    @Published var kekConfig: KEKConfig = .load()
    @Published var auditEvents: [AuditEvent] = []
    @Published var statusLine: String = "agent-creds is running"
    @Published var banner: String?
    @Published var selectedTab: Tab = .secrets

    init(vault: VaultStore, passkeyCeremony: PasskeyCeremony, audit: AuditLog = .shared) {
        self.audit = audit
        self.vault = vault
        self.passkeyCeremony = passkeyCeremony
        refresh()
    }

    func refresh() {
        guard !refreshing else { refreshRequested = true; return }
        refreshing = true
        let vault = vault
        Task {
            let result = await Task.detached {
                Result { try vault.list().sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending } }
            }.value
            switch result {
            case .success(let items): secrets = items
            case .failure(let error): banner = "Could not list vault: \(error.localizedDescription)"
            }
            let identity = Identity.load()
            identityEmail = identity.email ?? ""
            identityUsername = identity.username ?? ""
            kekConfig = KEKConfig.load()
            auditEvents = (try? audit.recent(limit: 40))?.reversed() ?? []
            let protection = kekConfig.source == .passkey ? "passkey-protected" : "Keychain KEK"
            statusLine = "\(secrets.count) secret\(secrets.count == 1 ? "" : "s") · \(protection)"
            refreshing = false
            if refreshRequested {
                refreshRequested = false
                refresh()
            }
        }
    }

    /// Saves a new secret. `value` must come from a secure field and is not retained.
    func addSecret(name: String, kind: SecretKind, hosts: [String], value: String,
                   injection: CredentialInjection = .bearer) async throws {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw VaultUIError.message("Name is required.") }
        let cleanHosts = hosts.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        guard !cleanHosts.isEmpty else {
            throw VaultUIError.message("At least one host is required — empty allowlist denies every host.")
        }
        guard !value.isEmpty else { throw VaultUIError.message("Secret value is required.") }
        try injection.validate()
        let vault = vault
        _ = try await Task.detached {
            try vault.save(name: trimmed, kind: kind, value: Data(value.utf8),
                           policy: SecretPolicy(allowedHosts: cleanHosts, injection: injection),
                           replacingExisting: false)
        }.value
        audit.record(client: "agentcredsd-ui", action: "save", secretName: trimmed, decision: "ui")
        banner = "Saved “\(trimmed)” for \(cleanHosts.joined(separator: ", "))."
        refresh()
    }

    func deleteSecret(named name: String) async throws {
        let vault = vault
        try await Task.detached { try vault.delete(name: name) }.value
        audit.record(client: "agentcredsd-ui", action: "delete", secretName: name, decision: "ui")
        banner = "Deleted “\(name)”."
        refresh()
    }

    func saveIdentity() throws {
        var identity = Identity.load()
        identity.email = identityEmail.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        identity.username = identityUsername.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        try identity.save()
        banner = "Identity updated."
        refresh()
    }

    func enrollPasskey() async {
        guard !enrolling else { return }
        enrolling = true
        defer { enrolling = false }
        let ceremony = passkeyCeremony
        let result = await Task.detached(priority: .userInitiated) {
            AppDelegate.runPasskeyEnrollment(ceremony: ceremony)
        }.value
        await MainActor.run {
            switch result {
            case .success(let outcome):
                banner = "Vault protected by passkey (\(outcome.secretsRewrapped) secret(s) re-wrapped). Passkey protection is active now."
            case .failure(let error):
                banner = "Passkey enrollment failed: \(error)"
            }
            refresh()
        }
    }
}

enum VaultUIError: Error, LocalizedError {
    case message(String)
    var errorDescription: String? {
        switch self {
        case .message(let text): return text
        }
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
