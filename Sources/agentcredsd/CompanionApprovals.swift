import Foundation
import CryptoKit
import AgentCredsCore
import CompanionProtocol

/// In-memory, per-daemon requests. Restart invalidates every pending request and
/// redemption capability rather than replaying approvals across daemon instances.
final class CompanionApprovals {
    private struct Entry {
        var request: CredentialRequest
        let record: SecretRecord
        let tokenHash: Data
        var credential: String?
    }
    let notifications: CompanionPush
    private var entries: [UUID: Entry] = [:]
    private let lock = NSLock()
    private let vault: VaultStore
    private let audit: AuditLog
    private let unlock: (String) -> Bool
    init(vault: VaultStore, notifications: CompanionPush = CompanionPush(), audit: AuditLog = .shared, unlock: @escaping (String) -> Bool = { reason in ApprovalCeremony.approve(reason: reason) }) {
        self.notifications = notifications; self.vault = vault; self.unlock = unlock; self.audit = audit
    }
    func create(record: SecretRecord, agent: String, purpose: String) throws -> String {
        lock.lock(); defer { lock.unlock() }
        entries = entries.filter { $0.value.request.expiresAt > Date() }
        guard entries.count < 100, !record.policy.allowedHosts.isEmpty, !purpose.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, purpose.count <= 2000 else {
            throw CompanionError.invalid("Too many pending requests, invalid purpose, or credential has no allowed hosts.")
        }
        let request = CredentialRequest(credentialID: record.id, credentialName: record.name, agent: String(agent.prefix(128)), purpose: purpose,
                                        hosts: record.policy.allowedHosts, expiresAt: Date().addingTimeInterval(600),
                                        maximumDuration: max(1, min(record.policy.defaultTTLSeconds, 3600)))
        let token = CompanionCrypto.randomKey().base64EncodedString()
        entries[request.id] = Entry(request: request, record: record, tokenHash: Data(SHA256.hash(data: Data(token.utf8))))
        notifications.notify(request)
        audit.record(client: agent, action: "request_approval", secretName: record.name, decision: "pending")
        let payload: [String: Any] = ["request_id": request.id.uuidString, "status": "pending", "approval_url": ApprovalLink.web(request.id).absoluteString,
                                      "app_url": ApprovalLink.native(request.id).absoluteString, "redemption_token": token,
                                      "expires_at": ISO8601DateFormatter().string(from: request.expiresAt),
                                      "instructions": "Show the user the app link to review on Mac or a paired iPhone. Keep redemption_token private; use approval_status to redeem. Universal HTTPS links require the associated-domain deployment."]
        return String(decoding: try JSONSerialization.data(withJSONObject: payload), as: UTF8.self)
    }
    func list() -> [CredentialRequest] {
        lock.lock(); defer { lock.unlock() }
        return entries.values.map { entry in var request = entry.request; request.status = request.effectiveStatus(); return request }.sorted { $0.createdAt > $1.createdAt }
    }
    func decide(id: UUID, approved: Bool, duration: Int, authorizedVault: VaultStore? = nil, reviewedRequest: CredentialRequest? = nil) throws {
        lock.lock()
        guard var entry = entries[id], entry.request.effectiveStatus() == .pending,
              duration > 0, duration <= entry.request.maximumDuration else {
            lock.unlock(); throw CompanionError.invalid("This request expired, was already decided, or has an invalid duration.")
        }
        if authorizedVault != nil {
            guard let reviewedRequest, (try? TrustedDeviceCrypto.encode(reviewedRequest)) == (try? TrustedDeviceCrypto.encode(entry.request)) else {
                lock.unlock(); throw CompanionError.invalid("Request changed. Refresh and review it again.")
            }
        }
        entry.request.status = approved ? (authorizedVault == nil ? .awaitingMacUnlock : .releasing) : .denied
        entries[id] = entry
        lock.unlock()
        audit.record(client: entry.request.agent, action: "companion_decision", secretName: entry.record.name, decision: entry.request.status.rawValue)
        guard approved else { return }
        let release = { [self] in
            do {
                // A trusted phone supplies a scoped operation handle after its
                // signature is verified; the normal Mac provider stays unchanged.
                let releaseVault = authorizedVault ?? vault
                guard let current = try vault.record(named: entry.record.name), current.id == entry.record.id else {
                    throw CompanionError.invalid("Credential changed after the request")
                }
                if authorizedVault == nil, !vault.promptsEveryTime, !unlock("Companion approved \(entry.request.agent) using “\(entry.record.name)” for \(duration) seconds. Unlock to release.") {
                    finish(id: id, status: .denied); return
                }
                let root = try releaseVault.revealValue(of: current)
                guard isAwaiting(id) else { return }
                let credential = try ProxyHandleMinter().mint(record: current, rootSecret: root,
                    request: MintRequest(client: entry.request.agent, secretName: current.name, purpose: entry.request.purpose, ttlSeconds: duration))
                let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
                finish(id: id, status: .ready, expiresAt: credential.expiresAt, credential: String(decoding: try encoder.encode(credential), as: UTF8.self))
            } catch { finish(id: id, status: .failed) }
        }
        if authorizedVault != nil { release() } else { DispatchQueue.global(qos: .userInitiated).async(execute: release) }
    }
    private func isAwaiting(_ id: UUID) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return entries[id].map { [.awaitingMacUnlock, .releasing].contains($0.request.effectiveStatus()) } ?? false
    }
    private func finish(id: UUID, status: CredentialRequest.Status, expiresAt: Date? = nil, credential: String? = nil) {
        lock.lock(); defer { lock.unlock() }
        guard let entry = entries[id], [.awaitingMacUnlock, .releasing].contains(entry.request.effectiveStatus()) else { return }
        entries[id]?.request.status = status
        if let expiresAt, let currentExpiry = entries[id]?.request.expiresAt { entries[id]?.request.expiresAt = min(currentExpiry, expiresAt) }
        entries[id]?.credential = credential
        if let entry = entries[id] { audit.record(client: entry.request.agent, action: "companion_release", secretName: entry.record.name, decision: status.rawValue) }
    }
    func cancelOutstanding() {
        lock.lock(); defer { lock.unlock() }
        for id in Array(entries.keys) where [.pending, .awaitingMacUnlock, .releasing, .ready].contains(entries[id]!.request.status) {
            entries[id]?.request.status = .denied
            entries[id]?.credential = nil
        }
    }

    func poll(id: UUID, token: String) throws -> String {
        lock.lock(); defer { lock.unlock() }
        guard var entry = entries[id], Data(SHA256.hash(data: Data(token.utf8))) == entry.tokenHash else {
            throw CompanionError.invalid("Unknown request or invalid redemption token")
        }
        let status = entry.request.effectiveStatus()
        if status == .ready, let credential = entry.credential {
            entry.request.status = .redeemed; entry.credential = nil; entries[id] = entry
            return credential
        }
        return "{\"status\":\"\(status.rawValue)\"}"
    }
}
