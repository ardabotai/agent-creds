import SwiftUI
import LocalAuthentication
import Security
import CompanionProtocol

@MainActor @Observable
final class CompanionStore {
    enum Section: String, CaseIterable { case requests = "Requests", vault = "Vault", activity = "Activity", devices = "Devices" }
    var section: Section = .requests
    var snapshot: CompanionSnapshot?
    var pairing: PairingInvite?
    var hasOwnerControl = false
    var isDemo = false
    var locked = true
    var busy = false
    var error: String?
    var notice: String?
    var selectedRequest: UUID?
    var pendingLink: UUID?
    private var notificationSyncing = false
    private var notificationSyncRequested = false
    private var pushSyncedAt: Date?
    private var pushSyncedPairing: UUID?
    private var pushSyncedRegistration: PushRegistration?
    var lastSync: Date?
    var connected: Bool { pairing != nil && snapshot != nil && !locked }
    init() {
        pairing = try? PairingKeychain.load()
        hasOwnerControl = pairing.map { DeviceOwnerIdentity.hasIdentity($0.id) } ?? false
        if ProcessInfo.processInfo.arguments.contains("--demo") { startDemo() }
        if let index = ProcessInfo.processInfo.arguments.firstIndex(of: "--approval"),
           ProcessInfo.processInfo.arguments.count > index + 1,
           let url = URL(string: ProcessInfo.processInfo.arguments[index + 1]) { open(url) }
    }
    func authenticate(_ reason: String) async throws {
        if isDemo { return }
        let context = LAContext()
        var authError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &authError) else {
            throw CompanionError.invalid("Set up Face ID or a device passcode to use your vault.")
        }
        guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else {
            throw CompanionError.invalid("Authentication cancelled")
        }
    }
    func unlock() async {
        do { try await authenticate("Open your paired credential vault"); locked = false; await refresh() }
        catch { self.error = error.localizedDescription }
    }
    func lock() { if !isDemo { locked = true; snapshot = nil } }
    func pair(code: String) async {
        guard !busy else { return }
        busy = true; defer { busy = false }
        do {
            let candidate = try PairingInvite.parse(code)
            isDemo = false
            try await authenticate("Pair with \(candidate.macName)")
            let reply = try await CompanionNetwork.exchange(CompanionCommand(action: .snapshot), pairing: candidate)
            if let previous = pairing { DeviceOwnerIdentity.delete(previous.id) }
            hasOwnerControl = false
            try PairingKeychain.save(candidate)
            pairing = candidate; snapshot = reply.snapshot; locked = false; lastSync = Date()
            notice = "Confirm “Trust this iPhone” on your Mac to finish pairing."
            resolvePendingLink()
            let finalPairing = try await DeviceOwnerIdentity.enroll(pairing: candidate)
            try PairingKeychain.save(finalPairing); pairing = finalPairing
            hasOwnerControl = true
            notice = "Paired. This iPhone can now manage the vault and approve requests independently."
            await ApprovalNotifications.shared.enable()
            await syncNotifications()
        } catch { self.error = error.localizedDescription }
    }
    func refresh() async {
        guard !isDemo, !locked, !busy, let pairing else { return }
        busy = true; defer { busy = false }
        do {
            let result = try await CompanionNetwork.exchange(CompanionCommand(action: .snapshot), pairing: pairing)
            guard !locked else { return }
            snapshot = result.snapshot; lastSync = Date(); error = nil; resolvePendingLink(); await syncNotifications()
        } catch { self.error = "Could not reach your Mac. Keep agent-creds running on the Mac and check its internet connection. \(error.localizedDescription)" }
    }
    func perform(_ command: CompanionCommand) async -> Bool {
        guard !busy, !locked else { return false }
        busy = true; defer { busy = false }
        do {
            if !hasOwnerControl || isDemo { try await authenticate(command.action == .approve ? "Approve this credential request" : "Confirm this vault change") }
            if isDemo { try simulate(command); return true }
            guard let pairing else { throw CompanionError.invalid("Pair your Mac first") }
            var command = command
            if [.approve, .deny].contains(command.action) {
                command.reviewedRequest = snapshot?.requests.first { $0.id == command.requestID }
            }
            let reply: CompanionReply
            if hasOwnerControl {
                reply = try await CompanionNetwork.exchange(command, pairing: pairing) { command, challenge in
                    let authorized = try await DeviceOwnerIdentity.authorize(command, challenge: challenge, pairing: pairing)
                    guard !self.locked, self.pairing?.id == pairing.id, !self.isDemo else { throw CompanionError.invalid("Companion locked before authorization completed") }
                    return authorized
                }
            } else { reply = try await CompanionNetwork.exchange(command, pairing: pairing) }
            if !locked { snapshot = reply.snapshot; lastSync = Date() }
            notice = command.action == .approve ? (hasOwnerControl ? "iPhone authorization processed. Check the request status for the release result." : "Approved on iPhone. Unlock on your Mac to release the credential.") : "Vault change confirmed."
            return true
        } catch { self.error = error.localizedDescription; return false }
    }
    func disconnect() async {
        if isDemo {
            isDemo = false; snapshot = nil; locked = true; selectedRequest = nil; notice = nil
            return
        }
        if !isDemo, let pairing { _ = try? await CompanionNetwork.exchange(CompanionCommand(action: .disconnect), pairing: pairing) }
        if let pairing { DeviceOwnerIdentity.delete(pairing.id) }
        hasOwnerControl = false
        try? PairingKeychain.delete()
        self.pairing = nil; snapshot = nil; isDemo = false; locked = true; selectedRequest = nil; notice = nil
    }
    func enableOwnerControl() async {
        guard !busy, !locked, !isDemo, !hasOwnerControl, let pairing else { return }
        busy = true; defer { busy = false }
        do {
            let finalPairing = try await DeviceOwnerIdentity.enroll(pairing: pairing)
            try PairingKeychain.save(finalPairing); self.pairing = finalPairing
            hasOwnerControl = true
            notice = "This iPhone can now control the vault without another Mac prompt."
        } catch { self.error = error.localizedDescription }
    }
    func syncNotifications() async {
        notificationSyncRequested = true
        guard !notificationSyncing else { return }
        notificationSyncing = true
        defer { notificationSyncing = false }
        while notificationSyncRequested {
            notificationSyncRequested = false
            guard !isDemo, let pairing else { return }
            let registration = ApprovalNotifications.shared.registration
            if pushSyncedPairing == pairing.id, pushSyncedRegistration == registration, let pushSyncedAt, Date().timeIntervalSince(pushSyncedAt) < 60 { continue }
            var command = CompanionCommand(action: registration == nil ? .unregisterPush : .registerPush)
            command.push = ApprovalNotifications.shared.registration
            do {
                let reply = try await CompanionNetwork.exchange(command, pairing: pairing)
                guard self.pairing?.id == pairing.id else { continue }
                pushSyncedAt = Date(); pushSyncedPairing = pairing.id; pushSyncedRegistration = registration
                ApprovalNotifications.shared.delivery = reply.notificationStatus ?? "Push registration disabled"
            } catch { ApprovalNotifications.shared.delivery = "Could not register with Mac; reconnect to enable alerts" }
        }
    }
    func consumeNotification() async {
        guard let route = ApprovalNotifications.shared.pendingRoute else { return }
        ApprovalNotifications.shared.pendingRoute = nil
        guard !isDemo, pairing?.id == route.pairingID else {
            error = "This notification belongs to another or expired Mac pairing. Reconnect to review current requests."
            return
        }
        // Discard cached request data: notification contents never authorize access.
        pendingLink = route.requestID; section = .requests
        if locked { await unlock() } else { await refresh() }
    }
    func open(_ url: URL) {
        guard let id = ApprovalLink.requestID(from: url) else { error = "That link is not a valid credential request."; return }
        pendingLink = id; section = .requests
        if snapshot != nil { resolvePendingLink() }
    }
    private func resolvePendingLink() {
        guard let id = pendingLink, let snapshot else { return }
        if snapshot.requests.contains(where: { $0.id == id }) { selectedRequest = id }
        else { error = "This request is unavailable. It may have expired or belong to a different Mac session." }
        pendingLink = nil
    }
    func startDemo() {
        isDemo = true; locked = false; error = nil; notice = nil
        let github = VaultItem(id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!, name: "GitHub", hosts: ["api.github.com"])
        let stripe = VaultItem(name: "Stripe", hosts: ["api.stripe.com"])
        let linear = VaultItem(name: "Linear", hosts: ["api.linear.app"], authentication: "header", headerName: "Authorization")
        snapshot = CompanionSnapshot(macName: "Studio Mac", protection: "passkey", items: [github, stripe, linear], requests: [
            CredentialRequest(id: UUID(uuidString: "00000000-0000-0000-0000-000000000101")!, credentialID: github.id, credentialName: "GitHub", agent: "Codex", purpose: "Read the open pull requests and prepare a review summary.", hosts: github.hosts, expiresAt: Date().addingTimeInterval(600)),
            CredentialRequest(credentialID: stripe.id, credentialName: "Stripe", agent: "Claude", purpose: "Check the status of recent payments.", hosts: stripe.hosts, expiresAt: Date().addingTimeInterval(480))
        ], activity: [CompanionActivity(title: "Vault connected", detail: "Synthetic demo · no real credentials")])
        lastSync = Date(); resolvePendingLink()
    }
    private func simulate(_ command: CompanionCommand) throws {
        guard var state = snapshot else { return }
        switch command.action {
        case .approve, .deny:
            guard let index = state.requests.firstIndex(where: { $0.id == command.requestID }), state.requests[index].effectiveStatus() == .pending else { throw CompanionError.invalid("Request is no longer pending") }
            state.requests[index].status = command.action == .approve ? .awaitingMacUnlock : .denied
            notice = command.action == .approve ? "Demo approval recorded. A real request would now wait for Mac unlock." : "Demo request denied."
        case .add:
            guard let item = command.item, !state.items.contains(where: { $0.name.lowercased() == item.name.lowercased() }) else { throw CompanionError.invalid("A credential with that name already exists") }
            state.items.append(item); notice = "Demo credential added. The entered value was not saved."
        case .updatePolicy:
            if let item = command.item, let index = state.items.firstIndex(where: { $0.id == item.id }) { state.items[index] = item }
        case .delete: state.items.removeAll { $0.id == command.item?.id }
        default: break
        }
        state.activity.insert(CompanionActivity(title: command.action.rawValue, detail: "Synthetic demo"), at: 0)
        snapshot = state
    }
}

private enum PairingKeychain {
    static let service = "ai.ardabot.agentcreds.companion.pairing"
    static let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "mac"]
    static func load() throws -> PairingInvite? {
        var lookup = query; lookup[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw CompanionError.invalid("Could not unlock pairing") }
        return try JSONDecoder().decode(PairingInvite.self, from: data)
    }
    static func save(_ value: PairingInvite) throws {
        let data = try JSONEncoder().encode(value)
        var attributes = query
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            guard SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary) == errSecSuccess else { throw CompanionError.invalid("Could not save pairing") }
        } else if status != errSecSuccess { throw CompanionError.invalid("Could not save pairing") }
    }
    static func delete() throws { SecItemDelete(query as CFDictionary) }
}
