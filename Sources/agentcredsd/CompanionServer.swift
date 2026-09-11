import Foundation
import Network
import AppKit
import CoreImage
import AgentCredsCore
import CompanionProtocol

/// Relay-first companion service. Trusted relay pairings persist in Keychain.
/// The opt-in LAN path remains available for tests and legacy callers.
final class CompanionServer {
    private let vault: VaultStore
    let approvals: CompanionApprovals
    private let queue = DispatchQueue(label: "agentcreds.companion.server")
    private var listener: NWListener?
    private var pairings: [UUID: PairingInvite] = [:]
    private let lock = NSLock()
    private var ownerKeys: [UUID: Data] = [:]
    private let relaySetupLock = NSLock()
    private var relayConfigured = false
    private var relayClient: CompanionRelay?
    private var stateStorage: CompanionStateStorage?
    private var activeConnections = 0
    private let port: UInt16
    private let audit: AuditLog
    private let authenticate: (String) -> Bool
    init(vault: VaultStore, approvals: CompanionApprovals, port: UInt16 = 9978, audit: AuditLog = .shared, authenticate: @escaping (String) -> Bool = { ApprovalCeremony.approve(reason: $0) }) { self.vault = vault; self.approvals = approvals; self.port = port; self.audit = audit; self.authenticate = authenticate }

    /// Called by the app on a worker. Tests inject a temporary state store.
    func enableRelay(url: String, storage: CompanionStateStorage) throws {
        relaySetupLock.lock(); defer { relaySetupLock.unlock() }
        if relayConfigured { relayClient?.start(); return }
        relayClient?.stop()
        let saved = try storage.load()
        let address = saved?.relay ?? RelayAddress(url: url, roomID: UUID(), token: Self.routingToken())
        guard address.url == url, address.isValid else { throw CompanionError.invalid("Relay configuration changed. Revoke previous companions before switching services.") }
        let client = CompanionRelay(address: address) { [weak self] pairingID, challenge, wire in
            guard let self else { throw CompanionError.invalid("Mac unavailable") }
            return try self.processRelay(pairingID: pairingID, challenge: challenge, wire: wire)
        }
        lock.lock()
        if let saved { pairings = saved.pairings; ownerKeys = saved.ownerKeys }
        stateStorage = storage; relayClient = client
        do { try persistLocked() } catch { lock.unlock(); throw error }
        let active = pairings.values.filter { min($0.expiresAt, $0.enrollmentExpiresAt ?? $0.expiresAt) > Date() }
        lock.unlock()
        _ = try client.control("", method: "PUT")
        let remote = try client.control("/devices", method: "GET")["devices"] as? [String] ?? []
        let ids = Set(active.map { $0.id.uuidString.lowercased() })
        for id in remote where !ids.contains(id) { _ = try client.control("/devices/" + id, method: "DELETE") }
        for invite in active { try client.register(invite) }
        approvals.notifications.setRelay { request in
            _ = try? client.control("/notify", method: "POST", object: ["requestID": request.id.uuidString.lowercased(), "expiresAt": request.expiresAt.timeIntervalSince1970 * 1000])
        }
        client.start(); relayConfigured = true
    }
    func stopRelay() { relayClient?.stop() }
    private static func routingToken() -> String { CompanionCrypto.randomKey().map { String(format: "%02x", $0) }.joined() }
    private func persistLocked() throws {
        guard let stateStorage, let relayClient else { return }
        try stateStorage.save(CompanionPersistentState(relay: relayClient.address, pairings: pairings, ownerKeys: ownerKeys))
    }
    private func processRelay(pairingID: UUID, challenge: Data, wire: Data) throws -> Data {
        guard let pairing = pairing(id: pairingID) else { throw CompanionError.invalid("Pairing revoked or expired") }
        let envelope = try JSONDecoder().decode(CompanionEnvelope.self, from: wire)
        guard envelope.pairingID == pairingID else { throw CompanionError.invalid("Wrong device") }
        let command = try CompanionCrypto.open(CompanionCommand.self, data: envelope.ciphertext, key: pairing.key, challenge: challenge, direction: "request")
        let reply = handle(command, pairingID: pairingID, challenge: challenge)
        return try CompanionCrypto.seal(reply, key: pairing.key, challenge: challenge, direction: "response")
    }

    func start() throws {
        guard listener == nil else { return }
        let listener = try NWListener(using: .tcp, on: port == 0 ? .any : NWEndpoint.Port(rawValue: port)!)
        let ready = DispatchSemaphore(value: 0)
        var startupError: Error?
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready: ready.signal()
            case .failed(let error): startupError = error; ready.signal()
            default: break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success, startupError == nil, listener.port != nil else { listener.cancel(); throw startupError ?? CompanionError.invalid("Could not start local companion connection") }
        self.listener = listener
    }
    @discardableResult func revokeAll() -> Bool {
        lock.lock(); let previous = pairings; pairings.removeAll(); ownerKeys.removeAll()
        // On persistence failure retain a fail-closed in-memory revocation and
        // surface the error; never silently claim durable revocation succeeded.
        var persisted = true
        do { try persistLocked() } catch { persisted = false }
        lock.unlock()
        approvals.notifications.revoke(); approvals.cancelOutstanding()
        for id in previous.keys { _ = try? relayClient?.control("/devices/\(id.uuidString.lowercased())", method: "DELETE") }
        listener?.cancel(); listener = nil
        return persisted
    }
    func invite() throws -> PairingInvite {
        let hostname = Host.current().localizedName ?? "Mac"
        var invite: PairingInvite
        if let relayClient {
            // Restart/reconnect is independent of an individual phone's lifetime.
            _ = try relayClient.control("", method: "PUT")
            relayClient.start()
            let limit = Date().addingTimeInterval(10)
            while !relayClient.isConnected && Date() < limit { Thread.sleep(forTimeInterval: 0.05) }
            guard relayClient.isConnected else { throw CompanionError.invalid("Mac could not connect to relay") }
            invite = PairingInvite(host: "relay", port: 443, key: CompanionCrypto.randomKey(), macName: hostname, expiresAt: Date().addingTimeInterval(365 * 86400))
            invite.enrollmentExpiresAt = Date().addingTimeInterval(600)
            invite.relay = RelayAddress(url: relayClient.address.url, roomID: relayClient.address.roomID, token: Self.routingToken())
            try relayClient.register(invite)
        } else {
            try start()
            guard let localName = Self.localHostName() else { throw CompanionError.invalid("No local network hostname") }
            invite = PairingInvite(host: localName, port: listener!.port!.rawValue, key: CompanionCrypto.randomKey(), macName: hostname, expiresAt: Date().addingTimeInterval(86400))
        }
        lock.lock(); defer { lock.unlock() }
        pairings = pairings.filter { min($0.value.expiresAt, $0.value.enrollmentExpiresAt ?? $0.value.expiresAt) > Date() }
        guard pairings.count < 8 else { throw CompanionError.invalid("Revoke existing companions before pairing more devices.") }
        pairings[invite.id] = invite
        do { try persistLocked() } catch { pairings[invite.id] = nil; throw error }
        return invite
    }
    private static func localHostName() -> String? {
        // Bonjour's LocalHostName is the hostname reachable from other devices.
        if let name = SCDynamicStoreCopyLocalHostName(nil) as String? { return name + ".local" }
        return nil
    }
    private func accept(_ connection: NWConnection) {
        lock.lock()
        guard activeConnections < 16 else { lock.unlock(); connection.cancel(); return }
        activeConnections += 1; lock.unlock()
        connection.start(queue: queue)
        let timeout = DispatchWorkItem { connection.cancel() }
        queue.asyncAfter(deadline: .now() + 180, execute: timeout)
        Task {
            defer { timeout.cancel(); connection.cancel(); connectionFinished() }
            do {
                let challenge = CompanionCrypto.randomKey()
                try await CompanionNetwork.send(challenge, over: connection)
                let wire = try await CompanionNetwork.receive(over: connection)
                let envelope = try JSONDecoder().decode(CompanionEnvelope.self, from: wire)
                guard let pairing = pairing(id: envelope.pairingID) else { return }
                let command = try CompanionCrypto.open(CompanionCommand.self, data: envelope.ciphertext, key: pairing.key, challenge: challenge, direction: "request")
                // Process on a worker; vault operations can require a Mac prompt.
                let reply = await Task.detached { self.handle(command, pairingID: pairing.id, challenge: challenge) }.value
                let encrypted = try CompanionCrypto.seal(reply, key: pairing.key, challenge: challenge, direction: "response")
                try await CompanionNetwork.send(encrypted, over: connection)
            } catch { /* No plaintext or client-controlled error is logged. */ }
        }
    }
    private func connectionFinished() { lock.lock(); activeConnections -= 1; lock.unlock() }
    private func pairing(id: UUID) -> PairingInvite? {
        lock.lock(); defer { lock.unlock() }
        guard let value = pairings[id], min(value.expiresAt, value.enrollmentExpiresAt ?? value.expiresAt) > Date() else { return nil }
        return value
    }
    private func snapshot() throws -> CompanionSnapshot {
        let items = try vault.list().compactMap { metadata -> VaultItem? in
            guard let record = try vault.record(named: metadata.name) else { return nil }
            var item = VaultItem(id: record.id, name: record.name, kind: record.kind.rawValue, hosts: record.policy.allowedHosts)
            switch record.policy.injection {
            case .bearer: break
            case .basic(let username): item.authentication = "basic"; item.username = username
            case .header(let name, let prefix): item.authentication = "header"; item.headerName = name; item.headerPrefix = prefix
            }
            return item
        }
        let events = (try? audit.recent(limit: 30)) ?? []
        return CompanionSnapshot(macName: Host.current().localizedName ?? "Mac", protection: KEKConfig.load().source.rawValue,
                                 items: items.sorted { $0.name < $1.name }, requests: approvals.list(),
                                 activity: events.reversed().map { CompanionActivity(title: $0.action, detail: "\($0.client) · \($0.decision ?? "")", date: $0.timestamp) })
    }
    private func handle(_ command: CompanionCommand, pairingID: UUID, challenge: Data) -> CompanionReply {
        do {
            guard pairing(id: pairingID) != nil else { throw CompanionError.invalid("Pairing revoked or expired") }
            if command.action == .enrollOwner {
                guard let enrollment = command.enrollment else { throw CompanionError.invalid("Missing device keys") }
                try TrustedDeviceCrypto.verify(command, publicKey: enrollment.signingPublicKey, pairingID: pairingID, challenge: challenge)
                guard authenticate("Trust this iPhone as a vault owner? It can independently approve agent access and add, edit or delete credentials after Face ID or its passcode. This adds a second unlock path to your vault.") else { throw CompanionError.invalid("Mac declined device trust") }
                let key = try vault.keyForTrustedDeviceEnrollment()
                let capsule = try TrustedDeviceCrypto.wrap(key, for: enrollment.agreementPublicKey, pairingID: pairingID)
                lock.lock(); defer { lock.unlock() }
                guard pairings[pairingID]?.expiresAt ?? .distantPast > Date(), ownerKeys[pairingID] == nil else { throw CompanionError.invalid("Pairing expired or already trusted. Pair again to change owner keys.") }
                let previous = pairings[pairingID]!
                var finalInvite = previous
                if finalInvite.relay != nil {
                    finalInvite.key = CompanionCrypto.randomKey()
                    finalInvite.relay?.token = Self.routingToken()
                    finalInvite.enrollmentExpiresAt = nil
                    try relayClient?.register(finalInvite)
                }
                ownerKeys[pairingID] = enrollment.signingPublicKey
                pairings[pairingID] = finalInvite
                do { try persistLocked() } catch { ownerKeys[pairingID] = nil; pairings[pairingID] = previous; throw error }
                var reply = CompanionReply(id: command.id); reply.keyCapsule = capsule
                if finalInvite.relay != nil { reply.pairedInvite = finalInvite }
                audit.record(client: "companion", action: "trust_owner", decision: "approved")
                return reply
            }
            let protected = [CompanionCommand.Action.approve, .deny, .add, .updatePolicy, .delete].contains(command.action)
            lock.lock()
            let ownerKey = ownerKeys[pairingID]
            lock.unlock()
            var operationVault = vault
            let trusted = protected && ownerKey != nil
            if trusted {
                try TrustedDeviceCrypto.verify(command, publicKey: ownerKey!, pairingID: pairingID, challenge: challenge)
                guard let key = command.vaultKey else { throw CompanionError.invalid("Missing phone-authorized vault key") }
                operationVault = try vault.authorizedDeviceVault(key: key)
            }
            // Trusted operations contain no UI waits. Serialize their execution
            // with revocation so a revoked owner cannot start a vault mutation.
            if trusted { lock.lock() }
            defer { if trusted { lock.unlock() } }
            if trusted {
                guard ownerKeys[pairingID] == ownerKey, pairings[pairingID]?.expiresAt ?? .distantPast > Date() else { throw CompanionError.invalid("Device revoked") }
            }
            switch command.action {
            case .enrollOwner: throw CompanionError.invalid("Invalid enrollment")
            case .snapshot: break
            case .registerPush:
                guard let registration = command.push else { throw CompanionError.invalid("Missing push registration") }
                var reply = CompanionReply(id: command.id)
                reply.notificationStatus = try registerPush(registration, pairingID: pairingID)
                return reply
            case .unregisterPush:
                if let relayClient { _ = try relayClient.control("/push/\(pairingID.uuidString.lowercased())", method: "DELETE") }
                approvals.notifications.revoke(pairingID)
                return CompanionReply(id: command.id)
            case .approve, .deny:
                guard let id = command.requestID else { throw CompanionError.invalid("Missing request") }
                try approvals.decide(id: id, approved: command.action == .approve, duration: command.duration ?? 1, authorizedVault: trusted ? operationVault : nil, reviewedRequest: command.reviewedRequest)
            case .add:
                guard let item = command.item, let value = command.value, !value.isEmpty, value.utf8.count <= 16384 else { throw CompanionError.invalid("Enter a secret value") }
                let policy = try policy(for: item)
                // Capture in the app already requires user authentication. The Mac
                // also approves sensitive writes, preventing a copied QR from silently changing the vault.
                guard trusted || authenticate("Your companion wants to add “\(item.name)” to the vault") else { throw CompanionError.invalid("Mac declined the save") }
                guard trusted || pairing(id: pairingID) != nil else { throw CompanionError.invalid("Pairing revoked") }
                try operationVault.save(name: item.name, kind: .opaque, value: Data(value.utf8), policy: policy, replacingExisting: false)
                audit.record(client: "companion", action: "save", secretName: item.name, decision: "approved")
            case .updatePolicy, .delete:
                guard let item = command.item else { throw CompanionError.invalid("Missing credential") }
                guard trusted || authenticate("Your companion wants to \(command.action == .delete ? "delete" : "change the policy of") “\(item.name)”") else { throw CompanionError.invalid("Mac declined the change") }
                guard trusted || pairing(id: pairingID) != nil else { throw CompanionError.invalid("Pairing revoked") }
                if command.action == .delete { try operationVault.delete(name: item.name, expectedID: item.id) }
                else {
                    guard let current = try vault.record(named: item.name), current.id == item.id else { throw CompanionError.invalid("Credential changed. Refresh before editing.") }
                    if let value = command.value, value.isEmpty || value.utf8.count > 16384 { throw CompanionError.invalid("Invalid replacement value") }
                    let edited = try policy(for: item)
                    var updated = current.policy
                    updated.allowedHosts = edited.allowedHosts; updated.injection = edited.injection
                    try operationVault.updatePolicy(name: item.name, expectedID: item.id, policy: updated, replacementValue: command.value.map { Data($0.utf8) })
                }
                audit.record(client: "companion", action: command.action.rawValue, secretName: item.name, decision: "approved")
            case .disconnect:
                lock.lock(); let previousPairing = pairings[pairingID]; let previousOwner = ownerKeys[pairingID]
                pairings[pairingID] = nil; ownerKeys[pairingID] = nil
                do { try persistLocked() } catch { pairings[pairingID] = previousPairing; ownerKeys[pairingID] = previousOwner; lock.unlock(); throw error }
                lock.unlock()
                // Send the final encrypted response before dropping this relay channel.
                if let relayClient { DispatchQueue.global().asyncAfter(deadline: .now() + 1) { _ = try? relayClient.control("/devices/\(pairingID.uuidString.lowercased())", method: "DELETE") } }
                approvals.notifications.revoke(pairingID)
                approvals.cancelOutstanding()
                return CompanionReply(id: command.id)
            }
            return CompanionReply(id: command.id, snapshot: try snapshot())
        } catch { return CompanionReply(id: command.id, error: error.localizedDescription) }
    }
    private func registerPush(_ registration: PushRegistration, pairingID: UUID) throws -> String {
        // Serialize registration with revocation, so an in-flight registration
        // cannot recreate a subscription after the pairing has been removed.
        lock.lock(); defer { lock.unlock() }
        guard let invite = pairings[pairingID], invite.expiresAt > Date() else { throw CompanionError.invalid("Pairing revoked or expired") }
        if let relayClient {
            guard registration.isValid else { throw CompanionError.invalid("Invalid push registration") }
            let result = try relayClient.control("/push/\(pairingID.uuidString.lowercased())", method: "PUT", object: ["token": registration.token, "environment": registration.environment])
            return result["notificationStatus"] as? String ?? "Registered with relay"
        }
        return try approvals.notifications.register(registration, pairing: invite)
    }
    private func policy(for item: VaultItem) throws -> SecretPolicy {
        let name = item.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard name == item.name, !name.isEmpty, name.count <= 256, !item.hosts.isEmpty,
              item.hosts.count <= 20, item.hosts.allSatisfy({ host in
                  !host.isEmpty && host.count <= 253 && host.unicodeScalars.allSatisfy { CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-").contains($0) }
              }) else { throw CompanionError.invalid("Use a name and valid hostnames without schemes or paths") }
        let injection: CredentialInjection
        switch item.authentication {
        case "bearer": injection = .bearer
        case "basic": injection = .basic(username: item.username)
        case "header": injection = .header(name: item.headerName, prefix: item.headerPrefix)
        default: throw CompanionError.invalid("Unsupported authentication")
        }
        try injection.validate()
        return SecretPolicy(allowedHosts: item.hosts, injection: injection)
    }
}
import SystemConfiguration
