import XCTest
import CryptoKit
import CompanionProtocol
import AgentCredsCore
@testable import agentcredsd

final class TrustedDeviceTests: XCTestCase {
    func testSignatureBindsCommandChallengeDeviceAndReviewedRequest() throws {
        let signing = P256.Signing.PrivateKey(), id = UUID(), challenge = CompanionCrypto.randomKey()
        var command = CompanionCommand(action: .approve, requestID: UUID(), duration: 120)
        command.vaultKey = CompanionCrypto.randomKey()
        command.signature = try signing.signature(for: TrustedDeviceCrypto.signingData(command, pairingID: id, challenge: challenge)).rawRepresentation
        try TrustedDeviceCrypto.verify(command, publicKey: signing.publicKey.x963Representation, pairingID: id, challenge: challenge)
        XCTAssertThrowsError(try TrustedDeviceCrypto.verify(command, publicKey: signing.publicKey.x963Representation, pairingID: UUID(), challenge: challenge))
        XCTAssertThrowsError(try TrustedDeviceCrypto.verify(command, publicKey: signing.publicKey.x963Representation, pairingID: id, challenge: CompanionCrypto.randomKey()))
        XCTAssertThrowsError(try TrustedDeviceCrypto.verify(command, publicKey: P256.Signing.PrivateKey().publicKey.x963Representation, pairingID: id, challenge: challenge))
        var altered = command; altered.duration = 3600
        XCTAssertThrowsError(try TrustedDeviceCrypto.verify(altered, publicKey: signing.publicKey.x963Representation, pairingID: id, challenge: challenge))
        altered = command; altered.action = .delete
        XCTAssertThrowsError(try TrustedDeviceCrypto.verify(altered, publicKey: signing.publicKey.x963Representation, pairingID: id, challenge: challenge))
    }
    func testCapsuleRequiresDevicePrivateKeyAndOriginalPairing() throws {
        let agreement = P256.KeyAgreement.PrivateKey(), id = UUID(), key = SymmetricKey(size: .bits256)
        let capsule = try TrustedDeviceCrypto.wrap(key, for: agreement.publicKey.x963Representation, pairingID: id)
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: capsule.ephemeralPublicKey)
        let shared = try agreement.sharedSecretFromKeyAgreement(with: ephemeral)
        XCTAssertEqual(try TrustedDeviceCrypto.unwrap(capsule, shared: shared, pairingID: id), key.withUnsafeBytes { Data($0) })
        XCTAssertThrowsError(try TrustedDeviceCrypto.unwrap(capsule, shared: shared, pairingID: UUID()))
        let wrong = try P256.KeyAgreement.PrivateKey().sharedSecretFromKeyAgreement(with: ephemeral)
        XCTAssertThrowsError(try TrustedDeviceCrypto.unwrap(capsule, shared: wrong, pairingID: id))
    }
    func testTrustedPhoneManagesPasskeyVaultAndReleasesWithoutMacPrompt() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("vault.json")
        let key = SymmetricKey(size: .bits256)
        let initial = try VaultStore(url: url, kek: SymmetricKey(size: .bits256))
        try initial.save(name: "synthetic", kind: .opaque, value: Data("synthetic-secret".utf8), policy: SecretPolicy(allowedHosts: ["example.test"]))
        _ = try initial.migrateToPasskey(key: key, config: KEKConfig(source: .passkey, relyingParty: "example.test", credentialID: Data([1]), salt: Data([2]), kekCheck: PasskeyKEK.check(for: key)))
        let provider = CountingProvider(key: key)
        let vault = try VaultStore(url: url, kekProvider: provider)
        let audit = AuditLog(url: directory.appendingPathComponent("audit.jsonl"))
        let approvals = CompanionApprovals(vault: vault, notifications: CompanionPush(configuration: nil), audit: audit, unlock: { _ in XCTFail("Unexpected Mac unlock"); return false })
        var confirmations = 0
        var server = CompanionServer(vault: vault, approvals: approvals, port: 0, audit: audit, authenticate: { _ in confirmations += 1; return confirmations == 1 })
        let stateURL = directory.appendingPathComponent("companion-state.json")
        let storage = CompanionStateStorage(load: {
            guard FileManager.default.fileExists(atPath: stateURL.path) else { return nil }
            return try JSONDecoder().decode(CompanionPersistentState.self, from: Data(contentsOf: stateURL))
        }, save: { state in try SecureFile.write(JSONEncoder().encode(state), to: stateURL) })
        let relayURL = ProcessInfo.processInfo.environment["AGENTCREDS_TEST_RELAY_URL"]
        if let relayURL { try server.enableRelay(url: relayURL, storage: storage) }
        defer { server.revokeAll(); server.stopRelay() }
        var pairing = try server.invite(); if pairing.relay == nil { pairing.host = "127.0.0.1" }
        let originalInvite = pairing
        let signing = P256.Signing.PrivateKey(), agreement = P256.KeyAgreement.PrivateKey()
        var enrollment = CompanionCommand(action: .enrollOwner)
        enrollment.enrollment = DeviceEnrollment(signingPublicKey: signing.publicKey.x963Representation, agreementPublicKey: agreement.publicKey.x963Representation)
        let enrolled = try await CompanionNetwork.exchange(enrollment, pairing: pairing) { command, challenge in
            var command = command
            command.signature = try signing.signature(for: TrustedDeviceCrypto.signingData(command, pairingID: pairing.id, challenge: challenge)).rawRepresentation
            return command
        }
        let capsule = try XCTUnwrap(enrolled.keyCapsule)
        pairing = enrolled.pairedInvite ?? pairing
        if let relayURL {
            XCTAssertNotEqual(pairing.key, originalInvite.key)
            XCTAssertNotEqual(pairing.relay?.token, originalInvite.relay?.token)
            XCTAssertNil(pairing.enrollmentExpiresAt)
            do { _ = try await CompanionNetwork.exchange(CompanionCommand(action: .snapshot), pairing: originalInvite); XCTFail("Used QR invite still accepted") } catch { }
            server.stopRelay()
            server = CompanionServer(vault: vault, approvals: approvals, port: 0, audit: audit, authenticate: { _ in XCTFail("Trust did not survive restart"); return false })
            try server.enableRelay(url: relayURL, storage: storage)
            // Wait for the new outbound connection, without issuing new device trust.
            try await Task.sleep(for: .seconds(2))
        }
        let shared = try agreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: capsule.ephemeralPublicKey))
        let phoneKey = try TrustedDeviceCrypto.unwrap(capsule, shared: shared, pairingID: pairing.id)
        XCTAssertEqual(provider.calls, 1)
        provider.disallow = true
        func send(_ command: CompanionCommand) async throws -> CompanionReply {
            try await CompanionNetwork.exchange(command, pairing: pairing) { command, challenge in
                var command = command; command.vaultKey = phoneKey
                command.signature = try signing.signature(for: TrustedDeviceCrypto.signingData(command, pairingID: pairing.id, challenge: challenge)).rawRepresentation
                return command
            }
        }
        let item = VaultItem(name: "phone-added", hosts: ["example.test"])
        let added = try await send(CompanionCommand(action: .add, item: item, value: "synthetic-new"))
        var saved = try XCTUnwrap(added.snapshot?.items.first { $0.name == item.name })
        saved.hosts = ["changed.test"]
        let edited = try await send(CompanionCommand(action: .updatePolicy, item: saved, value: "synthetic-rotated"))
        saved = try XCTUnwrap(edited.snapshot?.items.first { $0.name == item.name })
        let deviceVault = try vault.authorizedDeviceVault(key: phoneKey)
        XCTAssertEqual(try deviceVault.revealValue(of: XCTUnwrap(vault.record(named: item.name))), Data("synthetic-rotated".utf8))
        _ = try await send(CompanionCommand(action: .delete, item: saved))
        XCTAssertNil(try vault.record(named: item.name))
        let record = try XCTUnwrap(vault.record(named: "synthetic"))
        let created = try approvals.create(record: record, agent: "synthetic-agent", purpose: "synthetic-purpose")
        let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(created.utf8)) as? [String: String])
        let request = try XCTUnwrap(approvals.list().first)
        var approve = CompanionCommand(action: .approve, requestID: request.id, duration: 120)
        approve.reviewedRequest = request
        var altered = approve; altered.reviewedRequest?.purpose = "tampered"
        do { _ = try await send(altered); XCTFail("Changed review accepted") } catch { }
        do { _ = try await CompanionNetwork.exchange(approve, pairing: pairing); XCTFail("Unsigned approval accepted") } catch { }
        let released = try await send(approve)
        XCTAssertEqual(released.snapshot?.requests.first?.status, .ready)
        let result = try approvals.poll(id: request.id, token: XCTUnwrap(payload["redemption_token"]))
        XCTAssertFalse(result.contains("synthetic-secret"))
        XCTAssertNotEqual(result, "{\"status\":\"failed\"}")
        XCTAssertEqual(provider.calls, 1)
        XCTAssertEqual(confirmations, 1)
        do { _ = try await send(approve); XCTFail("Duplicate approval accepted") } catch { }
        _ = try await CompanionNetwork.exchange(CompanionCommand(action: .disconnect), pairing: pairing)
        do { _ = try await send(CompanionCommand(action: .add, item: item, value: "revoked")); XCTFail("Revoked device accepted") } catch { }
    }
}

private final class CountingProvider: KEKProviding {
    let promptsEveryTime = true
    let key: SymmetricKey
    var calls = 0
    var disallow = false
    init(key: SymmetricKey) { self.key = key }
    func kek(reason: String) throws -> SymmetricKey {
        calls += 1
        if disallow { throw VaultError.keyMismatch }
        return key
    }
}
