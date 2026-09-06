import Foundation
import CryptoKit
import LocalAuthentication
import Security
import CompanionProtocol

/// Secure Enclave handles are device-bound blobs, not exportable private keys.
/// The capsule is ciphertext; no plaintext vault key is saved or cached.
enum DeviceOwnerIdentity {
    struct Stored: Codable {
        let signing: Data
        let agreement: Data
        let capsule: DeviceKeyCapsule
    }
    static func hasIdentity(_ id: UUID) -> Bool { (try? load(id)) != nil }
    static func context(_ reason: String) async throws -> LAContext {
        let context = LAContext()
        context.localizedReason = reason
        guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else { throw CompanionError.invalid("Authentication cancelled") }
        return context
    }
    static func enroll(pairing: PairingInvite) async throws -> PairingInvite {
        guard SecureEnclave.isAvailable else { throw CompanionError.invalid("Independent iPhone control requires a physical device with Secure Enclave. Use the demo in Simulator.") }
        let context = try await context("Trust this iPhone to control your credential vault")
        defer { context.invalidate() }
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .userPresence], nil) else { throw CompanionError.invalid("Set a device passcode before enabling vault control") }
        let signing = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
        let agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: context)
        var command = CompanionCommand(action: .enrollOwner)
        command.enrollment = DeviceEnrollment(signingPublicKey: signing.publicKey.x963Representation, agreementPublicKey: agreement.publicKey.x963Representation)
        let reply = try await CompanionNetwork.exchange(command, pairing: pairing) { command, challenge in
            var signed = command
            signed.signature = try signing.signature(for: TrustedDeviceCrypto.signingData(command, pairingID: pairing.id, challenge: challenge)).rawRepresentation
            return signed
        }
        guard let capsule = reply.keyCapsule else { throw CompanionError.invalid("Mac did not authorize independent iPhone control") }
        try save(Stored(signing: signing.dataRepresentation, agreement: agreement.dataRepresentation, capsule: capsule), id: pairing.id)
        return reply.pairedInvite ?? pairing
    }
    static func authorize(_ command: CompanionCommand, challenge: Data, pairing: PairingInvite) async throws -> CompanionCommand {
        let stored = try load(pairing.id)
        let context = try await context(command.action == .approve ? "Approve this credential request" : "Authorize this vault change")
        defer { context.invalidate() }
        return try await Task.detached {
            let agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: stored.agreement, authenticationContext: context)
            let signing = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: stored.signing, authenticationContext: context)
            let shared = try agreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: stored.capsule.ephemeralPublicKey))
            var authorized = command
            authorized.vaultKey = try TrustedDeviceCrypto.unwrap(stored.capsule, shared: shared, pairingID: pairing.id)
            authorized.signature = try signing.signature(for: TrustedDeviceCrypto.signingData(authorized, pairingID: pairing.id, challenge: challenge)).rawRepresentation
            return authorized
        }.value
    }
    private static func query(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "ai.ardabot.agentcreds.owner", kSecAttrAccount as String: id.uuidString]
    }
    private static func load(_ id: UUID) throws -> Stored {
        var query = query(id); query[kSecReturnData as String] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { throw CompanionError.invalid("Enable iPhone control again from Devices") }
        return try JSONDecoder().decode(Stored.self, from: data)
    }
    private static func save(_ stored: Stored, id: UUID) throws {
        var attributes = query(id)
        attributes[kSecValueData as String] = try JSONEncoder().encode(stored)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else { throw CompanionError.invalid("Could not save device trust. Pair again before using iPhone control.") }
    }
    static func delete(_ id: UUID) { SecItemDelete(query(id) as CFDictionary) }
}
