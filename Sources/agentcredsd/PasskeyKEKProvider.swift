import Foundation
import CryptoKit
import AgentCredsCore

/// Derives the vault KEK from a passkey PRF assertion. Every call prompts, and
/// that prompt IS the approval — there is no cached key to fall back on.
final class PasskeyKEKProvider: KEKProviding {
    let promptsEveryTime = true

    private let config: KEKConfig
    private let ceremony: PasskeyCeremony

    init(config: KEKConfig, ceremony: PasskeyCeremony) {
        self.config = config
        self.ceremony = ceremony
    }

    func kek(reason: String) throws -> SymmetricKey {
        guard let relyingParty = config.relyingParty,
              let credentialID = config.credentialID,
              let salt = config.salt else {
            throw PasskeyError.failed("passkey KEK is not fully configured")
        }
        let prf = try ceremony.assertPRF(relyingParty: relyingParty,
                                         credentialID: credentialID, salt: salt)
        let key = PasskeyKEK.deriveKEK(prfOutput: prf, relyingParty: relyingParty)
        // A different passkey (or a rotated one) yields a different key. Catch
        // that here rather than letting every unwrap fail as "corrupt data".
        if let expected = config.kekCheck, PasskeyKEK.check(for: key) != expected {
            throw PasskeyError.failed("this passkey does not match the one the vault was enrolled with")
        }
        return key
    }
}

/// Chooses the KEK source the vault was configured for.
enum KEKResolver {
    static func provider(ceremony: PasskeyCeremony) throws -> KEKProviding {
        let config = KEKConfig.load()
        switch config.source {
        case .keychain:
            return StaticKEKProvider(try KeychainKEKProvider().loadOrCreate())
        case .passkey:
            return PasskeyKEKProvider(config: config, ceremony: ceremony)
        }
    }
}

/// Moves the vault from a Keychain-held KEK to one that only exists during a
/// passkey assertion. The DEKs are re-wrapped; secret values are untouched.
enum PasskeyEnrollment {
    struct Result: Codable {
        let relyingParty: String
        let secretsRewrapped: Int
    }

    static func enroll(relyingParty: String, userName: String,
                       ceremony: PasskeyCeremony) throws -> Result {
        let existing = KEKConfig.load()
        guard existing.source == .keychain else {
            throw PasskeyError.failed("the vault is already protected by a passkey")
        }

        let (credentialID, prfSupported) = try ceremony.enroll(relyingParty: relyingParty,
                                                              userName: userName)
        guard prfSupported else { throw PasskeyError.noPRF }

        let salt = PasskeyKEK.newSalt()
        let prf = try ceremony.assertPRF(relyingParty: relyingParty,
                                         credentialID: credentialID, salt: salt)
        let newKEK = PasskeyKEK.deriveKEK(prfOutput: prf, relyingParty: relyingParty)

        // Re-wrap under the OLD provider before switching config, so a failure
        // here leaves the vault readable exactly as it was.
        let oldProvider = StaticKEKProvider(try KeychainKEKProvider().loadOrCreate())
        let vault = try VaultStore(kekProvider: oldProvider)
        let count = try vault.list().count
        try vault.rewrapDEKs(to: newKEK, reason: "Move your vault to passkey protection")

        var config = KEKConfig(source: .passkey, relyingParty: relyingParty,
                               credentialID: credentialID, salt: salt,
                               kekCheck: PasskeyKEK.check(for: newKEK))
        try config.save()

        // Only now is the Keychain copy redundant. Removing it is what makes
        // the guarantee real: without an assertion there is no key anywhere.
        KeychainKEKProvider().deleteStoredKEK()
        return Result(relyingParty: relyingParty, secretsRewrapped: count)
    }
}
