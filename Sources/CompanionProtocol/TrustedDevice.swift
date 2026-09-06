import Foundation
import CryptoKit

public struct DeviceEnrollment: Codable {
    public var signingPublicKey: Data
    public var agreementPublicKey: Data
    public init(signingPublicKey: Data, agreementPublicKey: Data) {
        self.signingPublicKey = signingPublicKey; self.agreementPublicKey = agreementPublicKey
    }
}

/// Only ciphertext is persisted on the phone. The ephemeral private key is discarded.
public struct DeviceKeyCapsule: Codable {
    public var ephemeralPublicKey: Data
    public var ciphertext: Data
    public init(ephemeralPublicKey: Data, ciphertext: Data) { self.ephemeralPublicKey = ephemeralPublicKey; self.ciphertext = ciphertext }
}

public enum TrustedDeviceCrypto {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }
    public static func signingData(_ command: CompanionCommand, pairingID: UUID, challenge: Data) throws -> Data {
        guard challenge.count == 32 else { throw CompanionError.invalid("Invalid challenge") }
        var unsigned = command; unsigned.signature = nil
        return Data("agentcreds/owner-command/v1/\(pairingID.uuidString)/".utf8) + challenge + (try encode(unsigned))
    }
    public static func verify(_ command: CompanionCommand, publicKey: Data, pairingID: UUID, challenge: Data) throws {
        guard let signature = command.signature,
              try P256.Signing.PublicKey(x963Representation: publicKey).isValidSignature(
                P256.Signing.ECDSASignature(rawRepresentation: signature),
                for: signingData(command, pairingID: pairingID, challenge: challenge)) else {
            throw CompanionError.invalid("Authenticate on your trusted iPhone to authorize this operation")
        }
    }
    public static func wrap(_ key: SymmetricKey, for publicKey: Data, pairingID: UUID) throws -> DeviceKeyCapsule {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: publicKey))
        let wrappingKey = capsuleKey(shared, pairingID: pairingID)
        let box = try ChaChaPoly.seal(key.withUnsafeBytes { Data($0) }, using: wrappingKey, authenticating: Data(pairingID.uuidString.utf8))
        return DeviceKeyCapsule(ephemeralPublicKey: ephemeral.publicKey.x963Representation, ciphertext: box.combined)
    }
    public static func unwrap(_ capsule: DeviceKeyCapsule, shared: SharedSecret, pairingID: UUID) throws -> Data {
        let key = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: capsule.ciphertext), using: capsuleKey(shared, pairingID: pairingID), authenticating: Data(pairingID.uuidString.utf8))
        guard key.count == 32 else { throw CompanionError.invalid("Invalid vault key") }
        return key
    }
    private static func capsuleKey(_ shared: SharedSecret, pairingID: UUID) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(pairingID.uuidString.utf8), sharedInfo: Data("agentcreds/phone-vault-key/v1".utf8), outputByteCount: 32)
    }
}
