import Foundation
import CryptoKit

/// Supplies the key-encryption key that wraps every secret's DEK.
///
/// This is a per-operation lookup rather than a stored key on purpose. With a
/// passkey provider, deriving the KEK *is* the approval ceremony: the WebAuthn
/// assertion produces the key material, so a release that the user did not
/// approve cannot be performed at all — not because policy code refused, but
/// because the daemon never had the key.
public protocol KEKProviding {
    /// `reason` is shown to the user by providers that prompt.
    func kek(reason: String) throws -> SymmetricKey
    /// True when every call prompts the user (so callers can avoid asking twice).
    var promptsEveryTime: Bool { get }
}

/// Wraps an already-derived key. Used by tests and by the Keychain path, where
/// the key is fetched once and reused.
public struct StaticKEKProvider: KEKProviding {
    private let key: SymmetricKey
    public let promptsEveryTime = false

    public init(_ key: SymmetricKey) { self.key = key }
    public func kek(reason: String) throws -> SymmetricKey { key }
}

/// How the vault's KEK is obtained. Persisted next to the vault so the daemon
/// and CLI agree without probing.
public struct KEKConfig: Codable {
    public enum Source: String, Codable {
        /// Key stored in the Keychain. The biometric gate is procedural.
        case keychain
        /// Key derived from a WebAuthn PRF assertion. Crypto-gated.
        case passkey
    }

    public var source: Source
    /// Relying party identifier the passkey was created against.
    public var relyingParty: String?
    /// Credential ID returned at registration, so assertions target this key.
    public var credentialID: Data?
    /// PRF salt. Not secret — it selects which key the authenticator derives.
    public var salt: Data?
    /// Set at enrollment so a mismatch is caught rather than producing a
    /// silently wrong key.
    public var kekCheck: Data?

    public init(source: Source = .keychain, relyingParty: String? = nil,
                credentialID: Data? = nil, salt: Data? = nil, kekCheck: Data? = nil) {
        self.source = source
        self.relyingParty = relyingParty
        self.credentialID = credentialID
        self.salt = salt
        self.kekCheck = kekCheck
    }

    public static var fileURL: URL {
        IPCPaths.directory.appendingPathComponent("kek.json")
    }

    /// Security-sensitive callers must use this throwing reader. Malformed or
    /// unreadable configuration must never create a replacement Keychain key.
    public static func read(vaultURL: URL = IPCPaths.vaultURL) throws -> KEKConfig {
        if let embedded = try VaultDocument.read(at: vaultURL).kekConfig { return embedded }
        let legacyURL = vaultURL.deletingLastPathComponent().appendingPathComponent("kek.json")
        guard FileManager.default.fileExists(atPath: legacyURL.path) else { return KEKConfig() }
        return try JSONDecoder().decode(KEKConfig.self, from: Data(contentsOf: legacyURL))
    }

    public static func load() -> KEKConfig {
        // Display-only fallback is deliberately fail closed.
        (try? read()) ?? KEKConfig(source: .passkey)
    }

    public func save() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try SecureFile.write(try encoder.encode(self), to: KEKConfig.fileURL)
    }
}

public enum PasskeyKEK {
    /// Fresh 32-byte PRF salt.
    public static func newSalt() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }

    /// Derives the KEK from a PRF output. The authenticator's output is already
    /// uniformly random, but running it through HKDF domain-separates this use
    /// from any other use of the same passkey.
    public static func deriveKEK(prfOutput: SymmetricKey, relyingParty: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: prfOutput,
            info: Data("agent-creds/kek/v1/\(relyingParty)".utf8),
            outputByteCount: 32)
    }

    /// Non-secret fingerprint of a KEK, stored at enrollment so a wrong or
    /// rotated passkey is reported clearly instead of failing as corrupt data.
    public static func check(for key: SymmetricKey) -> Data {
        let raw = key.withUnsafeBytes { Data($0) }
        return Data(SHA256.hash(data: Data("agent-creds/kek-check/v1".utf8) + raw).prefix(8))
    }
}
