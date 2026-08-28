import Foundation
import CryptoKit
import Security

public enum CryptoError: Error {
    case keychain(OSStatus)
    case corrupt
}

/// Envelope encryption: each secret gets its own DEK; DEKs are wrapped by the
/// master KEK. Rotating the KEK (e.g. re-enrolling in Phase 2/3) only requires
/// re-wrapping DEKs, never re-encrypting values.
public enum Envelope {
    public static func seal(_ plaintext: Data, kek: SymmetricKey) throws -> (ciphertext: Data, wrappedDEK: Data) {
        let dek = SymmetricKey(size: .bits256)
        let sealed = try ChaChaPoly.seal(plaintext, using: dek)
        let dekData = dek.withUnsafeBytes { Data($0) }
        let wrapped = try ChaChaPoly.seal(dekData, using: kek)
        return (sealed.combined, wrapped.combined)
    }

    public static func open(ciphertext: Data, wrappedDEK: Data, kek: SymmetricKey) throws -> Data {
        let dekData = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: wrappedDEK), using: kek)
        let dek = SymmetricKey(data: dekData)
        return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: ciphertext), using: dek)
    }
}

/// Loads (or creates on first run) the 256-bit master KEK from the Keychain.
///
/// Phase 2: add `kSecAttrSynchronizable` so the KEK lives in iCloud Keychain and
/// syncs to the iPhone. That requires a signed, provisioned app with a
/// keychain-access-groups entitlement, so the unsigned dev build uses a
/// local-only item for now.
public struct KeychainKEKProvider {
    private let service = "ai.ardabot.agentcreds.master"
    /// Earlier service names, newest first. Read once, migrated, then removed —
    /// an installed vault must survive a rename, since losing the KEK loses
    /// every secret in it.
    private let legacyServices = ["com.ardabot.agentcreds.master", "dev.agentcreds.master"]
    private let account = "kek"

    public init() {}

    public func loadOrCreate() throws -> SymmetricKey {
        // Dev/CI escape hatch: unsigned dev binaries get a new code identity on
        // every rebuild, so the Keychain ACL re-prompts each time. Setting
        // AGENTCREDS_DEV_KEK_FILE=1 keeps the KEK in a 0600 file instead.
        // Never use outside development; the signed bundle removes the need.
        if ProcessInfo.processInfo.environment["AGENTCREDS_DEV_KEK_FILE"] == "1" {
            return try loadOrCreateFileKEK()
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let data = item as? Data {
            return SymmetricKey(data: data)
        }
        guard status == errSecItemNotFound else { throw CryptoError.keychain(status) }

        if let migrated = try migrateLegacyKEK() { return migrated }

        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: keyData,
        ]
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw CryptoError.keychain(addStatus) }
        return key
    }

    /// Moves a pre-1.0 KEK to the current service name, so upgrading does not
    /// silently strand an existing vault. Returns nil when there is nothing to
    /// migrate.
    private func migrateLegacyKEK() throws -> SymmetricKey? {
        var found: Data?
        var sourceService: String?
        for legacy in legacyServices {
            let legacyQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: legacy,
                kSecAttrAccount as String: account,
                kSecReturnData as String: true,
            ]
            var legacyItem: CFTypeRef?
            if SecItemCopyMatching(legacyQuery as CFDictionary, &legacyItem) == errSecSuccess,
               let data = legacyItem as? Data {
                found = data
                sourceService = legacy
                break
            }
        }
        guard let data = found, let sourceService else { return nil }

        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
        ]
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
            throw CryptoError.keychain(addStatus)
        }
        // Only drop the old copy once the new one is safely stored.
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: sourceService,
            kSecAttrAccount as String: account,
        ] as CFDictionary)
        return SymmetricKey(data: data)
    }

    /// Removes the stored key. Called only after the vault's DEKs have been
    /// re-wrapped under a new KEK — otherwise this destroys the vault.
    public func deleteStoredKEK() {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ] as CFDictionary)
    }

    private func loadOrCreateFileKEK() throws -> SymmetricKey {
        let url = IPCPaths.directory.appendingPathComponent("kek.devonly")
        if let data = try? Data(contentsOf: url), data.count == 32 {
            return SymmetricKey(data: data)
        }
        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        try SecureFile.write(keyData, to: url)
        return key
    }
}
