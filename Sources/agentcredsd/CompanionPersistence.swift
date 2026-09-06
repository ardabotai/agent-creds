import Foundation
import Security
import CompanionProtocol

struct CompanionPersistentState: Codable {
    var relay: RelayAddress
    var pairings: [UUID: PairingInvite] = [:]
    var ownerKeys: [UUID: Data] = [:]
}

/// A single atomic Keychain item holds routing credentials and trusted pairings.
/// It contains no vault KEK, key capsule or plaintext credential.
struct CompanionStateStorage {
    var load: () throws -> CompanionPersistentState?
    var save: (CompanionPersistentState) throws -> Void
    static let keychain = CompanionStateStorage(load: {
        var query = Self.query; query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw CompanionError.invalid("Cannot read companion trust from Keychain") }
        return try JSONDecoder().decode(CompanionPersistentState.self, from: data)
    }, save: { state in
        let data = try JSONEncoder().encode(state)
        var attributes = query; attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            guard SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary) == errSecSuccess else { throw CompanionError.invalid("Cannot persist companion trust") }
        } else if status != errSecSuccess { throw CompanionError.invalid("Cannot persist companion trust") }
    })
    private static var query: [String: Any] { [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "ai.ardabot.agentcreds.companion-trust", kSecAttrAccount as String: "v1"] }
}
