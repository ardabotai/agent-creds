import Foundation
import CryptoKit
import Darwin

public enum VaultError: Error, LocalizedError {
    case duplicate(String)
    case passkeyRequiresDaemon
    case keyMismatch

    public var errorDescription: String? {
        switch self {
        case .duplicate(let name): return "A secret named “\(name)” already exists. Choose a different name."
        case .passkeyRequiresDaemon: return "This vault uses a passkey. Add and use credentials through the running Mac app or MCP; CLI secret operations are unavailable in passkey mode."
        case .keyMismatch: return "The vault key changed. Reopen the vault before continuing."
        case .notFound(let name): return "Secret not found: \(name)"
        case .io(let message): return message
        }
    }
    case notFound(String)
    case io(String)
}

/// File-backed vault. Records are stored as JSON, but every value inside them
/// is envelope-encrypted, so the file itself only ever holds ciphertext.
///
/// TODO Phase 1.5: move to SQLite. TODO Phase 2: mirror records into the
/// CloudKit private database for iPhone sync.
public final class VaultStore {
    private let url: URL
    private let kekProvider: KEKProviding
    private let lock = NSLock()
    private let requireKeyForMutations: Bool
    private let writeFile: (Data, URL) throws -> Void

    /// The one way both the daemon and the CLI open the user's vault, so the
    /// KEK-acquisition contract lives in a single place.
    public static func openDefault() throws -> VaultStore {
        try VaultStore(kekProvider: CLIKEKProvider())
    }

    public convenience init(url: URL = IPCPaths.vaultURL, kek: SymmetricKey) throws {
        try self.init(url: url, kekProvider: StaticKEKProvider(kek))
    }

    public init(url: URL = IPCPaths.vaultURL, kekProvider: KEKProviding, requireKeyForMutations: Bool = false,
                writeFile: @escaping (Data, URL) throws -> Void = { try SecureFile.write($0, to: $1) }) throws {
        self.requireKeyForMutations = requireKeyForMutations
        self.writeFile = writeFile
        self.url = url
        self.kekProvider = kekProvider
        IPCPaths.ensureDirectory()
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
    }

    // File locking serializes CLI, enrollment, and daemon handles. Atomic rename
    // alone prevents torn files, but cannot prevent lost read-modify-write updates.
    private func withFileLock<T>(_ body: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        let fd = Darwin.open(url.path + ".lock", O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw VaultError.io("Cannot open vault lock") }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw VaultError.io("Cannot lock vault") }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    private func loadRecords() throws -> [SecretRecord] {
        try VaultDocument.read(at: url).records
    }

    private func persist(_ records: [SecretRecord], config: KEKConfig? = nil) throws {
        var document = try VaultDocument.read(at: url)
        document.records = records
        if let config { document.kekConfig = config }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try writeFile(try encoder.encode(document), url)
    }

    private func validate(_ key: SymmetricKey) throws {
        if let config = try VaultDocument.read(at: url).kekConfig,
           let check = config.kekCheck, PasskeyKEK.check(for: key) != check {
            throw VaultError.keyMismatch
        }
    }

    public var promptsEveryTime: Bool { kekProvider.promptsEveryTime }

    /// One-time owner enrollment: obtain the existing KEK through its normal
    /// ceremony and pin its check atomically, including for legacy Keychain vaults.
    public func keyForTrustedDeviceEnrollment() throws -> SymmetricKey {
        try withFileLock {
            let key = try kekProvider.kek(reason: "Allow your iPhone to independently control this vault")
            try validate(key)
            var config = try KEKConfig.read(vaultURL: url)
            config.kekCheck = PasskeyKEK.check(for: key)
            try persist(loadRecords(), config: config)
            return key
        }
    }

    /// A short-lived operation handle, never installed as the Mac's live provider.
    /// Callers must verify a trusted device signature before supplying a key.
    public func authorizedDeviceVault(key: Data) throws -> VaultStore {
        try withFileLock {
            guard key.count == 32,
                  let expected = try VaultDocument.read(at: url).kekConfig?.kekCheck,
                  expected == PasskeyKEK.check(for: SymmetricKey(data: key)) else { throw VaultError.keyMismatch }
        }
        return try VaultStore(url: url, kekProvider: StaticKEKProvider(SymmetricKey(data: key)), requireKeyForMutations: true)
    }

    /// Returns the stored record, so a caller that saves and then mints does
    /// not have to re-read the whole vault to get it back.
    @discardableResult
    public func save(name: String, kind: SecretKind, value: Data, policy: SecretPolicy, replacingExisting: Bool = true) throws -> SecretRecord {
        try withFileLock {
            try policy.injection.validate()
            var records = try loadRecords()
            if !replacingExisting, records.contains(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) {
                throw VaultError.duplicate(name)
            }
            let kek = try kekProvider.kek(reason: "Save “\(name)” to your vault")
            try validate(kek)
            let (ciphertext, wrappedDEK) = try Envelope.seal(value, kek: kek)
            records.removeAll { $0.name == name }
            let record = SecretRecord(name: name, kind: kind, ciphertext: ciphertext,
                                      wrappedDEK: wrappedDEK, policy: policy)
            records.append(record)
            try persist(records)
            return record
        }
    }

    public func list() throws -> [SecretMetadata] {
        try withFileLock {
            return try loadRecords().map {
                SecretMetadata(name: $0.name, kind: $0.kind, createdAt: $0.createdAt,
                               allowedHosts: $0.policy.allowedHosts)
            }
        }
    }

    /// Finds credentials by vault name or by the host they are scoped to, so a
    /// caller can ask for "github.com" without knowing it was saved as
    /// "github/token". Exact name match wins outright; otherwise every
    /// host-scoped candidate is returned for the caller to disambiguate.
    public func find(matching query: String) throws -> [SecretRecord] {
        try withFileLock {
            let records = try loadRecords()
            let needle = query.lowercased()
            if let exact = records.first(where: { $0.name.lowercased() == needle }) {
                return [exact]
            }
            let host = URL(string: needle.contains("//") ? needle : "https://\(needle)")?.host?.lowercased()
                ?? needle
            return records.filter { record in
                if record.name.lowercased().contains(needle) { return true }
                return record.policy.allowedHosts.contains { allowed in
                    let allowed = allowed.lowercased()
                    return host == allowed || host.hasSuffix("." + allowed) || allowed.hasSuffix("." + host)
                }
            }
        }
    }

    public func record(named name: String) throws -> SecretRecord? {
        try withFileLock {
            return try loadRecords().first { $0.name == name }
        }
    }

    /// Decrypts the root value. Only the daemon calls this, and only after an
    /// approval ceremony — the result feeds a minter or the egress proxy,
    /// never an agent-facing response.
    public func revealValue(of record: SecretRecord) throws -> Data {
        try withFileLock {
            guard let current = try loadRecords().first(where: { $0.id == record.id }) else {
                throw VaultError.notFound(record.name)
            }
            let kek = try kekProvider.kek(reason: "Release “\(record.name)”")
            try validate(kek)
            return try Envelope.open(ciphertext: current.ciphertext, wrappedDEK: current.wrappedDEK, kek: kek)
        }
    }

    /// Re-wraps every DEK under a new KEK. Switching KEK sources (Keychain to
    /// passkey, or rotating a passkey) only touches the wrapped DEKs — secret
    /// values are never re-encrypted, which is the point of the envelope.
    public func rewrapDEKs(to newKEK: SymmetricKey, reason: String) throws {
        try withFileLock {
            let oldKEK = try kekProvider.kek(reason: reason)
            var records = try loadRecords()
            for index in records.indices {
                let dekData = try ChaChaPoly.open(
                    ChaChaPoly.SealedBox(combined: records[index].wrappedDEK), using: oldKEK)
                records[index].wrappedDEK = try ChaChaPoly.seal(dekData, using: newKEK).combined
            }
            try persist(records)
        }
    }

    /// Configuration and wrapped keys commit together. A failed write leaves the
    /// old document readable; a successful rename is immediately authoritative.
    public func migrateToPasskey(key: SymmetricKey, config: KEKConfig) throws -> Int {
        try withFileLock {
            let current = try KEKConfig.read(vaultURL: url)
            guard current.source == .keychain else { throw VaultError.keyMismatch }
            guard config.source == .passkey, config.credentialID?.isEmpty == false,
                  config.salt?.isEmpty == false, config.relyingParty?.isEmpty == false,
                  config.kekCheck == PasskeyKEK.check(for: key) else { throw VaultError.keyMismatch }
            let oldKey = try kekProvider.kek(reason: "Move your vault to passkey protection")
            var records = try loadRecords()
            for index in records.indices {
                let dek = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: records[index].wrappedDEK), using: oldKey)
                records[index].wrappedDEK = try ChaChaPoly.seal(dek, using: key).combined
            }
            try persist(records, config: config)
            return records.count
        }
    }

    /// Policy edits change the record version, invalidating pending approvals.
    public func updatePolicy(name: String, expectedID: UUID, policy: SecretPolicy, replacementValue: Data? = nil) throws {
        try withFileLock {
            try policy.injection.validate()
            var records = try loadRecords()
            guard let index = records.firstIndex(where: { $0.name == name && $0.id == expectedID }) else {
                throw VaultError.notFound(name)
            }
            if requireKeyForMutations || replacementValue != nil {
                let key = try kekProvider.kek(reason: "Update “\(name)”")
                try validate(key)
                if let replacementValue {
                    let (ciphertext, wrappedDEK) = try Envelope.seal(replacementValue, kek: key)
                    records[index].ciphertext = ciphertext; records[index].wrappedDEK = wrappedDEK
                }
            }
            records[index].policy = policy
            records[index].id = UUID()
            try persist(records)
        }
    }

    public func delete(name: String, expectedID: UUID? = nil) throws {
        try withFileLock {
            var records = try loadRecords()
            guard records.contains(where: { $0.name == name && (expectedID == nil || $0.id == expectedID) }) else { throw VaultError.notFound(name) }
            if requireKeyForMutations { try validate(kekProvider.kek(reason: "Delete “\(name)”")) }
            records.removeAll { $0.name == name }
            try persist(records)
        }
    }
}

/// Legacy arrays remain readable. New writes use a document so migration is a
/// single atomic update; older binaries fail decoding instead of overwriting it.
struct VaultDocument: Codable {
    var records: [SecretRecord] = []
    var kekConfig: KEKConfig?

    static func read(at url: URL) throws -> VaultDocument {
        guard FileManager.default.fileExists(atPath: url.path) else { return VaultDocument() }
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        if data.first(where: { ![9, 10, 13, 32].contains($0) }) == 91 {
            return VaultDocument(records: try decoder.decode([SecretRecord].self, from: data))
        }
        return try decoder.decode(VaultDocument.self, from: data)
    }
}

/// Metadata operations need no key. Secret operations check the live config
/// before touching Keychain, including handles opened before enrollment.
public struct CLIKEKProvider: KEKProviding {
    private let vaultURL: URL
    private let loadKey: () throws -> SymmetricKey
    public var promptsEveryTime: Bool { false }
    public init(vaultURL: URL = IPCPaths.vaultURL,
                loadKey: @escaping () throws -> SymmetricKey = { try KeychainKEKProvider().loadOrCreate() }) {
        self.vaultURL = vaultURL
        self.loadKey = loadKey
    }
    public func kek(reason: String) throws -> SymmetricKey {
        guard try KEKConfig.read(vaultURL: vaultURL).source == .keychain else {
            throw VaultError.passkeyRequiresDaemon
        }
        return try loadKey()
    }
}
