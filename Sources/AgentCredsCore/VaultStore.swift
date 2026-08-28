import Foundation
import CryptoKit

public enum VaultError: Error {
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
    private let kek: SymmetricKey
    private let lock = NSLock()

    /// The one way both the daemon and the CLI open the user's vault, so the
    /// KEK-acquisition contract lives in a single place.
    public static func openDefault() throws -> VaultStore {
        try VaultStore(kek: KeychainKEKProvider().loadOrCreate())
    }

    public init(url: URL = IPCPaths.vaultURL, kek: SymmetricKey) throws {
        self.url = url
        self.kek = kek
        IPCPaths.ensureDirectory()
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
    }

    // Reload from disk on every operation: the CLI and the daemon both touch the
    // vault file in Phase 1, and this keeps them coherent without IPC.
    private func loadRecords() throws -> [SecretRecord] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode([SecretRecord].self, from: data)
    }

    private func persist(_ records: [SecretRecord]) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(records)
        try SecureFile.write(data, to: url)
    }

    /// Returns the stored record, so a caller that saves and then mints does
    /// not have to re-read the whole vault to get it back.
    @discardableResult
    public func save(name: String, kind: SecretKind, value: Data, policy: SecretPolicy) throws -> SecretRecord {
        lock.lock(); defer { lock.unlock() }
        var records = try loadRecords()
        let (ciphertext, wrappedDEK) = try Envelope.seal(value, kek: kek)
        records.removeAll { $0.name == name }
        let record = SecretRecord(name: name, kind: kind, ciphertext: ciphertext,
                                  wrappedDEK: wrappedDEK, policy: policy)
        records.append(record)
        try persist(records)
        return record
    }

    public func list() throws -> [SecretMetadata] {
        lock.lock(); defer { lock.unlock() }
        return try loadRecords().map {
            SecretMetadata(name: $0.name, kind: $0.kind, createdAt: $0.createdAt)
        }
    }

    public func record(named name: String) throws -> SecretRecord? {
        lock.lock(); defer { lock.unlock() }
        return try loadRecords().first { $0.name == name }
    }

    /// Decrypts the root value. Only the daemon calls this, and only after an
    /// approval ceremony — the result feeds a minter or the egress proxy,
    /// never an agent-facing response.
    public func revealValue(of record: SecretRecord) throws -> Data {
        try Envelope.open(ciphertext: record.ciphertext, wrappedDEK: record.wrappedDEK, kek: kek)
    }

    public func delete(name: String) throws {
        lock.lock(); defer { lock.unlock() }
        var records = try loadRecords()
        guard records.contains(where: { $0.name == name }) else { throw VaultError.notFound(name) }
        records.removeAll { $0.name == name }
        try persist(records)
    }
}
