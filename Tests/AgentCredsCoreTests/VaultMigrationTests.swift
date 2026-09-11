import XCTest
import CryptoKit
@testable import AgentCredsCore

final class VaultMigrationTests: XCTestCase {
    private func location() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try FileManager.default.removeItem(at: dir) }
        return dir.appendingPathComponent("vault.json")
    }

    private func config(_ key: SymmetricKey) -> KEKConfig {
        KEKConfig(source: .passkey, relyingParty: "example.test", credentialID: Data([1]),
                  salt: Data(repeating: 2, count: 32), kekCheck: PasskeyKEK.check(for: key))
    }

    func testMigrationCommitsConfigurationAndRecordsAndRejectsStaleWrites() throws {
        let url = try location()
        let old = SymmetricKey(size: .bits256), new = SymmetricKey(size: .bits256)
        let vault = try VaultStore(url: url, kek: old)
        let record = try vault.save(name: "one", kind: .opaque, value: Data("synthetic".utf8), policy: SecretPolicy())
        XCTAssertEqual(try vault.migrateToPasskey(key: new, config: config(new)), 1)
        XCTAssertEqual(try KEKConfig.read(vaultURL: url).kekCheck, config(new).kekCheck)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.deletingLastPathComponent().appendingPathComponent("kek.json").path))
        let reopened = try VaultStore(url: url, kek: new)
        // A request may have captured the record before enrollment.
        XCTAssertEqual(try reopened.revealValue(of: record), Data("synthetic".utf8))
        XCTAssertThrowsError(try vault.save(name: "after", kind: .opaque, value: Data([3]), policy: SecretPolicy()))
        XCTAssertEqual(try reopened.list().count, 1)
        let added = try reopened.save(name: "after", kind: .opaque, value: Data([4]), policy: SecretPolicy())
        XCTAssertEqual(try reopened.revealValue(of: added), Data([4]))
    }

    func testFailedCommitPreservesOldVaultAndConfiguration() throws {
        let url = try location()
        let old = SymmetricKey(size: .bits256), new = SymmetricKey(size: .bits256)
        let vault = try VaultStore(url: url, kek: old)
        let record = try vault.save(name: "one", kind: .opaque, value: Data([7]), policy: SecretPolicy())
        let before = try Data(contentsOf: url)
        let failing = try VaultStore(url: url, kekProvider: StaticKEKProvider(old), writeFile: { _, _ in
            throw VaultError.io("simulated disk failure before commit")
        })
        XCTAssertThrowsError(try failing.migrateToPasskey(key: new, config: config(new)))
        XCTAssertEqual(try Data(contentsOf: url), before)
        XCTAssertEqual(try KEKConfig.read(vaultURL: url).source, .keychain)
        XCTAssertEqual(try vault.revealValue(of: record), Data([7]))
    }

    func testCLIHandleNeverLoadsKeyAfterEnrollment() throws {
        let url = try location()
        let old = SymmetricKey(size: .bits256), new = SymmetricKey(size: .bits256)
        var loads = 0
        let provider = CLIKEKProvider(vaultURL: url, loadKey: { loads += 1; return old })
        let cli = try VaultStore(url: url, kekProvider: provider)
        let record = try cli.save(name: "one", kind: .opaque, value: Data([1]), policy: SecretPolicy())
        let migrator = try VaultStore(url: url, kek: old)
        _ = try migrator.migrateToPasskey(key: new, config: config(new))
        loads = 0
        XCTAssertEqual(try cli.list().count, 1)
        XCTAssertThrowsError(try cli.save(name: "two", kind: .opaque, value: Data([2]), policy: SecretPolicy()))
        XCTAssertThrowsError(try cli.revealValue(of: record))
        XCTAssertEqual(loads, 0)
    }

    func testCorruptLegacyConfigNeverLoadsKey() throws {
        let url = try location()
        try Data("broken".utf8).write(to: url.deletingLastPathComponent().appendingPathComponent("kek.json"))
        let provider = CLIKEKProvider(vaultURL: url, loadKey: {
            XCTFail("Must not touch Keychain for corrupt configuration")
            return SymmetricKey(size: .bits256)
        })
        XCTAssertThrowsError(try provider.kek(reason: "test"))
    }

    func testDuplicateInsertPreservesValueAndPolicy() throws {
        let url = try location()
        let vault = try VaultStore(url: url, kek: SymmetricKey(size: .bits256))
        let original = try vault.save(name: "Token", kind: .opaque, value: Data([1]),
                                      policy: SecretPolicy(allowedHosts: ["example.test"], injection: .basic(username: "user")))
        XCTAssertThrowsError(try vault.save(name: "token", kind: .opaque, value: Data([2]),
                                            policy: SecretPolicy(), replacingExisting: false))
        let current = try XCTUnwrap(vault.record(named: "Token"))
        XCTAssertEqual(current.id, original.id)
        XCTAssertEqual(current.policy.injection, .basic(username: "user"))
        XCTAssertEqual(try vault.revealValue(of: current), Data([1]))
    }

    func testLegacyArrayRemainsReadable() throws {
        let url = try location()
        let key = SymmetricKey(size: .bits256)
        let sealed = try Envelope.seal(Data([1]), kek: key)
        let record = SecretRecord(name: "legacy", kind: .opaque, ciphertext: sealed.ciphertext,
                                  wrappedDEK: sealed.wrappedDEK, policy: SecretPolicy())
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        try encoder.encode([record]).write(to: url)
        let vault = try VaultStore(url: url, kek: key)
        XCTAssertEqual(try vault.revealValue(of: record), Data([1]))
        let new = SymmetricKey(size: .bits256)
        _ = try vault.migrateToPasskey(key: new, config: config(new))
        XCTAssertEqual(try VaultStore(url: url, kek: new).revealValue(of: record), Data([1]))
    }

    func testConcurrentHandlesDoNotLoseUpdates() throws {
        let url = try location(), key = SymmetricKey(size: .bits256)
        let stores = try (0..<12).map { _ in try VaultStore(url: url, kek: key) }
        DispatchQueue.concurrentPerform(iterations: stores.count) { i in
            do { try stores[i].save(name: "item-\(i)", kind: .opaque, value: Data([1]), policy: SecretPolicy()) }
            catch { XCTFail("Write failed: \(error)") }
        }
        XCTAssertEqual(try stores[0].list().count, stores.count)
    }

    func testAuthenticationSettingsValidateAndPersist() throws {
        let vault = try VaultStore(url: location(), kek: SymmetricKey(size: .bits256))
        for injection in [CredentialInjection.bearer, .basic(username: "alice"), .header(name: "X-Api-Key", prefix: "token ")] {
            let record = try vault.save(name: UUID().uuidString, kind: .opaque, value: Data([1]), policy: SecretPolicy(injection: injection))
            XCTAssertEqual(try vault.record(named: record.name)?.policy.injection, injection)
        }
        XCTAssertThrowsError(try CredentialInjection.header(name: "Bad\r\nHeader", prefix: "").validate())
        XCTAssertThrowsError(try CredentialInjection.header(name: "X-Key", prefix: "\r\n").validate())
        XCTAssertThrowsError(try CredentialInjection.basic(username: "a:b").validate())
    }
}
