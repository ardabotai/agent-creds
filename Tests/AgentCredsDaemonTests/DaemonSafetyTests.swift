import XCTest
import CryptoKit
import AgentCredsCore
@testable import agentcredsd

final class DaemonSafetyTests: XCTestCase {
    private func vault(provider: KEKProviding) throws -> VaultStore {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return try VaultStore(url: directory.appendingPathComponent("vault.json"), kekProvider: provider)
    }

    func testCDPToolIsNotAdvertisedAndCannotRelease() throws {
        let handler = MCPHandler(vault: try vault(provider: NeverRelease()))
        let tools = try XCTUnwrap(handler.handle(message: Data(#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.utf8), client: "test"))
        XCTAssertFalse(String(decoding: tools, as: UTF8.self).contains("fill_browser_field"))
        let response = try XCTUnwrap(handler.handle(message: Data(#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fill_browser_field","arguments":{"name":"test","selector":"input","cdp_url":"http://127.0.0.1:9222"}}}"#.utf8), client: "test"))
        XCTAssertTrue(String(decoding: response, as: UTF8.self).contains("Browser fill is disabled"))
    }

    func testLiveProviderSwitchesWithoutRestart() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("vault.json")
        let old = SymmetricKey(size: .bits256), new = SymmetricKey(size: .bits256)
        var oldLoads = 0, newLoads = 0
        let provider = LiveKEKProvider(ceremony: PasskeyCeremony(), vaultURL: url, keychainLoader: {
            oldLoads += 1; return old
        }, passkeyLoader: { _, _ in newLoads += 1; return new })
        let running = try VaultStore(url: url, kekProvider: provider)
        let before = try running.save(name: "before", kind: .opaque, value: Data([1]), policy: SecretPolicy())
        let config = KEKConfig(source: .passkey, relyingParty: "example.test", credentialID: Data([1]),
                               salt: Data([2]), kekCheck: PasskeyKEK.check(for: new))
        XCTAssertFalse(provider.promptsEveryTime)
        _ = try VaultStore(url: url, kek: old).migrateToPasskey(key: new, config: config)
        XCTAssertTrue(provider.promptsEveryTime)
        XCTAssertEqual(try running.revealValue(of: before), Data([1]))
        let after = try running.save(name: "after", kind: .opaque, value: Data([2]), policy: SecretPolicy())
        XCTAssertEqual(try VaultStore(url: url, kek: new).revealValue(of: after), Data([2]))
        XCTAssertEqual(oldLoads, 1)
        XCTAssertEqual(newLoads, 2)
    }

    @MainActor
    func testUISaveAndRefreshDoNotBlockMainActor() async throws {
        let provider = MainThreadPromptProvider()
        let store = try vault(provider: provider)
        let auditURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).appendingPathComponent("audit.jsonl")
        addTeardownBlock { try? FileManager.default.removeItem(at: auditURL.deletingLastPathComponent()) }
        let model = VaultUIModel(vault: store, passkeyCeremony: PasskeyCeremony(), audit: AuditLog(url: auditURL))
        try await model.addSecret(name: "test", kind: .opaque, hosts: ["example.test"], value: "synthetic",
                                  injection: .header(name: "X-Key", prefix: ""))
        let record = try XCTUnwrap(store.record(named: "test"))
        XCTAssertEqual(record.policy.injection, .header(name: "X-Key", prefix: ""))
        XCTAssertFalse(provider.calledOnMain)
    }
}

private struct NeverRelease: KEKProviding {
    var promptsEveryTime: Bool { true }
    func kek(reason: String) throws -> SymmetricKey {
        XCTFail("Disabled browser fill must not acquire a key")
        throw VaultError.io("unexpected key access")
    }
}

private final class MainThreadPromptProvider: KEKProviding {
    var promptsEveryTime: Bool { true }
    var calledOnMain = false
    func kek(reason: String) throws -> SymmetricKey {
        calledOnMain = Thread.isMainThread
        guard !calledOnMain else { throw VaultError.io("Main thread would deadlock") }
        let prompt = DispatchSemaphore(value: 0)
        DispatchQueue.main.async { prompt.signal() }
        guard prompt.wait(timeout: .now() + 3) == .success else { throw VaultError.io("Main actor blocked") }
        return SymmetricKey(size: .bits256)
    }
}
