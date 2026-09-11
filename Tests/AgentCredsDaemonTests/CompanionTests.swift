import XCTest
import CryptoKit
import CompanionProtocol
import AgentCredsCore
@testable import agentcredsd

final class CompanionTests: XCTestCase {
    private func fixture(unlock: @escaping (String) -> Bool = { _ in true }) throws -> (VaultStore, CompanionApprovals, AuditLog) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let vault = try VaultStore(url: directory.appendingPathComponent("vault.json"), kek: SymmetricKey(size: .bits256))
        let audit = AuditLog(url: directory.appendingPathComponent("audit.jsonl"))
        return (vault, CompanionApprovals(vault: vault, notifications: CompanionPush(configuration: nil), audit: audit, unlock: unlock), audit)
    }
    private func pending(_ vault: VaultStore, _ approvals: CompanionApprovals) throws -> (UUID, String, SecretRecord) {
        let record = try vault.save(name: "synthetic", kind: .opaque, value: Data("synthetic-value".utf8), policy: SecretPolicy(allowedHosts: ["example.test"]))
        let response = try approvals.create(record: record, agent: "test-agent", purpose: "test request")
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(response.utf8)) as? [String: String])
        let id = try XCTUnwrap(UUID(uuidString: XCTUnwrap(object["request_id"])))
        let token = try XCTUnwrap(object["redemption_token"])
        XCTAssertFalse(object["approval_url"]!.contains(token))
        XCTAssertFalse(response.contains("synthetic-value"))
        return (id, token, record)
    }
    func testLinksRejectUntrustedHostsAndParameters() {
        let id = UUID()
        XCTAssertEqual(ApprovalLink.requestID(from: ApprovalLink.web(id)), id)
        XCTAssertEqual(ApprovalLink.requestID(from: ApprovalLink.native(id)), id)
        for value in ["https://evil.test/approve/\(id)", "https://agentcreds.vercel.app.evil.test/approve/\(id)", "agentcreds://approve/\(id)?approved=true", "https://agentcreds.vercel.app/approve/\(id)#token", "agentcreds://approve/\(id)/", "https://user@agentcreds.vercel.app/approve/\(id)"] {
            XCTAssertNil(ApprovalLink.requestID(from: URL(string: value)!), value)
        }
    }
    func testWireRejectsTamperingReplayAndReflection() throws {
        let key = CompanionCrypto.randomKey(), challenge = CompanionCrypto.randomKey()
        let command = CompanionCommand(action: .approve, requestID: UUID(), duration: 120)
        let sealed = try CompanionCrypto.seal(command, key: key, challenge: challenge, direction: "request")
        XCTAssertEqual(try CompanionCrypto.open(CompanionCommand.self, data: sealed, key: key, challenge: challenge, direction: "request").id, command.id)
        XCTAssertThrowsError(try CompanionCrypto.open(CompanionCommand.self, data: sealed, key: key, challenge: CompanionCrypto.randomKey(), direction: "request"))
        XCTAssertThrowsError(try CompanionCrypto.open(CompanionCommand.self, data: sealed, key: key, challenge: challenge, direction: "response"))
        XCTAssertThrowsError(try CompanionCrypto.open(CompanionCommand.self, data: sealed, key: CompanionCrypto.randomKey(), challenge: challenge, direction: "request"))
        var tampered = sealed; tampered[tampered.startIndex + 15] ^= 1
        XCTAssertThrowsError(try CompanionCrypto.open(CompanionCommand.self, data: tampered, key: key, challenge: challenge, direction: "request"))
    }
    func testPairingRejectsExpiredOrMalformedCodes() throws {
        let invite = PairingInvite(host: "mac.local", port: 9978, key: CompanionCrypto.randomKey(), macName: "Mac", expiresAt: Date().addingTimeInterval(60))
        XCTAssertEqual(try PairingInvite.parse(invite.qrString).id, invite.id)
        XCTAssertThrowsError(try PairingInvite.parse(invite.qrString, now: Date().addingTimeInterval(120)))
        XCTAssertThrowsError(try PairingInvite.parse("https://evil.test"))
    }
    func testApprovalCanOnlyBeRedeemedOnceWithCapability() async throws {
        let (vault, approvals, _) = try fixture()
        let (id, token, _) = try pending(vault, approvals)
        XCTAssertThrowsError(try approvals.poll(id: id, token: "wrong"))
        try approvals.decide(id: id, approved: true, duration: 120)
        XCTAssertThrowsError(try approvals.decide(id: id, approved: true, duration: 120))
        for _ in 0..<100 {
            if approvals.list().first?.status == .ready { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertEqual(approvals.list().first?.status, .ready)
        let result = try approvals.poll(id: id, token: token)
        XCTAssertTrue(result.contains("proxyHandle"))
        XCTAssertFalse(result.contains("synthetic-value"))
        XCTAssertEqual(try approvals.poll(id: id, token: token), "{\"status\":\"redeemed\"}")
    }
    func testDeniedRequestAndChangedCredentialCannotRelease() async throws {
        let (vault, approvals, _) = try fixture()
        let (id, token, record) = try pending(vault, approvals)
        try vault.updatePolicy(name: record.name, expectedID: record.id, policy: SecretPolicy(allowedHosts: ["other.test"]))
        try approvals.decide(id: id, approved: true, duration: 120)
        for _ in 0..<100 {
            if approvals.list().first?.status == .failed { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertEqual(try approvals.poll(id: id, token: token), "{\"status\":\"failed\"}")
        let (secondVault, second, _) = try fixture()
        let (deniedID, deniedToken, _) = try pending(secondVault, second)
        try second.decide(id: deniedID, approved: false, duration: 1)
        XCTAssertThrowsError(try second.decide(id: deniedID, approved: true, duration: 120))
        XCTAssertEqual(try second.poll(id: deniedID, token: deniedToken), "{\"status\":\"denied\"}")
    }
    func testRevocationCancelsApprovalDuringMacUnlock() async throws {
        let reached = expectation(description: "Mac unlock requested")
        let resume = DispatchSemaphore(value: 0)
        let (vault, approvals, _) = try fixture { _ in reached.fulfill(); _ = resume.wait(timeout: .now() + 5); return true }
        let (id, token, _) = try pending(vault, approvals)
        try approvals.decide(id: id, approved: true, duration: 120)
        await fulfillment(of: [reached], timeout: 3)
        approvals.cancelOutstanding(); resume.signal()
        XCTAssertEqual(try approvals.poll(id: id, token: token), "{\"status\":\"denied\"}")
    }
    func testEncryptedLANRoundTripReturnsMetadataOnly() async throws {
        let (vault, approvals, audit) = try fixture()
        let (_, _, _) = try pending(vault, approvals)
        let server = CompanionServer(vault: vault, approvals: approvals, port: 0, audit: audit, authenticate: { _ in true })
        var invite = try server.invite()
        defer { server.revokeAll() }
        invite.host = "127.0.0.1"
        let reply = try await CompanionNetwork.exchange(CompanionCommand(action: .snapshot), pairing: invite)
        XCTAssertEqual(reply.snapshot?.items.first?.name, "synthetic")
        XCTAssertEqual(reply.snapshot?.requests.count, 1)
        var registration = CompanionCommand(action: .registerPush)
        registration.push = PushRegistration(token: String(repeating: "ab", count: 32), environment: "sandbox")
        let registered = try await CompanionNetwork.exchange(registration, pairing: invite)
        XCTAssertEqual(registered.notificationStatus, "Mac push delivery is not configured")
        XCTAssertNil(registered.snapshot)
        _ = try await CompanionNetwork.exchange(CompanionCommand(action: .unregisterPush), pairing: invite)
        let encoded = try JSONEncoder().encode(reply)
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("synthetic-value"))
        let id = try XCTUnwrap(reply.snapshot?.requests.first?.id)
        let denial = try await CompanionNetwork.exchange(CompanionCommand(action: .deny, requestID: id, duration: 1), pairing: invite)
        XCTAssertEqual(denial.snapshot?.requests.first?.status, .denied)
        let item = VaultItem(name: "added-from-phone", hosts: ["example.test"], authentication: "header", headerName: "X-Key")
        let added = try await CompanionNetwork.exchange(CompanionCommand(action: .add, item: item, value: "synthetic-new"), pairing: invite)
        var savedItem = try XCTUnwrap(added.snapshot?.items.first { $0.name == item.name })
        XCTAssertEqual(savedItem.authentication, "header")
        savedItem.hosts = ["changed.test"]
        let changed = try await CompanionNetwork.exchange(CompanionCommand(action: .updatePolicy, item: savedItem), pairing: invite)
        let changedItem = try XCTUnwrap(changed.snapshot?.items.first { $0.name == item.name })
        XCTAssertNotEqual(changedItem.id, savedItem.id)
        XCTAssertEqual(changedItem.hosts, ["changed.test"])
        let deleted = try await CompanionNetwork.exchange(CompanionCommand(action: .delete, item: changedItem), pairing: invite)
        XCTAssertFalse(deleted.snapshot!.items.contains { $0.name == item.name })
        _ = try await CompanionNetwork.exchange(CompanionCommand(action: .disconnect), pairing: invite)
        do {
            _ = try await CompanionNetwork.exchange(CompanionCommand(action: .snapshot), pairing: invite)
            XCTFail("Revoked pairing was accepted")
        } catch { }
    }
}
