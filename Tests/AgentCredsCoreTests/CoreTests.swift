import XCTest
import CryptoKit
@testable import AgentCredsCore

final class CoreTests: XCTestCase {
    func testEnvelopeRoundTrip() throws {
        let kek = SymmetricKey(size: .bits256)
        let plaintext = Data("hunter2".utf8)
        let (ciphertext, wrappedDEK) = try Envelope.seal(plaintext, kek: kek)
        XCTAssertNotEqual(ciphertext, plaintext)
        let opened = try Envelope.open(ciphertext: ciphertext, wrappedDEK: wrappedDEK, kek: kek)
        XCTAssertEqual(opened, plaintext)
    }

    func testEnvelopeWrongKEKFails() throws {
        let (ciphertext, wrappedDEK) = try Envelope.seal(Data("x".utf8), kek: SymmetricKey(size: .bits256))
        XCTAssertThrowsError(try Envelope.open(ciphertext: ciphertext, wrappedDEK: wrappedDEK,
                                               kek: SymmetricKey(size: .bits256)))
    }

    func testProxyRegistryExpiryAndHostScoping() {
        let registry = ProxyRegistry()
        let secret = Data("tok".utf8)
        let (token, _) = registry.register(rootSecret: secret, allowedHosts: ["api.github.com"], ttlSeconds: 60)
        XCTAssertEqual(registry.resolve(token: token, host: "api.github.com"), secret)
        XCTAssertNil(registry.resolve(token: token, host: "evil.example.com"))
        XCTAssertNil(registry.resolve(token: "acred_bogus", host: "api.github.com"))

        let (expired, _) = registry.register(rootSecret: secret, allowedHosts: [], ttlSeconds: -1)
        XCTAssertNil(registry.resolve(token: expired, host: "api.github.com"))
    }

    func testPasswordGeneratorShape() {
        let password = PasswordGenerator.generate()
        XCTAssertEqual(password.count, 24)
        XCTAssertTrue(password.contains { PasswordGenerator.upper.contains($0) })
        XCTAssertTrue(password.contains { PasswordGenerator.lower.contains($0) })
        XCTAssertTrue(password.contains { PasswordGenerator.digits.contains($0) })
        XCTAssertTrue(password.contains { PasswordGenerator.symbols.contains($0) })
        XCTAssertNotEqual(password, PasswordGenerator.generate())
    }

    func testPlaceholderSignupSubstitution() throws {
        let grant = SignupGrant(service: "example.com")
        let context = PlaceholderEngine.Context(
            identity: Identity(email: "user@example.com", username: "example-user"),
            signup: grant)
        let body = #"{"email":"{{acred:email}}","user":"{{acred:username}}","pw":"{{acred:password.generate}}","pw2":"{{acred:password.confirm}}"}"#
        let (output, secrets) = try PlaceholderEngine.substitute(body, context: context)

        XCTAssertFalse(output.contains("{{acred:"))
        XCTAssertTrue(output.contains("user@example.com"))
        let password = grant.password(forTag: "default")
        // generate and confirm resolved to the same value, reported once each
        XCTAssertEqual(secrets, [password, password])
        XCTAssertEqual(output.components(separatedBy: password).count, 3)
        // distinct tags generate distinct passwords; retries are stable
        XCTAssertNotEqual(grant.password(forTag: "other"), password)
        XCTAssertEqual(grant.password(forTag: "default"), password)
    }

    func testPlaceholderErrors() {
        let noSignup = PlaceholderEngine.Context(identity: Identity(email: "a@b.c"), signup: nil)
        XCTAssertThrowsError(try PlaceholderEngine.substitute("{{acred:password.generate}}", context: noSignup))
        let noIdentity = PlaceholderEngine.Context(identity: Identity(), signup: nil)
        XCTAssertThrowsError(try PlaceholderEngine.substitute("{{acred:email}}", context: noIdentity))
        XCTAssertThrowsError(try PlaceholderEngine.substitute("{{acred:bogus}}", context: noSignup))
    }

    func testPlaceholderTransformAppliesToValueOnly() throws {
        let context = PlaceholderEngine.Context(identity: Identity(email: "a+b@c.io"), signup: nil)
        let (output, _) = try PlaceholderEngine.substitute("/signup?email={{acred:email}}", context: context) {
            $0.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? $0
        }
        XCTAssertEqual(output, "/signup?email=a%2Bb%40c%2Eio")
    }

    func testSignupGrantResolution() {
        let registry = ProxyRegistry()
        let grant = SignupGrant(service: "example.com")
        let (token, _) = registry.registerSignup(grant, allowedHosts: ["example.com"], ttlSeconds: 60)
        guard case .signup(let resolved)? = registry.grant(token: token, host: "example.com") else {
            return XCTFail("expected signup grant")
        }
        XCTAssertTrue(resolved === grant)
        XCTAssertNil(registry.grant(token: token, host: "evil.example.net"))
        XCTAssertTrue(grant.markSaved(tag: "default"))
        XCTAssertFalse(grant.markSaved(tag: "default"))
    }

    func testEmptyAllowlistDeniesEveryHost() {
        XCTAssertFalse(HostPolicy.matches(host: "attacker.example", allowedHosts: []))
        XCTAssertFalse(HostPolicy.matches(host: "api.github.com", allowedHosts: []))
        XCTAssertTrue(HostPolicy.matches(host: "api.github.com", allowedHosts: ["api.github.com"]))
        XCTAssertTrue(HostPolicy.matches(host: "API.GitHub.com", allowedHosts: ["api.github.com"]))
        XCTAssertTrue(HostPolicy.matches(host: "gist.github.com", allowedHosts: ["github.com"]))
        // suffix matching must not admit a lookalike parent domain
        XCTAssertFalse(HostPolicy.matches(host: "evilgithub.com", allowedHosts: ["github.com"]))
        XCTAssertFalse(HostPolicy.matches(host: "github.com.evil.net", allowedHosts: ["github.com"]))
    }

    func testEmptyAllowlistDeniesAtTheRegistry() {
        let registry = ProxyRegistry()
        let (token, _) = registry.register(rootSecret: Data("tok".utf8), allowedHosts: [], ttlSeconds: 60)
        XCTAssertNil(registry.resolve(token: token, host: "attacker.example"))
        XCTAssertNil(registry.grant(token: token, host: "api.github.com"))
    }

    func testLoopbackEndpointRejectsLookalikeHosts() {
        XCTAssertTrue(HostPolicy.isLoopbackEndpoint("http://127.0.0.1:9222"))
        XCTAssertTrue(HostPolicy.isLoopbackEndpoint("http://localhost:9222/json/list"))
        XCTAssertFalse(HostPolicy.isLoopbackEndpoint("http://127.0.0.1.evil.com:9222"))
        XCTAssertFalse(HostPolicy.isLoopbackEndpoint("http://localhost.evil.com"))
        XCTAssertFalse(HostPolicy.isLoopbackEndpoint("http://evil.com/?x=127.0.0.1"))
    }

    func testTransformedSecretIsAlsoTrackedForScrubbing() throws {
        let grant = SignupGrant(service: "example.com")
        let context = PlaceholderEngine.Context(identity: Identity(), signup: grant)
        let (output, secrets) = try PlaceholderEngine.substitute("/signup/{{acred:password.generate}}",
                                                                 context: context) {
            $0.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? $0
        }
        let raw = grant.password(forTag: "default")
        let encoded = raw.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        XCTAssertTrue(output.contains(encoded))
        // both the raw and the on-the-wire form must be scrubbable
        XCTAssertTrue(secrets.contains(raw))
        XCTAssertTrue(secrets.contains(encoded))
    }

    func testIdentityValuesAreNotTrackedAsSecrets() throws {
        let context = PlaceholderEngine.Context(identity: Identity(email: "a@b.c"), signup: nil)
        let (_, secrets) = try PlaceholderEngine.substitute("{{acred:email}}", context: context)
        XCTAssertTrue(secrets.isEmpty)
    }

    func testInjectionSchemes() {
        XCTAssertEqual(CredentialInjection.bearer.headerField(secret: "s").name, "Authorization")
        XCTAssertEqual(CredentialInjection.bearer.headerField(secret: "s").value, "Bearer s")
        let apiKey = CredentialInjection.header(name: "X-Api-Key", prefix: "")
        XCTAssertEqual(apiKey.headerField(secret: "k").name, "X-Api-Key")
        XCTAssertEqual(apiKey.headerField(secret: "k").value, "k")
        let prefixed = CredentialInjection.header(name: "Authorization", prefix: "token ")
        XCTAssertEqual(prefixed.headerField(secret: "k").value, "token k")
        let basic = CredentialInjection.basic(username: "user")
        XCTAssertEqual(basic.headerField(secret: "pw").value,
                       "Basic " + Data("user:pw".utf8).base64EncodedString())
    }

    func testPolicyDecodesWithoutInjectionField() throws {
        // vaults written before `injection` existed must still load
        let legacy = Data(#"{"defaultTTLSeconds":900,"allowedHosts":["api.github.com"],"allowReveal":false}"#.utf8)
        let policy = try JSONDecoder().decode(SecretPolicy.self, from: legacy)
        XCTAssertEqual(policy.allowedHosts, ["api.github.com"])
        XCTAssertEqual(policy.injection, .bearer)
    }

    func testSecureFileIsNeverWorldReadable() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("vault.json")
        try SecureFile.write(Data("secret".utf8), to: url)
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.int16Value, 0o600)
        XCTAssertEqual(try Data(contentsOf: url), Data("secret".utf8))
        // overwriting keeps the restrictive mode
        try SecureFile.write(Data("second".utf8), to: url)
        let mode2 = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode2?.int16Value, 0o600)
        XCTAssertEqual(try Data(contentsOf: url), Data("second".utf8))
    }

    func testSignupGrantMarksSavedOnlyOnce() {
        let grant = SignupGrant(service: "example.com")
        _ = grant.password(forTag: "default")
        XCTAssertFalse(grant.isSaved(tag: "default"))
        XCTAssertTrue(grant.markSaved(tag: "default"))
        XCTAssertTrue(grant.isSaved(tag: "default"))
        XCTAssertFalse(grant.markSaved(tag: "default"))
    }

    func testEnvNameDerivation() {
        XCTAssertEqual(EnvName.derive(from: "github/token"), "GITHUB_TOKEN")
        XCTAssertEqual(EnvName.derive(from: "aws.secret-key"), "AWS_SECRET_KEY")
        XCTAssertEqual(EnvName.derive(from: "1secret"), "_1SECRET")
        XCTAssertEqual(EnvName.derive(from: "///"), "SECRET")
    }

    func testVaultSaveListDelete() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let kek = SymmetricKey(size: .bits256)
        let vault = try VaultStore(url: dir.appendingPathComponent("vault.json"), kek: kek)
        try vault.save(name: "github/token", kind: .opaque, value: Data("ghp_abc".utf8),
                       policy: SecretPolicy(allowedHosts: ["api.github.com"]))
        XCTAssertEqual(try vault.list().map(\.name), ["github/token"])
        let record = try XCTUnwrap(try vault.record(named: "github/token"))
        XCTAssertEqual(try vault.revealValue(of: record), Data("ghp_abc".utf8))
        try vault.delete(name: "github/token")
        XCTAssertTrue(try vault.list().isEmpty)
    }
}

final class AuditLogTests: XCTestCase {
    private func temporaryLog() -> AuditLog {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("audit.jsonl")
        return AuditLog(url: url)
    }

    func testRecordsAppendInOrder() throws {
        let log = temporaryLog()
        log.record(client: "claude-code", action: "request_secret",
                   secretName: "github/token", decision: "approved")
        log.record(client: "claude-code", action: "request_secret",
                   secretName: "stripe/key", decision: "denied")
        let events = try log.recent()
        XCTAssertEqual(events.count, 2)
        XCTAssertEqual(events.first?.secretName, "github/token")
        XCTAssertEqual(events.first?.decision, "approved")
        XCTAssertEqual(events.last?.decision, "denied")
        XCTAssertEqual(events.last?.action, "request_secret")
    }

    func testRecentAppliesLimit() throws {
        let log = temporaryLog()
        for index in 0..<10 {
            log.record(client: "cli", action: "run", secretName: "secret\(index)")
        }
        let events = try log.recent(limit: 3)
        XCTAssertEqual(events.count, 3)
        XCTAssertEqual(events.last?.secretName, "secret9")
    }

    func testEmptyLogReadsAsNoEvents() throws {
        XCTAssertTrue(try temporaryLog().recent().isEmpty)
    }
}

final class UnixSocketTests: XCTestCase {
    /// A second listener must not unlink a socket that someone is answering on.
    /// Doing so orphans the first daemon's inode: it keeps its listening fd, the
    /// path still looks like a healthy socket, and every client gets
    /// ECONNREFUSED with nothing in the logs to explain it.
    func testListenRefusesToStealALiveSocket() throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("ac-\(UUID().uuidString.prefix(8)).sock").path
        let first = try UnixSocket.listen(at: path)
        defer { close(first); unlink(path) }

        XCTAssertThrowsError(try UnixSocket.listen(at: path)) { error in
            guard case UnixSocketError.alreadyInUse = error else {
                return XCTFail("expected alreadyInUse, got \(error)")
            }
        }

        // The original listener is still reachable — not orphaned.
        let client = try UnixSocket.connect(to: path)
        close(client)
    }

    /// A socket file left behind by a crashed daemon must not block startup.
    func testListenReclaimsAStaleSocket() throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("ac-\(UUID().uuidString.prefix(8)).sock").path
        let dead = try UnixSocket.listen(at: path)
        close(dead)                                  // simulate a crashed daemon
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))

        let revived = try UnixSocket.listen(at: path)
        defer { close(revived); unlink(path) }
        let client = try UnixSocket.connect(to: path)
        close(client)
    }
}

final class PasskeyKEKTests: XCTestCase {
    func testDerivedKEKIsDeterministicAndDomainSeparated() {
        let prf = SymmetricKey(size: .bits256)
        let a = PasskeyKEK.deriveKEK(prfOutput: prf, relyingParty: "agentcreds.ardabot.ai")
        let b = PasskeyKEK.deriveKEK(prfOutput: prf, relyingParty: "agentcreds.ardabot.ai")
        XCTAssertEqual(a.withUnsafeBytes { Data($0) }, b.withUnsafeBytes { Data($0) })

        // The same authenticator output used for a different relying party must
        // not yield the same vault key.
        let other = PasskeyKEK.deriveKEK(prfOutput: prf, relyingParty: "example.com")
        XCTAssertNotEqual(a.withUnsafeBytes { Data($0) }, other.withUnsafeBytes { Data($0) })
    }

    func testKEKCheckDetectsTheWrongPasskey() {
        let enrolled = PasskeyKEK.deriveKEK(prfOutput: SymmetricKey(size: .bits256),
                                            relyingParty: "agentcreds.ardabot.ai")
        let different = PasskeyKEK.deriveKEK(prfOutput: SymmetricKey(size: .bits256),
                                             relyingParty: "agentcreds.ardabot.ai")
        XCTAssertEqual(PasskeyKEK.check(for: enrolled), PasskeyKEK.check(for: enrolled))
        XCTAssertNotEqual(PasskeyKEK.check(for: enrolled), PasskeyKEK.check(for: different))
        // The check must not be the key itself.
        XCTAssertNotEqual(PasskeyKEK.check(for: enrolled), enrolled.withUnsafeBytes { Data($0) })
    }

    func testSaltsAreUnique() {
        XCTAssertEqual(PasskeyKEK.newSalt().count, 32)
        XCTAssertNotEqual(PasskeyKEK.newSalt(), PasskeyKEK.newSalt())
    }

    /// Switching KEK source must preserve every secret. This is the step that
    /// would destroy a vault if it were wrong.
    func testRewrapPreservesEverySecretUnderTheNewKEK() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString).appendingPathComponent("vault.json")
        let oldKEK = SymmetricKey(size: .bits256)
        let vault = try VaultStore(url: url, kek: oldKEK)
        try vault.save(name: "github/token", kind: .opaque, value: Data("ghp_one".utf8),
                       policy: SecretPolicy(allowedHosts: ["api.github.com"]))
        try vault.save(name: "stripe/key", kind: .opaque, value: Data("sk_two".utf8),
                       policy: SecretPolicy(allowedHosts: ["api.stripe.com"]))

        let newKEK = SymmetricKey(size: .bits256)
        try vault.rewrapDEKs(to: newKEK, reason: "test")

        // Readable under the new KEK...
        let reopened = try VaultStore(url: url, kek: newKEK)
        let github = try XCTUnwrap(try reopened.record(named: "github/token"))
        XCTAssertEqual(try reopened.revealValue(of: github), Data("ghp_one".utf8))
        let stripe = try XCTUnwrap(try reopened.record(named: "stripe/key"))
        XCTAssertEqual(try reopened.revealValue(of: stripe), Data("sk_two".utf8))
        // ...and no longer under the old one.
        let stale = try VaultStore(url: url, kek: oldKEK)
        XCTAssertThrowsError(try stale.revealValue(of: try XCTUnwrap(stale.record(named: "github/token"))))
        // Policy and metadata survive the re-wrap.
        XCTAssertEqual(github.policy.allowedHosts, ["api.github.com"])
    }

    func testKEKConfigRoundTrips() throws {
        let config = KEKConfig(source: .passkey, relyingParty: "agentcreds.ardabot.ai",
                               credentialID: Data([1, 2, 3]), salt: PasskeyKEK.newSalt(),
                               kekCheck: Data([9, 9]))
        let data = try JSONEncoder().encode(config)
        let back = try JSONDecoder().decode(KEKConfig.self, from: data)
        XCTAssertEqual(back.source, .passkey)
        XCTAssertEqual(back.relyingParty, "agentcreds.ardabot.ai")
        XCTAssertEqual(back.credentialID, Data([1, 2, 3]))
        // A vault with no config file defaults to the Keychain, not to passkey.
        XCTAssertEqual(KEKConfig().source, .keychain)
    }
}

final class CredentialLookupTests: XCTestCase {
    private func vault() throws -> VaultStore {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString).appendingPathComponent("vault.json")
        let store = try VaultStore(url: url, kek: SymmetricKey(size: .bits256))
        try store.save(name: "github/token", kind: .opaque, value: Data("a".utf8),
                       policy: SecretPolicy(allowedHosts: ["api.github.com"]))
        try store.save(name: "stripe/api-key", kind: .opaque, value: Data("b".utf8),
                       policy: SecretPolicy(allowedHosts: ["api.stripe.com"]))
        return store
    }

    func testExactNameWinsOutright() throws {
        let found = try vault().find(matching: "github/token")
        XCTAssertEqual(found.map(\.name), ["github/token"])
    }

    /// An agent knows the site it is working with, not what the user named the
    /// secret. Both must resolve to the same credential.
    func testFindsByHostTheAgentIsActuallyTalkingTo() throws {
        XCTAssertEqual(try vault().find(matching: "api.github.com").map(\.name), ["github/token"])
        XCTAssertEqual(try vault().find(matching: "github.com").map(\.name), ["github/token"])
        XCTAssertEqual(try vault().find(matching: "https://api.stripe.com/v1/charges").map(\.name),
                       ["stripe/api-key"])
    }

    func testUnknownDomainFindsNothing() throws {
        XCTAssertTrue(try vault().find(matching: "example.com").isEmpty)
        // ...which is the signal to ask the user for it rather than to fail.
    }

    func testUnrelatedHostDoesNotMatchOnSuffixAccident() throws {
        XCTAssertTrue(try vault().find(matching: "evilgithub.com").isEmpty)
    }
}
