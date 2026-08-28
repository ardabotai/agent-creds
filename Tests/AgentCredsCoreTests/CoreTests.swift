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
