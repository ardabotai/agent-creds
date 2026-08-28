import Foundation
import Security

public struct MintRequest {
    public let client: String
    public let secretName: String
    public let purpose: String
    public let ttlSeconds: Int

    public init(client: String, secretName: String, purpose: String, ttlSeconds: Int) {
        self.client = client
        self.secretName = secretName
        self.purpose = purpose
        self.ttlSeconds = ttlSeconds
    }
}

/// Produces a temporary credential from a root secret. One implementation per
/// SecretKind; `request_secret` picks the minter by the record's kind.
public protocol CredentialMinter {
    var kind: SecretKind { get }
    func mint(record: SecretRecord, rootSecret: Data, request: MintRequest) throws -> TempCredential
}

/// State of one signup flow: passwords generated so far (stable per tag, so
/// retried requests reuse the same value) and which have been saved to the
/// vault after a successful response.
public final class SignupGrant {
    public let service: String
    private var generated: [String: String] = [:]
    private var saved: Set<String> = []
    private let lock = NSLock()

    public init(service: String) {
        self.service = service
    }

    public func password(forTag tag: String) -> String {
        lock.lock(); defer { lock.unlock() }
        if let existing = generated[tag] { return existing }
        let password = PasswordGenerator.generate()
        generated[tag] = password
        return password
    }

    public func isSaved(tag: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return saved.contains(tag)
    }

    public func generatedValues() -> [String: String] {
        lock.lock(); defer { lock.unlock() }
        return generated
    }

    /// Returns true the first time a tag is marked, so the caller saves once.
    public func markSaved(tag: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return saved.insert(tag).inserted
    }
}

/// Live table of proxy handles: token -> grant + constraints. The egress proxy
/// resolves incoming bearer tokens against this. In-memory only, so every
/// handle dies with the daemon — that's a feature.
public final class ProxyRegistry {
    public static let shared = ProxyRegistry()

    public enum Grant {
        /// A stored secret attached at egress using the secret's own injection
        /// scheme (bearer, custom header, or basic).
        case credential(rootSecret: Data, injection: CredentialInjection)
        /// A signup flow: no credential yet; passwords are generated on demand.
        case signup(SignupGrant)
    }

    private struct Entry {
        let grant: Grant
        let allowedHosts: [String]
        let expiresAt: Date
    }

    private var entries: [String: Entry] = [:]
    private let lock = NSLock()

    public init() {}

    private func newToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 24)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return "acred_" + bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func add(_ grant: Grant, allowedHosts: [String], ttlSeconds: Int) -> (token: String, expiresAt: Date) {
        let token = newToken()
        let expiresAt = Date().addingTimeInterval(TimeInterval(ttlSeconds))
        lock.lock()
        entries[token] = Entry(grant: grant, allowedHosts: allowedHosts, expiresAt: expiresAt)
        lock.unlock()
        return (token, expiresAt)
    }

    public func register(rootSecret: Data, injection: CredentialInjection = .bearer,
                         allowedHosts: [String], ttlSeconds: Int) -> (token: String, expiresAt: Date) {
        add(.credential(rootSecret: rootSecret, injection: injection),
            allowedHosts: allowedHosts, ttlSeconds: ttlSeconds)
    }

    public func registerSignup(_ grant: SignupGrant, allowedHosts: [String], ttlSeconds: Int) -> (token: String, expiresAt: Date) {
        add(.signup(grant), allowedHosts: allowedHosts, ttlSeconds: ttlSeconds)
    }

    /// Resolves a token for a request to `host`, enforcing expiry and allowlist.
    /// An empty allowlist denies everything (HostPolicy) — never allow-all.
    public func grant(token: String, host: String) -> Grant? {
        lock.lock(); defer { lock.unlock() }
        guard let entry = entries[token], entry.expiresAt > Date() else { return nil }
        guard HostPolicy.matches(host: host, allowedHosts: entry.allowedHosts) else { return nil }
        return entry.grant
    }

    public func resolve(token: String, host: String) -> Data? {
        if case .credential(let root, _)? = grant(token: token, host: host) { return root }
        return nil
    }

    /// The allowlist a token was issued against — used to re-check redirect
    /// targets, which would otherwise escape the first-hop host check.
    public func allowedHosts(token: String) -> [String] {
        lock.lock(); defer { lock.unlock() }
        return entries[token]?.allowedHosts ?? []
    }

    public func revoke(token: String) {
        lock.lock()
        entries[token] = nil
        lock.unlock()
    }
}

/// Tier 1: universal fallback. Returns an opaque handle; the real value only
/// ever leaves the daemon through the egress proxy's outbound requests.
public struct ProxyHandleMinter: CredentialMinter {
    public let kind: SecretKind = .opaque
    private let registry: ProxyRegistry

    public init(registry: ProxyRegistry = .shared) {
        self.registry = registry
    }

    public func mint(record: SecretRecord, rootSecret: Data, request: MintRequest) throws -> TempCredential {
        let (token, expiresAt) = registry.register(rootSecret: rootSecret,
                                                   injection: record.policy.injection,
                                                   allowedHosts: record.policy.allowedHosts,
                                                   ttlSeconds: request.ttlSeconds)
        return TempCredential(payload: .proxyHandle(proxyURL: EgressProxy.baseURL, token: token),
                              expiresAt: expiresAt,
                              allowedHosts: record.policy.allowedHosts)
    }
}

public enum EgressProxy {
    public static let port = 9977
    public static var baseURL: String { "http://127.0.0.1:\(port)" }
}

// TODO Phase 3 minters (tier 2, provider-native ephemeral credentials):
//   OAuthRefreshMinter (.oauthRefresh) — refresh-token grant -> access token
//   STSMinter          (.awsRoot)      — sts:GetSessionToken / AssumeRole
//   GitHubAppMinter    (.githubApp)    — JWT -> installation token
