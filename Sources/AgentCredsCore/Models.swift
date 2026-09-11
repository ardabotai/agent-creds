import Foundation

/// What kind of root credential a secret holds. Determines which minter can
/// produce temporary credentials from it.
public enum SecretKind: String, Codable, CaseIterable {
    /// Generic API key / password. Released only as a proxy handle (tier 1).
    case opaque
    /// OAuth refresh token. Mints short-lived access tokens (tier 2). TODO.
    case oauthRefresh
    /// Long-lived AWS keys. Mints STS session credentials (tier 2). TODO.
    case awsRoot
    /// GitHub App private key. Mints installation tokens (tier 2). TODO.
    case githubApp
}

/// How the egress proxy places a credential into an outbound request. Stored
/// per secret, because the agent never sees the value and so cannot position it
/// itself — guessing "Bearer" for every secret silently breaks Basic auth and
/// API keys that belong in their own header.
public enum CredentialInjection: Codable, Equatable {
    /// Authorization: Bearer <secret>
    case bearer
    /// <name>: <prefix><secret> — e.g. header("X-Api-Key", prefix: "") or
    /// header("Authorization", prefix: "token ").
    case header(name: String, prefix: String)
    /// Authorization: Basic base64(<username>:<secret>)
    case basic(username: String)

    public func validate() throws {
        switch self {
        case .bearer: break
        case .basic(let username):
            guard !username.isEmpty, !username.contains(":"),
                  !username.contains(where: { $0.isNewline }) else {
                throw VaultError.io("Basic authentication requires a username without colons or newlines.")
            }
        case .header(let name, let prefix):
            let token = CharacterSet(charactersIn: "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
            guard !name.isEmpty, name.unicodeScalars.allSatisfy({ token.contains($0) }),
                  !prefix.contains(where: { $0.isNewline }) else {
                throw VaultError.io("Enter a valid HTTP header name and a prefix without newlines.")
            }
        }
    }

    /// The header this injection writes, and the value to write into it.
    public func headerField(secret: String) -> (name: String, value: String) {
        switch self {
        case .bearer:
            return ("Authorization", "Bearer \(secret)")
        case .header(let name, let prefix):
            return (name, prefix + secret)
        case .basic(let username):
            let encoded = Data("\(username):\(secret)".utf8).base64EncodedString()
            return ("Authorization", "Basic \(encoded)")
        }
    }
}

public struct SecretPolicy: Codable {
    /// Default lifetime of a minted temporary credential.
    public var defaultTTLSeconds: Int
    /// Hosts the egress proxy will forward this credential to. EMPTY = DENY ALL:
    /// a secret with no declared hosts has no egress path (see HostPolicy).
    public var allowedHosts: [String]
    /// Whether the raw value may ever be revealed to an agent (elevated approval).
    public var allowReveal: Bool
    /// Where the credential goes in an outbound request.
    public var injection: CredentialInjection

    public init(defaultTTLSeconds: Int = 900, allowedHosts: [String] = [],
                allowReveal: Bool = false, injection: CredentialInjection = .bearer) {
        self.defaultTTLSeconds = defaultTTLSeconds
        self.allowedHosts = allowedHosts
        self.allowReveal = allowReveal
        self.injection = injection
    }

    // Hand-written so vaults written before `injection` existed still decode.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        defaultTTLSeconds = try container.decodeIfPresent(Int.self, forKey: .defaultTTLSeconds) ?? 900
        allowedHosts = try container.decodeIfPresent([String].self, forKey: .allowedHosts) ?? []
        allowReveal = try container.decodeIfPresent(Bool.self, forKey: .allowReveal) ?? false
        injection = try container.decodeIfPresent(CredentialInjection.self, forKey: .injection) ?? .bearer
    }
}

public struct SecretRecord: Codable, Identifiable {
    public var id: UUID
    public var name: String
    public var kind: SecretKind
    /// Value encrypted with a per-secret DEK (ChaChaPoly, combined format).
    public var ciphertext: Data
    /// The DEK, wrapped by the master KEK.
    public var wrappedDEK: Data
    public var policy: SecretPolicy
    public var createdAt: Date

    public init(id: UUID = UUID(), name: String, kind: SecretKind, ciphertext: Data,
                wrappedDEK: Data, policy: SecretPolicy, createdAt: Date = Date()) {
        self.id = id
        self.name = name
        self.kind = kind
        self.ciphertext = ciphertext
        self.wrappedDEK = wrappedDEK
        self.policy = policy
        self.createdAt = createdAt
    }
}

public struct SecretMetadata: Codable, Identifiable {
    public var id: String { name }
    public let name: String
    public let kind: SecretKind
    public let createdAt: Date
    /// Host allowlist only — never the secret value. Empty means deny-all.
    public let allowedHosts: [String]

    public init(name: String, kind: SecretKind, createdAt: Date, allowedHosts: [String] = []) {
        self.name = name
        self.kind = kind
        self.createdAt = createdAt
        self.allowedHosts = allowedHosts
    }
}

/// What an agent actually receives from `request_secret`. Never the root value.
public struct TempCredential: Codable {
    public enum Payload: Codable {
        /// Tier 1: opaque handle usable only through the local egress proxy.
        case proxyHandle(proxyURL: String, token: String)
        /// Tier 2: a provider-minted, self-expiring credential (e.g. STS session).
        case ephemeralValue(String)
    }

    public var payload: Payload
    public var expiresAt: Date
    public var allowedHosts: [String]

    public init(payload: Payload, expiresAt: Date, allowedHosts: [String]) {
        self.payload = payload
        self.expiresAt = expiresAt
        self.allowedHosts = allowedHosts
    }
}

public struct AuditEvent: Codable {
    public var timestamp: Date
    public var client: String
    public var action: String
    public var secretName: String?
    public var decision: String?

    public init(timestamp: Date = Date(), client: String, action: String,
                secretName: String? = nil, decision: String? = nil) {
        self.timestamp = timestamp
        self.client = client
        self.action = action
        self.secretName = secretName
        self.decision = decision
    }
}
