import Foundation
import CryptoKit

public enum CompanionError: Error, LocalizedError {
    case invalid(String)
    public var errorDescription: String? { if case .invalid(let text) = self { return text }; return nil }
}

public struct PairingInvite: Codable, Equatable {
    public var id: UUID
    public var host: String
    public var port: UInt16
    public var key: Data
    public var macName: String
    public var relay: RelayAddress?
    public var enrollmentExpiresAt: Date?
    public var expiresAt: Date
    public init(id: UUID = UUID(), host: String, port: UInt16, key: Data, macName: String, expiresAt: Date) {
        self.id = id; self.host = host; self.port = port; self.key = key; self.macName = macName; self.expiresAt = expiresAt
    }
    public var qrString: String { "agentcreds-pair:" + ((try? JSONEncoder().encode(self)) ?? Data()).base64EncodedString() }
    public static func parse(_ text: String, now: Date = Date()) throws -> PairingInvite {
        guard text.hasPrefix("agentcreds-pair:"), text.count < 4096,
              let data = Data(base64Encoded: String(text.dropFirst("agentcreds-pair:".count))),
              let invite = try? JSONDecoder().decode(Self.self, from: data),
              invite.key.count == 32, invite.port > 0, !invite.host.isEmpty,
              invite.host.count < 256, invite.expiresAt > now,
              (invite.enrollmentExpiresAt ?? invite.expiresAt) > now,
              invite.relay?.isValid != false else {
            throw CompanionError.invalid("This pairing code is invalid or expired. Generate a new code on your Mac.")
        }
        return invite
    }
}

public enum ApprovalLink {
    public static let host = "agentcreds.vercel.app"
    public static func web(_ id: UUID) -> URL { URL(string: "https://\(host)/approve/\(id.uuidString.lowercased())")! }
    public static func native(_ id: UUID) -> URL { URL(string: "agentcreds://approve/\(id.uuidString.lowercased())")! }
    public static func requestID(from url: URL) -> UUID? {
        guard url.query == nil, url.fragment == nil, url.user == nil, url.password == nil, url.port == nil else { return nil }
        guard let path = URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedPath else { return nil }
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        if url.scheme == "https", url.host == host, parts.count == 3, parts[1] == "approve" { return UUID(uuidString: String(parts[2])) }
        if url.scheme == "agentcreds", url.host == "approve", parts.count == 2 { return UUID(uuidString: String(parts[1])) }
        return nil
    }
}

public struct VaultItem: Codable, Identifiable, Equatable {
    public var id: UUID
    public var name: String
    public var kind: String
    public var hosts: [String]
    public var authentication: String
    public var headerName: String
    public var headerPrefix: String
    public var username: String
    public init(id: UUID = UUID(), name: String, kind: String = "opaque", hosts: [String], authentication: String = "bearer", headerName: String = "X-Api-Key", headerPrefix: String = "", username: String = "") {
        self.id = id; self.name = name; self.kind = kind; self.hosts = hosts; self.authentication = authentication
        self.headerName = headerName; self.headerPrefix = headerPrefix; self.username = username
    }
}

public struct CredentialRequest: Codable, Identifiable, Equatable {
    public enum Status: String, Codable { case pending, awaitingMacUnlock, releasing, ready, denied, expired, failed, redeemed }
    public var id: UUID
    public var credentialID: UUID
    public var credentialName: String
    public var agent: String
    public var purpose: String
    public var hosts: [String]
    public var expiresAt: Date
    public var maximumDuration: Int
    public var status: Status
    public var createdAt: Date
    public init(id: UUID = UUID(), credentialID: UUID, credentialName: String, agent: String, purpose: String, hosts: [String], expiresAt: Date, maximumDuration: Int = 900, status: Status = .pending, createdAt: Date = Date()) {
        self.id = id; self.credentialID = credentialID; self.credentialName = credentialName; self.agent = agent
        self.purpose = purpose; self.hosts = hosts; self.expiresAt = expiresAt; self.maximumDuration = maximumDuration; self.status = status; self.createdAt = createdAt
    }
    public func effectiveStatus(at now: Date = Date()) -> Status {
        [.pending, .awaitingMacUnlock, .releasing, .ready].contains(status) && expiresAt <= now ? .expired : status
    }
}

public struct CompanionActivity: Codable, Identifiable {
    public var id: UUID
    public var title: String
    public var detail: String
    public var date: Date
    public init(id: UUID = UUID(), title: String, detail: String, date: Date = Date()) { self.id = id; self.title = title; self.detail = detail; self.date = date }
}

public struct CompanionSnapshot: Codable {
    public var macName: String
    public var protection: String
    public var items: [VaultItem]
    public var requests: [CredentialRequest]
    public var activity: [CompanionActivity]
    public init(macName: String, protection: String, items: [VaultItem], requests: [CredentialRequest], activity: [CompanionActivity]) {
        self.macName = macName; self.protection = protection; self.items = items; self.requests = requests; self.activity = activity
    }
}

public struct CompanionCommand: Codable {
    public enum Action: String, Codable { case snapshot, add, updatePolicy, delete, approve, deny, disconnect, registerPush, unregisterPush, enrollOwner }
    public var id = UUID()
    public var action: Action
    public var item: VaultItem?
    public var value: String?
    public var requestID: UUID?
    public var enrollment: DeviceEnrollment?
    public var signature: Data?
    public var vaultKey: Data?
    public var reviewedRequest: CredentialRequest?
    public var push: PushRegistration?
    public var duration: Int?
    public init(action: Action, item: VaultItem? = nil, value: String? = nil, requestID: UUID? = nil, duration: Int? = nil) {
        self.action = action; self.item = item; self.value = value; self.requestID = requestID; self.duration = duration
    }
}

public struct CompanionReply: Codable {
    public var id: UUID
    public var snapshot: CompanionSnapshot?
    public var pairedInvite: PairingInvite?
    public var keyCapsule: DeviceKeyCapsule?
    public var notificationStatus: String?
    public var error: String?
    public init(id: UUID, snapshot: CompanionSnapshot? = nil, error: String? = nil) { self.id = id; self.snapshot = snapshot; self.error = error }
}

/// Challenge is generated anew by the Mac for each connection. Direction-bound
/// AEAD prevents response reflection; fresh challenges prevent command replay.
public enum CompanionCrypto {
    public static let limit = 1_048_576
    public static func randomKey() -> Data { SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }
    public static func seal<T: Encodable>(_ value: T, key: Data, challenge: Data, direction: String) throws -> Data {
        guard key.count == 32, challenge.count == 32 else { throw CompanionError.invalid("Invalid session") }
        let data = try JSONEncoder().encode(value)
        guard data.count < limit / 2 else { throw CompanionError.invalid("Message too large") }
        return try ChaChaPoly.seal(data, using: SymmetricKey(data: key), authenticating: aad(challenge, direction)).combined
    }
    public static func open<T: Decodable>(_ type: T.Type, data: Data, key: Data, challenge: Data, direction: String) throws -> T {
        guard data.count <= limit, key.count == 32, challenge.count == 32 else { throw CompanionError.invalid("Invalid session") }
        let plaintext = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: data), using: SymmetricKey(data: key), authenticating: aad(challenge, direction))
        return try JSONDecoder().decode(type, from: plaintext)
    }
    private static func aad(_ challenge: Data, _ direction: String) -> Data { Data("agent-creds/companion/v1/\(direction)/".utf8) + challenge }
}

public struct CompanionEnvelope: Codable {
    public let pairingID: UUID
    public let ciphertext: Data
    public init(pairingID: UUID, ciphertext: Data) { self.pairingID = pairingID; self.ciphertext = ciphertext }
}
