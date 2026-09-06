import Foundation

/// Push is only a hint to fetch an authenticated request, never an approval.
public enum ApprovalNotification {
    public static let category = "CREDENTIAL_APPROVAL"
    public static let reviewAction = "REVIEW_REQUEST"
    public static func payload(requestID: UUID, pairingID: UUID) -> [String: Any] {
        ["aps": ["alert": ["title": "Approval needed", "body": "An agent is requesting credential access. Open AgentCreds to review."],
                 "sound": "default", "category": category],
         "request_id": requestID.uuidString, "pairing_id": pairingID.uuidString]
    }
    public static func route(_ info: [AnyHashable: Any]) -> (requestID: UUID, pairingID: UUID)? {
        guard let request = info["request_id"] as? String, let id = UUID(uuidString: request),
              let pairing = info["pairing_id"] as? String, let device = UUID(uuidString: pairing) else { return nil }
        return (id, device)
    }
}

public struct PushRegistration: Codable, Equatable {
    public let token: String
    public let environment: String
    public init(token: String, environment: String) { self.token = token; self.environment = environment }
    public var isValid: Bool {
        (32...512).contains(token.count) && token.count.isMultiple(of: 2)
        && token.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        && ["sandbox", "production"].contains(environment)
    }
}
