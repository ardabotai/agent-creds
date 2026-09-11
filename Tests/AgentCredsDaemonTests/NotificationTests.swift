import XCTest
import CryptoKit
import CompanionProtocol
@testable import agentcredsd

final class NotificationTests: XCTestCase {
    func testPayloadContainsOnlyOpaqueRoutingAndGenericAlert() throws {
        let request = UUID(), pairing = UUID()
        let payload = ApprovalNotification.payload(requestID: request, pairingID: pairing)
        XCTAssertEqual(Set(payload.keys), ["aps", "request_id", "pairing_id"])
        XCTAssertEqual(ApprovalNotification.route(payload)?.requestID, request)
        XCTAssertEqual(ApprovalNotification.route(payload)?.pairingID, pairing)
        XCTAssertNil(ApprovalNotification.route(["request_id": request.uuidString]))
        XCTAssertNil(ApprovalNotification.route(["request_id": "bad", "pairing_id": pairing.uuidString]))
        let aps = try XCTUnwrap(payload["aps"] as? [String: Any])
        XCTAssertNil(aps["content-available"])
        XCTAssertEqual(aps["category"] as? String, ApprovalNotification.category)
    }
    func testRegistrationRejectsMalformedTokenAndEnvironment() {
        XCTAssertTrue(PushRegistration(token: String(repeating: "ab", count: 32), environment: "production").isValid)
        for token in ["", "abc", String(repeating: "z", count: 64), String(repeating: "a", count: 513), "../device"] {
            XCTAssertFalse(PushRegistration(token: token, environment: "sandbox").isValid)
        }
        XCTAssertFalse(PushRegistration(token: String(repeating: "ab", count: 32), environment: "https://evil.test").isValid)
        let service = CompanionPush(configuration: nil)
        let invite = PairingInvite(host: "test.local", port: 9978, key: Data(repeating: 0, count: 32), macName: "test", expiresAt: .distantPast)
        XCTAssertThrowsError(try service.register(PushRegistration(token: String(repeating: "ab", count: 32), environment: "sandbox"), pairing: invite))
    }
    func testAPNsRequestHasVerifiedSignatureExpiryAndNoCredentialData() throws {
        let key = P256.Signing.PrivateKey()
        let configuration = CompanionPush.Configuration(teamID: "TESTTEAM", keyID: "TESTKEY", key: key)
        let request = CredentialRequest(credentialID: UUID(), credentialName: "private-name", agent: "private-agent", purpose: "private-purpose", hosts: ["private.test"], expiresAt: Date().addingTimeInterval(600))
        for environment in ["sandbox", "production"] {
            let message = try CompanionPush.makeRequest(request: request, pairingID: UUID(), registration: PushRegistration(token: String(repeating: "ab", count: 32), environment: environment), configuration: configuration)
            XCTAssertEqual(message.url?.host, environment == "sandbox" ? "api.sandbox.push.apple.com" : "api.push.apple.com")
            XCTAssertEqual(message.value(forHTTPHeaderField: "apns-push-type"), "alert")
            XCTAssertEqual(message.value(forHTTPHeaderField: "apns-expiration"), String(Int(request.expiresAt.timeIntervalSince1970)))
            XCTAssertEqual(message.value(forHTTPHeaderField: "apns-collapse-id"), request.id.uuidString)
            let payload = String(decoding: try XCTUnwrap(message.httpBody), as: UTF8.self)
            XCTAssertFalse(payload.contains("private-")); XCTAssertFalse(payload.contains("private.test"))
            let jwt = try XCTUnwrap(message.value(forHTTPHeaderField: "authorization")).dropFirst(7).split(separator: ".")
            XCTAssertEqual(jwt.count, 3)
            var encoded = String(jwt[2]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: XCTUnwrap(Data(base64Encoded: encoded)))
            XCTAssertTrue(key.publicKey.isValidSignature(signature, for: Data("\(jwt[0]).\(jwt[1])".utf8)))
        }
    }
}
