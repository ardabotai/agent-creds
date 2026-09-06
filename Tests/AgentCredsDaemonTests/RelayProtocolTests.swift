import XCTest
import CompanionProtocol

final class RelayProtocolTests: XCTestCase {
    func testRelayAddressesKeepCredentialsOutOfURLsAndRejectUnsafeEndpoints() throws {
        let address = RelayAddress(url: RelayAddress.productionURL, roomID: UUID(), token: String(repeating: "a", count: 64))
        XCTAssertTrue(address.isValid)
        let request = try RelayTransport.request(address, suffix: "/host", websocket: true)
        XCTAssertEqual(request.url?.scheme, "wss")
        XCTAssertNil(request.url?.query)
        XCTAssertFalse(request.url!.absoluteString.contains(address.token))
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer " + address.token)
        for url in ["http://public.example", "https://user:password@example.test", "https://example.test?token=abc", "https://example.test/#fragment", "https://example.test/path", "file:///tmp/relay"] {
            XCTAssertFalse(RelayAddress(url: url, roomID: UUID(), token: address.token).isValid, url)
        }
        XCTAssertFalse(RelayAddress(url: address.url, roomID: address.roomID, token: "short").isValid)
    }
    func testEnrollmentExpiryIsSeparateFromTrustedPairingLifetime() throws {
        let now = Date()
        var invite = PairingInvite(host: "relay", port: 443, key: Data(repeating: 1, count: 32), macName: "Synthetic Mac", expiresAt: now.addingTimeInterval(86400))
        invite.relay = RelayAddress(url: RelayAddress.productionURL, roomID: UUID(), token: String(repeating: "a", count: 64))
        invite.enrollmentExpiresAt = now.addingTimeInterval(600)
        XCTAssertEqual(try PairingInvite.parse(invite.qrString, now: now), invite)
        XCTAssertThrowsError(try PairingInvite.parse(invite.qrString, now: now.addingTimeInterval(601)))
        invite.enrollmentExpiresAt = nil
        XCTAssertEqual(try PairingInvite.parse(invite.qrString, now: now.addingTimeInterval(601)), invite)
        XCTAssertThrowsError(try PairingInvite.parse(invite.qrString, now: now.addingTimeInterval(86401)))
    }
}
