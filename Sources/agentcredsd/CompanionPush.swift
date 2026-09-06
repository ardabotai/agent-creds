import Foundation
import CryptoKit
import CompanionProtocol

/// Interim APNs provider on the Mac. The hosted relay can later own this transport.
/// Only opaque request and pairing IDs leave the Mac; never vault metadata or grants.
final class CompanionPush {
    struct Configuration {
        let teamID: String
        let keyID: String
        let key: P256.Signing.PrivateKey
        static func load() -> Configuration? {
            let env = ProcessInfo.processInfo.environment
            guard let team = env["AGENTCREDS_APNS_TEAM_ID"], let id = env["AGENTCREDS_APNS_KEY_ID"],
                  let path = env["AGENTCREDS_APNS_KEY_PATH"],
                  let pem = try? String(contentsOfFile: path, encoding: .utf8),
                  let key = try? P256.Signing.PrivateKey(pemRepresentation: pem),
                  !team.isEmpty, !id.isEmpty else { return nil }
            return Configuration(teamID: team, keyID: id, key: key)
        }
    }
    private struct Device { let registration: PushRegistration; let expiresAt: Date }
    private var relayNotify: ((CredentialRequest) -> Void)?
    func setRelay(_ notify: @escaping (CredentialRequest) -> Void) { lock.lock(); relayNotify = notify; lock.unlock() }
    private var devices: [UUID: Device] = [:]
    private var statuses: [UUID: String] = [:]
    private let lock = NSLock()
    private let configuration: Configuration?
    private let session: URLSession
    init(configuration: Configuration? = Configuration.load(), session: URLSession = .shared) {
        self.configuration = configuration; self.session = session
    }
    func register(_ registration: PushRegistration, pairing: PairingInvite) throws -> String {
        guard registration.isValid, pairing.expiresAt > Date() else { throw CompanionError.invalid("Invalid push registration") }
        lock.lock(); defer { lock.unlock() }
        if devices[pairing.id]?.registration != registration { statuses[pairing.id] = nil }
        devices[pairing.id] = Device(registration: registration, expiresAt: pairing.expiresAt)
        return configuration == nil ? "Mac push delivery is not configured" : (statuses[pairing.id] ?? "Registered with Mac; delivery not yet verified")
    }
    func revoke(_ id: UUID? = nil) {
        lock.lock(); defer { lock.unlock() }
        if let id { devices[id] = nil; statuses[id] = nil } else { devices.removeAll(); statuses.removeAll() }
    }
    func notify(_ request: CredentialRequest) {
        lock.lock()
        let relay = relayNotify
        let targets = devices.filter { $0.value.expiresAt > Date() }
        lock.unlock()
        if let relay { DispatchQueue.global().async { relay(request) }; return }
        guard let configuration else { return }
        for (id, device) in targets {
            Task { [self] in
                // Retry transient failures only, with the same collapse ID and expiry.
                for attempt in 0..<3 {
                    guard active(id, device.registration), request.expiresAt > Date() else { return }
                    do {
                        let message = try Self.makeRequest(request: request, pairingID: id, registration: device.registration, configuration: configuration)
                        let (_, response) = try await session.data(for: message)
                        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                        if code == 200 { status("Apple accepted the last alert", id: id); return }
                        if code == 410 || code == 400 { revoke(id); status("Push registration expired; reconnect iPhone", id: id); return }
                        guard code == 429 || code >= 500 else { status("Apple rejected delivery; check Mac push configuration", id: id); return }
                    } catch { /* Never log tokens, payloads, keys or APNs response bodies. */ }
                    if attempt < 2 { try? await Task.sleep(for: .seconds(attempt == 0 ? 2 : 8)) }
                }
                status("Last push delivery failed; reconnect to check requests", id: id)
            }
        }
    }
    private func active(_ id: UUID, _ registration: PushRegistration) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return devices[id]?.registration == registration && (devices[id]?.expiresAt ?? .distantPast) > Date()
    }
    private func status(_ text: String, id: UUID) { lock.lock(); statuses[id] = text; lock.unlock() }
    static func makeRequest(request: CredentialRequest, pairingID: UUID, registration: PushRegistration, configuration: Configuration) throws -> URLRequest {
        guard registration.isValid else { throw CompanionError.invalid("Invalid push registration") }
        func base64(_ data: Data) -> String { data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
        let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "kid": configuration.keyID])
        let claims = try JSONSerialization.data(withJSONObject: ["iss": configuration.teamID, "iat": Int(Date().timeIntervalSince1970)])
        let signingInput = base64(header) + "." + base64(claims)
        let signature = try configuration.key.signature(for: Data(signingInput.utf8)).rawRepresentation
        let host = registration.environment == "sandbox" ? "api.sandbox.push.apple.com" : "api.push.apple.com"
        var result = URLRequest(url: URL(string: "https://\(host)/3/device/\(registration.token)")!)
        result.httpMethod = "POST"; result.timeoutInterval = 15
        result.setValue("bearer \(signingInput).\(base64(signature))", forHTTPHeaderField: "authorization")
        result.setValue("ai.ardabot.agentcreds.companion", forHTTPHeaderField: "apns-topic")
        result.setValue("alert", forHTTPHeaderField: "apns-push-type")
        result.setValue("10", forHTTPHeaderField: "apns-priority")
        result.setValue(String(Int(request.expiresAt.timeIntervalSince1970)), forHTTPHeaderField: "apns-expiration")
        result.setValue(request.id.uuidString, forHTTPHeaderField: "apns-collapse-id")
        result.setValue("application/json", forHTTPHeaderField: "content-type")
        result.httpBody = try JSONSerialization.data(withJSONObject: ApprovalNotification.payload(requestID: request.id, pairingID: pairingID))
        return result
    }
}
