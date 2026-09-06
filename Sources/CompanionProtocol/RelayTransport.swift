import Foundation

public struct RelayAddress: Codable, Equatable {
    public static let productionURL = "https://agentcreds-relay.agentcreds-relay.workers.dev"
    public var url: String
    public var roomID: UUID
    /// Routing credential only. Never used as the end-to-end encryption key.
    public var token: String
    public init(url: String, roomID: UUID, token: String) { self.url = url; self.roomID = roomID; self.token = token }
    public var isValid: Bool {
        guard let parts = URLComponents(string: url), parts.host != nil,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/",
              parts.scheme == "https" || (parts.scheme == "http" && parts.host == "127.0.0.1"),
              token.count == 64, token.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return false }
        return true
    }
    public func endpoint(_ suffix: String = "", websocket: Bool = false) throws -> URL {
        guard isValid else { throw CompanionError.invalid("Invalid relay address") }
        var parts = URLComponents(string: url)!
        if websocket { parts.scheme = parts.scheme == "https" ? "wss" : "ws" }
        parts.path = "/v1/rooms/\(roomID.uuidString.lowercased())" + suffix
        return parts.url!
    }
}

public struct RelayFrame: Codable {
    public var type: String
    public var channel: String?
    public var pairingID: String?
    public var payload: String?
    public var error: String?
    public init(type: String, channel: String? = nil, pairingID: String? = nil, payload: String? = nil) {
        self.type = type; self.channel = channel; self.pairingID = pairingID; self.payload = payload
    }
}

private final class NoRelayRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
public enum RelayTransport {
    private static let delegate = NoRelayRedirect()
    public static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20
        config.timeoutIntervalForResource = 190
        return URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }
    public static func request(_ relay: RelayAddress, suffix: String, method: String = "GET", body: Data? = nil, websocket: Bool = false) throws -> URLRequest {
        var request = URLRequest(url: try relay.endpoint(suffix, websocket: websocket))
        request.httpMethod = method; request.httpBody = body
        request.setValue("Bearer \(relay.token)", forHTTPHeaderField: "Authorization")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        return request
    }
    public static func send(_ frame: RelayFrame, over socket: URLSessionWebSocketTask) async throws {
        let data = try JSONEncoder().encode(frame)
        guard data.count <= 1_400_000 else { throw CompanionError.invalid("Relay message too large") }
        try await socket.send(.data(data))
    }
    public static func receive(over socket: URLSessionWebSocketTask) async throws -> RelayFrame {
        let message = try await socket.receive()
        let data: Data
        switch message { case .data(let bytes): data = bytes; case .string(let text): data = Data(text.utf8); @unknown default: throw CompanionError.invalid("Invalid relay frame") }
        guard data.count <= 1_400_000 else { throw CompanionError.invalid("Relay message too large") }
        let frame = try JSONDecoder().decode(RelayFrame.self, from: data)
        if frame.type == "error" { throw CompanionError.invalid("Mac unavailable or pairing invalid. Reconnect your Mac and try again.") }
        return frame
    }
    public static func exchange(_ command: CompanionCommand, pairing: PairingInvite, authorize: ((CompanionCommand, Data) async throws -> CompanionCommand)?) async throws -> CompanionReply {
        guard let relay = pairing.relay else { throw CompanionError.invalid("Missing relay") }
        let session = session()
        let socket = session.webSocketTask(with: try request(relay, suffix: "/phone/\(pairing.id.uuidString.lowercased())", websocket: true))
        socket.maximumMessageSize = 1_400_000; socket.resume()
        let deadline = Task { try? await Task.sleep(for: .seconds(180)); if !Task.isCancelled { socket.cancel(with: .goingAway, reason: nil) } }
        defer { deadline.cancel(); socket.cancel(with: .normalClosure, reason: nil); session.invalidateAndCancel() }
        do {
            let frame = try await receive(over: socket)
            guard frame.type == "challenge", let payload = frame.payload, let challenge = Data(base64Encoded: payload), challenge.count == 32 else { throw CompanionError.invalid("Invalid Mac challenge") }
            let command = try await authorize?(command, challenge) ?? command
            let encrypted = try CompanionCrypto.seal(command, key: pairing.key, challenge: challenge, direction: "request")
            let wire = try JSONEncoder().encode(CompanionEnvelope(pairingID: pairing.id, ciphertext: encrypted))
            try await send(RelayFrame(type: "request", payload: wire.base64EncodedString()), over: socket)
            let response = try await receive(over: socket)
            guard response.type == "response", let payload = response.payload, let ciphertext = Data(base64Encoded: payload) else { throw CompanionError.invalid("Invalid Mac response") }
            let reply = try CompanionCrypto.open(CompanionReply.self, data: ciphertext, key: pairing.key, challenge: challenge, direction: "response")
            guard reply.id == command.id else { throw CompanionError.invalid("Response did not match request") }
            if let error = reply.error { throw CompanionError.invalid(error) }
            return reply
        } catch let error as CompanionError { throw error }
        catch { throw CompanionError.invalid("Could not reach your Mac through the relay. Keep agent-creds running on the Mac and check your connection.") }
    }
}
