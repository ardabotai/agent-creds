import Foundation
import CompanionProtocol

/// Outbound-only connection. No router ports or public daemon listener required.
/// A disconnect discards pending challenges; commands are never replayed on reconnect.
final class CompanionRelay {
    let address: RelayAddress
    private let lock = NSLock()
    private var loop: Task<Void, Never>?
    private var socket: URLSessionWebSocketTask?
    private var ready = false
    private let process: (UUID, Data, Data) throws -> Data
    init(address: RelayAddress, process: @escaping (UUID, Data, Data) throws -> Data) { self.address = address; self.process = process }
    var isConnected: Bool { lock.lock(); defer { lock.unlock() }; return ready }
    func control(_ suffix: String, method: String, object: [String: Any]? = nil) throws -> [String: Any] {
        let body = try object.map { try JSONSerialization.data(withJSONObject: $0) }
        let request = try RelayTransport.request(address, suffix: suffix, method: method, body: body)
        let session = RelayTransport.session(); defer { session.invalidateAndCancel() }
        let result = HTTPResult(), completed = DispatchSemaphore(value: 0)
        let task = session.dataTask(with: request) { data, response, error in
            result.data = data; result.status = (response as? HTTPURLResponse)?.statusCode ?? 0; result.failed = error != nil; completed.signal()
        }
        task.resume()
        guard completed.wait(timeout: .now() + 22) == .success, !result.failed, (200...299).contains(result.status) else {
            task.cancel(); throw CompanionError.invalid("Relay connection failed. Check your connection and try again.")
        }
        return (try? JSONSerialization.jsonObject(with: result.data ?? Data()) as? [String: Any]) ?? [:]
    }
    func register(_ invite: PairingInvite) throws {
        guard let device = invite.relay else { return }
        _ = try control("/devices/\(invite.id.uuidString.lowercased())", method: "PUT", object: ["token": device.token, "expiresAt": min(invite.expiresAt, invite.enrollmentExpiresAt ?? invite.expiresAt).timeIntervalSince1970 * 1000])
    }
    func start() {
        lock.lock(); defer { lock.unlock() }
        guard loop == nil else { return }
        loop = Task { [weak self] in
            var delay = 1
            while !Task.isCancelled {
                guard let self else { return }
                do { try await self.connect(); delay = 1 } catch { /* Reconnect silently without logging credentials or frames. */ }
                self.setConnection(nil, ready: false)
                if Task.isCancelled { return }
                try? await Task.sleep(for: .seconds(delay)); delay = min(delay * 2, 30)
            }
        }
    }
    func stop() { lock.lock(); loop?.cancel(); loop = nil; socket?.cancel(with: .goingAway, reason: nil); socket = nil; ready = false; lock.unlock() }
    private func setConnection(_ socket: URLSessionWebSocketTask?, ready: Bool) { lock.lock(); self.socket = socket; self.ready = ready; lock.unlock() }
    private func connect() async throws {
        let session = RelayTransport.session(); defer { session.invalidateAndCancel() }
        let socket = session.webSocketTask(with: try RelayTransport.request(address, suffix: "/host", websocket: true))
        socket.maximumMessageSize = 1_400_000; setConnection(socket, ready: false); socket.resume()
        try await ping(socket); setConnection(socket, ready: true)
        let heartbeat = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(25))
                guard !Task.isCancelled else { return }
                do { try await self.ping(socket) } catch { socket.cancel(with: .goingAway, reason: nil); return }
            }
        }
        defer { heartbeat.cancel(); socket.cancel(with: .goingAway, reason: nil) }
        var challenges: [String: (UUID, Data, Date)] = [:]
        while !Task.isCancelled {
            let frame = try await RelayTransport.receive(over: socket)
            challenges = challenges.filter { $0.value.2 > Date() }
            guard let channel = frame.channel, UUID(uuidString: channel) != nil, let text = frame.pairingID, let pairingID = UUID(uuidString: text) else { throw CompanionError.invalid("Invalid relay routing") }
            if frame.type == "open" {
                guard challenges.count < 16 else { continue }
                let challenge = CompanionCrypto.randomKey()
                challenges[channel] = (pairingID, challenge, Date().addingTimeInterval(180))
                try await RelayTransport.send(RelayFrame(type: "challenge", channel: channel, payload: challenge.base64EncodedString()), over: socket)
            } else if frame.type == "request" {
                guard let pending = challenges.removeValue(forKey: channel), pending.0 == pairingID, let payload = frame.payload, let wire = Data(base64Encoded: payload), wire.count <= CompanionCrypto.limit else { throw CompanionError.invalid("Invalid request") }
                // Do not block other devices while a one-time enrollment prompts.
                Task.detached { [process] in
                    do {
                        let response = try process(pairingID, pending.1, wire)
                        try await RelayTransport.send(RelayFrame(type: "response", channel: channel, payload: response.base64EncodedString()), over: socket)
                    } catch { try? await RelayTransport.send(RelayFrame(type: "error", channel: channel), over: socket) }
                }
            }
        }
    }
    private func ping(_ socket: URLSessionWebSocketTask) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            socket.sendPing { error in if let error { continuation.resume(throwing: error) } else { continuation.resume() } }
        }
    }
}
private final class HTTPResult { var data: Data?; var status = 0; var failed = false }
