import Foundation
import Network

public enum CompanionNetwork {
    public static func send(_ data: Data, over connection: NWConnection) async throws {
        guard data.count <= CompanionCrypto.limit else { throw CompanionError.invalid("Message too large") }
        var size = UInt32(data.count).bigEndian
        let frame = withUnsafeBytes(of: &size) { Data($0) } + data
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: frame, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }
    public static func receive(over connection: NWConnection) async throws -> Data {
        let header = try await read(count: 4, over: connection)
        let count = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count > 0, count <= CompanionCrypto.limit else { throw CompanionError.invalid("Invalid frame") }
        return try await read(count: Int(count), over: connection)
    }
    private static func read(count: Int, over connection: NWConnection) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                if let data, data.count == count { continuation.resume(returning: data) }
                else { continuation.resume(throwing: error ?? CompanionError.invalid("The Mac disconnected. Try again.")) }
            }
        }
    }
    public static func exchange(_ command: CompanionCommand, pairing: PairingInvite, authorize: ((CompanionCommand, Data) async throws -> CompanionCommand)? = nil) async throws -> CompanionReply {
        guard pairing.expiresAt > Date() else { throw CompanionError.invalid("Pairing expired. Pair again from your Mac.") }
        if pairing.relay != nil { return try await RelayTransport.exchange(command, pairing: pairing, authorize: authorize) }
        let connection = NWConnection(host: NWEndpoint.Host(pairing.host), port: NWEndpoint.Port(rawValue: pairing.port)!, using: .tcp)
        let deadline = DispatchWorkItem { connection.cancel() }
        DispatchQueue.global().asyncAfter(deadline: .now() + 180, execute: deadline)
        connection.start(queue: DispatchQueue(label: "agentcreds.companion.client"))
        defer { deadline.cancel(); connection.cancel() }
        let challenge = try await receive(over: connection)
        let command = try await authorize?(command, challenge) ?? command
        let sealed = try CompanionCrypto.seal(command, key: pairing.key, challenge: challenge, direction: "request")
        let envelope = CompanionEnvelope(pairingID: pairing.id, ciphertext: sealed)
        try await send(JSONEncoder().encode(envelope), over: connection)
        let response = try await receive(over: connection)
        let reply = try CompanionCrypto.open(CompanionReply.self, data: response, key: pairing.key, challenge: challenge, direction: "response")
        guard reply.id == command.id else { throw CompanionError.invalid("Response did not match this request") }
        if let error = reply.error { throw CompanionError.invalid(error) }
        return reply
    }
}
