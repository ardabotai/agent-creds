import Foundation

/// Append-only record of every request, approval, denial, and release.
///
/// Written as JSON Lines so an append is a single atomic-enough write and the
/// file stays readable with `tail`. Created 0600 before any bytes land, like
/// every other file this tool owns.
///
/// TODO Phase 2: mirror events into CloudKit so the iPhone shows the same log.
public final class AuditLog {
    public static let shared = AuditLog()

    private let url: URL
    private let lock = NSLock()

    public init(url: URL = IPCPaths.directory.appendingPathComponent("audit.jsonl")) {
        self.url = url
    }

    public func record(client: String, action: String, secretName: String? = nil, decision: String? = nil) {
        record(AuditEvent(client: client, action: action, secretName: secretName, decision: decision))
    }

    public func record(_ event: AuditEvent) {
        lock.lock(); defer { lock.unlock() }
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.sortedKeys]
            var line = try encoder.encode(event)
            line.append(UInt8(ascii: "\n"))

            let fileManager = FileManager.default
            if !fileManager.fileExists(atPath: url.path) {
                try fileManager.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
                guard fileManager.createFile(atPath: url.path, contents: nil,
                                             attributes: [.posixPermissions: 0o600]) else {
                    throw VaultError.io("could not create \(url.path)")
                }
            }
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: line)
        } catch {
            // An audit failure must never block or crash a release in progress.
            NSLog("agent-creds: could not write audit event: \(error)")
        }
    }

    /// Most recent events last, as stored. Unparsable lines are skipped.
    public func recent(limit: Int = 50) throws -> [AuditEvent] {
        lock.lock(); defer { lock.unlock() }
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let events = try String(contentsOf: url, encoding: .utf8)
            .split(separator: "\n")
            .compactMap { try? decoder.decode(AuditEvent.self, from: Data($0.utf8)) }
        return Array(events.suffix(limit))
    }
}
