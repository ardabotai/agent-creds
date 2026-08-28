import Foundation

public enum HostPolicy {
    /// An empty allowlist DENIES every host: a secret with no declared hosts has
    /// no egress path at all. Anything else would make the common case (a secret
    /// saved without hosts) usable against an attacker-chosen destination.
    public static func matches(host: String, allowedHosts: [String]) -> Bool {
        guard !allowedHosts.isEmpty else { return false }
        let host = host.lowercased()
        return allowedHosts.contains { allowed in
            let allowed = allowed.lowercased()
            return host == allowed || host.hasSuffix("." + allowed)
        }
    }

    /// True for CDP endpoints that are genuinely on this machine. Prefix checks
    /// are not enough: "http://127.0.0.1.evil.com" starts with the loopback
    /// literal but resolves to an attacker's host.
    public static func isLoopbackEndpoint(_ urlString: String) -> Bool {
        guard let url = URL(string: urlString),
              let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = url.host?.lowercased() else { return false }
        return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
    }
}

public enum SecureFile {
    /// Writes `data` so it is never readable by other users, not even briefly.
    /// `Data.write(options: .atomic)` creates the file with umask-derived
    /// permissions (usually 0644) and can only be chmod'ed afterwards, leaving
    /// a window where the vault or the master key is world-readable. Here the
    /// destination permissions exist before any bytes are written.
    public static func write(_ data: Data, to url: URL) throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        // Tighten even when the directory already existed with looser bits.
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)

        let temporary = directory.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        guard FileManager.default.createFile(atPath: temporary.path, contents: nil,
                                             attributes: [.posixPermissions: 0o600]) else {
            throw VaultError.io("could not create \(temporary.path)")
        }
        do {
            // Non-atomic on purpose: writing into the file we just created 0600
            // keeps those permissions, where .atomic would swap in a fresh one.
            try data.write(to: temporary)
            guard rename(temporary.path, url.path) == 0 else {
                throw VaultError.io("could not replace \(url.path) (errno \(errno))")
            }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }
}
