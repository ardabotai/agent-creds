import Foundation
import Darwin

public enum IPCPaths {
    public static var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/agent-creds")
    }
    public static var socketPath: String { directory.appendingPathComponent("agent.sock").path }

    /// Creates the state directory 0700, and tightens it if an earlier version
    /// (or a stray umask) left it group/world-readable.
    @discardableResult
    public static func ensureDirectory() -> URL {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        return directory
    }
    public static var vaultURL: URL { directory.appendingPathComponent("vault.json") }
}

/// First line a shim sends after connecting, before raw MCP traffic begins.
/// TODO: pairing — unknown client names should trigger an approval prompt and
/// be issued a per-agent token; known clients must present theirs.
public struct ClientHello: Codable {
    public var agentcreds: String
    public var client: String
    public var token: String?

    public init(client: String, token: String? = nil) {
        self.agentcreds = "hello"
        self.client = client
        self.token = token
    }
}

public enum UnixSocketError: Error {
    case pathTooLong
    case syscall(String, Int32)
}

public enum UnixSocket {
    private static func withSockaddr(_ path: String,
                                     _ body: (UnsafePointer<sockaddr>, socklen_t) -> Int32) throws -> Int32 {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard bytes.count < capacity else { throw UnixSocketError.pathTooLong }
        withUnsafeMutableBytes(of: &addr.sun_path) { dest in
            for (i, b) in bytes.enumerated() { dest[i] = b }
            dest[bytes.count] = 0
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        return withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { body($0, len) }
        }
    }

    public static func listen(at path: String) throws -> Int32 {
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw UnixSocketError.syscall("socket", errno) }
        let bound = try withSockaddr(path) { sa, len in Darwin.bind(fd, sa, len) }
        guard bound == 0 else {
            close(fd)
            throw UnixSocketError.syscall("bind", errno)
        }
        chmod(path, 0o600)
        guard Darwin.listen(fd, 16) == 0 else {
            close(fd)
            throw UnixSocketError.syscall("listen", errno)
        }
        return fd
    }

    public static func connect(to path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw UnixSocketError.syscall("socket", errno) }
        let connected = try withSockaddr(path) { sa, len in Darwin.connect(fd, sa, len) }
        guard connected == 0 else {
            close(fd)
            throw UnixSocketError.syscall("connect", errno)
        }
        return fd
    }
}
