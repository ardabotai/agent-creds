import Foundation
import AgentCredsCore

/// Accepts shim connections on the unix socket. Each connection speaks one
/// ClientHello line, then newline-delimited MCP JSON-RPC.
final class SocketServer {
    private let vault: VaultStore
    private let listenFD: Int32
    private let acceptQueue = DispatchQueue(label: "agentcreds.accept")
    private var acceptSource: DispatchSourceRead?
    private var connections: [ObjectIdentifier: Connection] = [:]
    private let lock = NSLock()

    init(vault: VaultStore) throws {
        self.vault = vault
        self.listenFD = try UnixSocket.listen(at: IPCPaths.socketPath)
    }

    func start() {
        let source = DispatchSource.makeReadSource(fileDescriptor: listenFD, queue: acceptQueue)
        source.setEventHandler { [weak self] in self?.acceptOne() }
        source.resume()
        acceptSource = source
    }

    private func acceptOne() {
        let fd = accept(listenFD, nil, nil)
        guard fd >= 0 else { return }
        let connection = Connection(fd: fd, handler: MCPHandler(vault: vault))
        lock.lock()
        connections[ObjectIdentifier(connection)] = connection
        lock.unlock()
        connection.onClose = { [weak self] conn in
            guard let self else { return }
            self.lock.lock()
            self.connections[ObjectIdentifier(conn)] = nil
            self.lock.unlock()
        }
        connection.start()
    }
}

final class Connection {
    private let fileHandle: FileHandle
    private let handler: MCPHandler
    private var hello: ClientHello?
    var onClose: ((Connection) -> Void)?

    init(fd: Int32, handler: MCPHandler) {
        self.fileHandle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        self.handler = handler
    }

    func start() {
        Thread.detachNewThread { [self] in
            readLoop()
            onClose?(self)
        }
    }

    private func readLoop() {
        var buffer = Data()
        while true {
            let chunk = fileHandle.availableData
            if chunk.isEmpty { return }
            buffer.append(chunk)
            while let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = buffer.subdata(in: buffer.startIndex..<newline)
                buffer.removeSubrange(buffer.startIndex...newline)
                if !line.isEmpty { handleLine(line) }
            }
        }
    }

    private func handleLine(_ line: Data) {
        if hello == nil {
            if let h = try? JSONDecoder().decode(ClientHello.self, from: line), h.agentcreds == "hello" {
                // TODO pairing: unknown client -> approval prompt + issue token;
                // known client -> verify token. For now, accept and record.
                hello = h
                return
            }
        }
        let client = hello?.client ?? "unknown-agent"
        if let response = handler.handle(message: line, client: client) {
            fileHandle.write(response)
            fileHandle.write(Data([UInt8(ascii: "\n")]))
        }
    }
}
