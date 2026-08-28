import Foundation
import AgentCredsCore

/// The egress proxy: a local rewriting gateway on 127.0.0.1:9977.
///
/// Agents send `METHOD /p/<host>/<path>` with `Authorization: Bearer acred_*`.
/// The daemon resolves the handle (expiry + host allowlist), substitutes
/// `{{acred:*}}` placeholders in the path, headers, and body, attaches the real
/// credential (bearer grants) at egress, forwards over HTTPS, then scrubs every
/// injected secret from the response before the agent sees it. For signup
/// grants, generated passwords are saved to the vault on a successful response.
///
/// HTTP/1.1 subset: Content-Length bodies only (no chunked upload), one request
/// per connection. Fine for API calls, which is what agents make.
final class ProxyServer {
    private let vault: VaultStore
    private let listenFD: Int32
    private let acceptQueue = DispatchQueue(label: "agentcreds.proxy.accept")
    private var acceptSource: DispatchSourceRead?

    private static let hopHeaders: Set<String> = [
        "host", "connection", "content-length", "authorization", "x-acred-token",
        "accept-encoding", "proxy-connection", "transfer-encoding",
    ]

    init(vault: VaultStore) throws {
        self.vault = vault
        self.listenFD = try Self.listenLoopback(port: UInt16(EgressProxy.port))
    }

    private static func listenLoopback(port: UInt16) throws -> Int32 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw UnixSocketError.syscall("socket", errno) }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bound = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else {
            close(fd)
            throw UnixSocketError.syscall("bind", errno)
        }
        guard listen(fd, 16) == 0 else {
            close(fd)
            throw UnixSocketError.syscall("listen", errno)
        }
        return fd
    }

    func start() {
        let source = DispatchSource.makeReadSource(fileDescriptor: listenFD, queue: acceptQueue)
        source.setEventHandler { [weak self] in
            guard let self else { return }
            let fd = accept(self.listenFD, nil, nil)
            guard fd >= 0 else { return }
            Thread.detachNewThread { self.serve(fd: fd) }
        }
        source.resume()
        acceptSource = source
    }

    // MARK: - Per-connection handling

    private struct Request {
        let method: String
        let target: String
        let headers: [(name: String, value: String)]
        let body: Data

        func header(_ name: String) -> String? {
            headers.first { $0.name.lowercased() == name.lowercased() }?.value
        }
    }

    private func serve(fd: Int32) {
        let fh = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        guard let request = readRequest(fh) else {
            write(fh, status: 400, json: ["error": "malformed request"])
            return
        }
        let (status, contentType, body) = process(request)
        write(fh, status: status, contentType: contentType, body: body)
    }

    private func readRequest(_ fh: FileHandle) -> Request? {
        let separator = Data("\r\n\r\n".utf8)
        var buffer = Data()
        var headerEnd: Range<Data.Index>?
        while headerEnd == nil {
            if buffer.count > 1 << 20 { return nil }
            let chunk = fh.availableData
            if chunk.isEmpty { return nil }
            buffer.append(chunk)
            headerEnd = buffer.range(of: separator)
        }
        guard let headerEnd,
              let head = String(data: buffer.subdata(in: buffer.startIndex..<headerEnd.lowerBound),
                                encoding: .utf8) else { return nil }
        var lines = head.components(separatedBy: "\r\n")
        let requestLine = lines.removeFirst().split(separator: " ")
        guard requestLine.count >= 2 else { return nil }
        let headers: [(String, String)] = lines.compactMap { line in
            guard let colon = line.firstIndex(of: ":") else { return nil }
            let name = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            return (name, value)
        }
        let contentLength = headers.first { $0.0.lowercased() == "content-length" }
            .flatMap { Int($0.1) } ?? 0
        var body = buffer.subdata(in: headerEnd.upperBound..<buffer.endIndex)
        while body.count < contentLength {
            let chunk = fh.availableData
            if chunk.isEmpty { break }
            body.append(chunk)
        }
        return Request(method: String(requestLine[0]), target: String(requestLine[1]),
                       headers: headers, body: body)
    }

    // MARK: - The interesting part

    private func process(_ request: Request) -> (Int, String, Data) {
        guard request.target.hasPrefix("/p/") else {
            return jsonError(404, "unknown path — use /p/<host>/<path>")
        }
        let after = request.target.dropFirst(3)
        let host: String
        var path: String
        if let slash = after.firstIndex(of: "/") {
            host = String(after[..<slash])
            path = String(after[slash...])
        } else {
            host = String(after)
            path = "/"
        }
        guard !host.isEmpty else { return jsonError(400, "missing host in /p/<host>/<path>") }

        // Resolve the handle.
        var token: String?
        if let auth = request.header("Authorization"), auth.lowercased().hasPrefix("bearer acred_") {
            token = String(auth.dropFirst("Bearer ".count))
        } else if let headerToken = request.header("X-Acred-Token") {
            token = headerToken
        }
        guard let token, let grant = ProxyRegistry.shared.grant(token: token, host: host) else {
            return jsonError(401, "missing, expired, or host-mismatched credential handle")
        }

        var signupGrant: SignupGrant?
        if case .signup(let g) = grant { signupGrant = g }
        let context = PlaceholderEngine.Context(identity: Identity.load(), signup: signupGrant)
        var injectedSecrets: [String] = []

        // Substitute placeholders in path (percent-encoded), headers, and body.
        var outBody = request.body
        do {
            let (newPath, pathSecrets) = try PlaceholderEngine.substitute(path, context: context) {
                $0.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0
            }
            path = newPath
            injectedSecrets += pathSecrets

            if !request.body.isEmpty, let bodyString = String(data: request.body, encoding: .utf8),
               PlaceholderEngine.containsPlaceholders(bodyString) {
                let (newBody, bodySecrets) = try PlaceholderEngine.substitute(bodyString, context: context)
                outBody = Data(newBody.utf8)
                injectedSecrets += bodySecrets
            }
        } catch {
            return jsonError(400, "\(error)")
        }

        guard let url = URL(string: "https://\(host)\(path)") else {
            return jsonError(400, "could not form URL for https://\(host)\(path)")
        }

        var outbound = URLRequest(url: url)
        outbound.httpMethod = request.method
        for (name, value) in request.headers where !Self.hopHeaders.contains(name.lowercased()) {
            let substituted = (try? PlaceholderEngine.substitute(value, context: context))
            if let (newValue, secrets) = substituted {
                outbound.setValue(newValue, forHTTPHeaderField: name)
                injectedSecrets += secrets
            } else {
                outbound.setValue(value, forHTTPHeaderField: name)
            }
        }
        if case .credential(let rootSecret, let injection) = grant {
            let secret = String(data: rootSecret, encoding: .utf8) ?? ""
            let field = injection.headerField(secret: secret)
            outbound.setValue(field.value, forHTTPHeaderField: field.name)
            injectedSecrets.append(secret)
            // Basic auth base64-encodes the secret, so the raw value never
            // appears on the wire — redact the encoded form as well.
            if !field.value.contains(secret) { injectedSecrets.append(field.value) }
        }
        if !outBody.isEmpty { outbound.httpBody = outBody }

        // Follow redirects only within the allowlist: the host check above
        // covers the first hop, and URLSession would otherwise re-send the
        // injected credential to wherever a 302 points.
        let redirectGuard = RedirectGuard(allowedHosts: ProxyRegistry.shared.allowedHosts(token: token))
        let session = URLSession(configuration: .ephemeral, delegate: redirectGuard, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        // Forward synchronously (we're on a dedicated thread).
        let semaphore = DispatchSemaphore(value: 0)
        var responseData = Data()
        var responseStatus = 502
        var responseContentType = "application/json"
        var transportError: Error?
        session.dataTask(with: outbound) { data, response, error in
            if let data { responseData = data }
            if let http = response as? HTTPURLResponse {
                responseStatus = http.statusCode
                if let ct = http.value(forHTTPHeaderField: "Content-Type") { responseContentType = ct }
            }
            transportError = error
            semaphore.signal()
        }.resume()
        semaphore.wait()

        if let transportError {
            return jsonError(502, "upstream request failed: \(transportError.localizedDescription)")
        }

        // Success: persist generated signup passwords before anything else.
        // The account now exists upstream with this password, and it is scrubbed
        // from the response below, so the vault is about to hold its only copy:
        // mark a tag saved ONLY after the save succeeds, so a failure retries on
        // the next request in this grant instead of losing the password.
        if let signupGrant, (200..<400).contains(responseStatus) {
            for (tag, password) in signupGrant.generatedValues() where !signupGrant.isSaved(tag: tag) {
                let name = tag == "default"
                    ? "\(signupGrant.service)/password"
                    : "\(signupGrant.service)/password.\(tag)"
                do {
                    try vault.save(name: name, kind: .opaque, value: Data(password.utf8),
                                   policy: SecretPolicy(allowedHosts: [host]))
                    _ = signupGrant.markSaved(tag: tag)
                    NSLog("agent-creds: saved generated password as “\(name)”")
                } catch {
                    NSLog("agent-creds: FAILED to save generated password “\(name)”: \(error) — will retry on the next request in this grant")
                }
            }
        }

        // Scrub every injected secret from the response before the agent sees
        // it. Byte-level: a body that is not valid UTF-8 (binary, compressed,
        // Latin-1) must not slip past the scrubber just because it will not
        // decode into a String.
        for secret in injectedSecrets where !secret.isEmpty {
            responseData = responseData.replacingOccurrences(of: Data(secret.utf8),
                                                             with: Data("{{acred:redacted}}".utf8))
        }

        return (responseStatus, responseContentType, responseData)
    }

    // MARK: - Response plumbing

    private func jsonError(_ status: Int, _ message: String) -> (Int, String, Data) {
        let body = (try? JSONSerialization.data(withJSONObject: ["error": message])) ?? Data()
        return (status, "application/json", body)
    }

    private func write(_ fh: FileHandle, status: Int, json: [String: String]) {
        let body = (try? JSONSerialization.data(withJSONObject: json)) ?? Data()
        write(fh, status: status, contentType: "application/json", body: body)
    }

    private func write(_ fh: FileHandle, status: Int, contentType: String, body: Data) {
        let head = "HTTP/1.1 \(status) \(reason(for: status))\r\n"
            + "Content-Type: \(contentType)\r\n"
            + "Content-Length: \(body.count)\r\n"
            + "Connection: close\r\n\r\n"
        fh.write(Data(head.utf8))
        fh.write(body)
        try? fh.close()
    }

    /// Re-checks every redirect hop against the grant's allowlist. Returning nil
    /// stops the chain, so the injected credential is never re-sent off-list.
    private final class RedirectGuard: NSObject, URLSessionTaskDelegate {
        private let allowedHosts: [String]

        init(allowedHosts: [String]) {
            self.allowedHosts = allowedHosts
            super.init()
        }

        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) {
            guard let host = request.url?.host,
                  HostPolicy.matches(host: host, allowedHosts: allowedHosts) else {
                NSLog("agent-creds: blocked redirect to \(request.url?.absoluteString ?? "?") — outside the grant's allowlist")
                completionHandler(nil)
                return
            }
            completionHandler(request)
        }
    }

    private func reason(for status: Int) -> String {
        switch status {
        case 200: return "OK"
        case 201: return "Created"
        case 204: return "No Content"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 502: return "Bad Gateway"
        default: return "Status"
        }
    }
}

private extension Data {
    /// Byte-level replace, so secrets are redacted from bodies that are not
    /// valid UTF-8 and therefore cannot be scrubbed as Strings.
    func replacingOccurrences(of target: Data, with replacement: Data) -> Data {
        guard !target.isEmpty, count >= target.count else { return self }
        var result = Data()
        result.reserveCapacity(count)
        var cursor = startIndex
        while let found = range(of: target, options: [], in: cursor..<endIndex) {
            result.append(self[cursor..<found.lowerBound])
            result.append(replacement)
            cursor = found.upperBound
        }
        result.append(self[cursor...])
        return result
    }
}
