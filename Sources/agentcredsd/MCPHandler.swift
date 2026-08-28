import Foundation
import AgentCredsCore

/// Minimal MCP server: initialize, tools/list, tools/call over newline-delimited
/// JSON-RPC. The tool descriptions teach agents the protocol: request a secret
/// with an honest purpose, expect to block while the human approves, and never
/// expect a raw value back.
final class MCPHandler {
    private let vault: VaultStore
    private let audit = AuditLog.shared
    private let capture = CaptureController()

    init(vault: VaultStore) {
        self.vault = vault
    }

    func handle(message: Data, client: String) -> Data? {
        guard let object = (try? JSONSerialization.jsonObject(with: message)) as? [String: Any],
              let method = object["method"] as? String else { return nil }
        let id = object["id"]

        switch method {
        case "initialize":
            return reply(id: id, result: [
                "protocolVersion": "2024-11-05",
                "capabilities": ["tools": [String: Any]()],
                "serverInfo": ["name": "agent-creds", "version": "1.0.1"],
            ])
        case "notifications/initialized", "notifications/cancelled":
            return nil
        case "tools/list":
            return reply(id: id, result: ["tools": toolDefinitions])
        case "tools/call":
            return handleToolCall(object, id: id, client: client)
        case "ping":
            return reply(id: id, result: [String: Any]())
        default:
            guard id != nil else { return nil }
            return reply(id: id, errorMessage: "method not supported: \(method)")
        }
    }

    // MARK: - Tools

    private var toolDefinitions: [[String: Any]] {
        [
            [
                "name": "list_secrets",
                "description": "List the names and kinds of stored secrets. Metadata only — values are never returned.",
                "inputSchema": ["type": "object", "properties": [String: Any]()],
            ],
            [
                "name": "save_secret",
                "description": "Save a secret into the user's vault. The user confirms with Touch ID. Once saved, the value can never be read back — only temporary credentials can be minted from it.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "name": ["type": "string", "description": "Secret name, e.g. github/token"],
                        "value": ["type": "string", "description": "The secret value to store"],
                        "kind": ["type": "string", "enum": SecretKind.allCases.map(\.rawValue)],
                        "allowed_hosts": ["type": "array", "items": ["type": "string"],
                                          "description": "REQUIRED. Hosts the egress proxy may send this credential to, e.g. api.github.com. A secret with no hosts has no egress path at all."],
                        "injection": ["type": "string", "enum": ["bearer", "header", "basic"],
                                      "description": "How the credential is attached at egress (default bearer). Use 'header' for API keys in their own header, 'basic' for HTTP Basic."],
                        "header_name": ["type": "string", "description": "With injection=header, e.g. X-Api-Key"],
                        "header_prefix": ["type": "string", "description": "With injection=header, e.g. 'token ' (default empty)"],
                        "username": ["type": "string", "description": "With injection=basic, the username half"],
                    ],
                    "required": ["name", "value", "allowed_hosts"],
                ],
            ],
            [
                "name": "request_secret",
                "description": "Request a TEMPORARY credential minted from a stored secret. Blocks up to 2 minutes while the user approves with Touch ID / Face ID — supply an honest, specific `purpose`, it is shown to the user. Returns a short-lived handle: send API requests to <proxyURL>/p/<host>/<path> with header `Authorization: Bearer <token>`; the real secret is attached at egress and scrubbed from responses. Placeholders {{acred:email}} and {{acred:username}} in the path, headers, or body are swapped for the user's identity before sending. You will never receive the raw secret.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "name": ["type": "string", "description": "Name of the stored secret"],
                        "purpose": ["type": "string", "description": "Why you need it right now — shown verbatim to the user"],
                    ],
                    "required": ["name", "purpose"],
                ],
            ],
            [
                "name": "begin_signup",
                "description": "Start an account-signup flow where a password is GENERATED for the user — you never see it. Blocks while the user approves with Touch ID / Face ID. Returns a signup handle scoped to the host. Then send the site's signup HTTP request to <proxyURL>/p/<host>/<path> with header `Authorization: Bearer <token>`, using placeholders where real values belong: {{acred:password.generate}} for the new-password field, {{acred:password.confirm}} for the confirmation field, {{acred:email}} and {{acred:username}} for the user's identity. They are substituted at egress; on a successful response the generated password is saved into the user's vault automatically, and any echo of it is scrubbed from the response you receive.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "service": ["type": "string", "description": "Service being signed up for, e.g. github.com — used as the vault name prefix"],
                        "host": ["type": "string", "description": "API host the signup request goes to (defaults to service)"],
                        "purpose": ["type": "string", "description": "Why you are creating this account — shown verbatim to the user"],
                    ],
                    "required": ["service", "purpose"],
                ],
            ],
            [
                "name": "capture_secret",
                "description": "Ask the USER to provide a secret that is not in the vault yet. NEVER ask for secret values in chat — use this instead. It opens a secure window in the agent-creds app where the user pastes the value directly (with a shortcut to Apple Passwords for copy-paste); the value is saved to the encrypted vault without ever entering your context. Blocks until the user saves or cancels. On success returns a temporary credential handle, exactly like request_secret.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "name": ["type": "string", "description": "Vault name for the secret, e.g. github.com/password"],
                        "purpose": ["type": "string", "description": "Why you need it — shown verbatim to the user"],
                        "allowed_hosts": ["type": "array", "items": ["type": "string"],
                                          "description": "REQUIRED. Hosts this credential may be used against, e.g. github.com"],
                        "injection": ["type": "string", "enum": ["bearer", "header", "basic"],
                                      "description": "How the credential is attached at egress (default bearer)"],
                        "header_name": ["type": "string", "description": "With injection=header, e.g. X-Api-Key"],
                        "header_prefix": ["type": "string", "description": "With injection=header, e.g. 'token '"],
                        "username": ["type": "string", "description": "With injection=basic, the username half"],
                    ],
                    "required": ["name", "purpose", "allowed_hosts"],
                ],
            ],
            [
                "name": "fill_browser_field",
                "description": "Type a stored secret directly into a field of a browser you are automating — the daemon connects over the Chrome DevTools Protocol and sets the value browser-side, so it never enters your context. Works with Playwright, agent-browser, or any Chromium launched with --remote-debugging-port=9222. Steps: navigate to the login page, make sure the field exists, call this with its CSS selector, then submit the form yourself. Blocks for Touch ID approval showing the page's real URL (read from the browser, not from you). The page's host must be within the secret's allowed hosts.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "name": ["type": "string", "description": "Vault name of the secret to fill"],
                        "selector": ["type": "string", "description": "CSS selector of the target field, e.g. input[type=password]"],
                        "purpose": ["type": "string", "description": "Why — shown verbatim to the user"],
                        "cdp_url": ["type": "string", "description": "CDP endpoint (default http://127.0.0.1:9222)"],
                        "page_url_contains": ["type": "string", "description": "Substring to pick the right page when several are open"],
                    ],
                    "required": ["name", "selector", "purpose"],
                ],
            ],
        ]
    }

    private func handleToolCall(_ object: [String: Any], id: Any?, client: String) -> Data? {
        guard let params = object["params"] as? [String: Any],
              let tool = params["name"] as? String else {
            return reply(id: id, errorMessage: "invalid tools/call params")
        }
        let args = params["arguments"] as? [String: Any] ?? [:]

        do {
            switch tool {
            case "list_secrets":
                let meta = try vault.list().map { ["name": $0.name, "kind": $0.kind.rawValue] }
                let text = String(data: try JSONSerialization.data(withJSONObject: meta), encoding: .utf8) ?? "[]"
                return toolReply(id: id, text: text)

            case "save_secret":
                guard let name = args["name"] as? String, let value = args["value"] as? String else {
                    return reply(id: id, errorMessage: "name and value are required")
                }
                let kind = SecretKind(rawValue: args["kind"] as? String ?? "") ?? .opaque
                let hosts = args["allowed_hosts"] as? [String] ?? []
                guard !hosts.isEmpty else {
                    return toolReply(id: id, text: "allowed_hosts is required — a secret with no hosts has no egress path. Pass the API host(s) this credential is for, e.g. [\"api.github.com\"].")
                }
                guard approve(reason: "\(client) wants to save the secret “\(name)” into your vault",
                              client: client, action: "save_secret", secretName: name) else {
                    return toolReply(id: id, text: "The user denied the save.")
                }
                _ = try vault.save(name: name, kind: kind, value: Data(value.utf8),
                                   policy: SecretPolicy(allowedHosts: hosts, injection: Self.injection(from: args)))
                return toolReply(id: id, text: "Saved “\(name)” (\(kind.rawValue)). The plaintext can never be read back.")

            case "request_secret":
                guard let name = args["name"] as? String else {
                    return reply(id: id, errorMessage: "name is required")
                }
                let purpose = args["purpose"] as? String ?? "(no purpose given)"
                guard let record = try vault.record(named: name) else {
                    return toolReply(id: id, text: "No secret named “\(name)”. Use list_secrets to see what exists, or capture_secret to have the user provide it securely.")
                }
                let ttl = record.policy.defaultTTLSeconds
                let reason = "\(client) requests a \(ttl / 60)-minute credential for “\(name)” — purpose: \(purpose)"
                guard approve(reason: reason, client: client, action: "request_secret", secretName: name) else {
                    return toolReply(id: id, text: "The user denied the request.")
                }
                return toolReply(id: id, text: try mintedCredentialText(record: record, client: client, purpose: purpose))

            case "begin_signup":
                guard let service = args["service"] as? String else {
                    return reply(id: id, errorMessage: "service is required")
                }
                let host = args["host"] as? String ?? service
                let purpose = args["purpose"] as? String ?? "(no purpose given)"
                let identity = Identity.load()
                guard let email = identity.email else {
                    return toolReply(id: id, text: "No identity configured. Ask the user to run: agentcreds identity --email their@email.com (and optionally --username).")
                }
                let reason = "\(client) wants to create an account on \(service) as \(email) — purpose: \(purpose). A password will be generated and saved to your vault; the agent never sees it."
                guard approve(reason: reason, client: client, action: "begin_signup", secretName: service) else {
                    return toolReply(id: id, text: "The user denied the signup.")
                }
                let grant = SignupGrant(service: service)
                let (token, expiresAt) = ProxyRegistry.shared.registerSignup(grant, allowedHosts: [host], ttlSeconds: 900)
                let formatter = ISO8601DateFormatter()
                let payload: [String: Any] = [
                    "token": token,
                    "proxyURL": EgressProxy.baseURL,
                    "host": host,
                    "expiresAt": formatter.string(from: expiresAt),
                    "usage": "Send the signup request to \(EgressProxy.baseURL)/p/\(host)/<path> with header 'Authorization: Bearer \(token)'. Use {{acred:password.generate}}, {{acred:password.confirm}}, {{acred:email}}, {{acred:username}} where those values belong.",
                ]
                let text = String(data: try JSONSerialization.data(withJSONObject: payload), encoding: .utf8) ?? "{}"
                return toolReply(id: id, text: text)

            case "capture_secret":
                guard let name = args["name"] as? String else {
                    return reply(id: id, errorMessage: "name is required")
                }
                let purpose = args["purpose"] as? String ?? "(no purpose given)"
                let hosts = args["allowed_hosts"] as? [String] ?? []
                guard !hosts.isEmpty else {
                    return toolReply(id: id, text: "allowed_hosts is required — a secret with no hosts has no egress path and cannot be filled into any page. Pass the host(s) this credential is for, e.g. [\"github.com\"].")
                }
                if try vault.record(named: name) != nil {
                    return toolReply(id: id, text: "“\(name)” already exists — use request_secret instead.")
                }
                guard let value = capture.capture(client: client, name: name, purpose: purpose) else {
                    return toolReply(id: id, text: "The user cancelled without providing a value.")
                }
                let record = try vault.save(name: name, kind: .opaque, value: Data(value.utf8),
                                            policy: SecretPolicy(allowedHosts: hosts,
                                                                 injection: Self.injection(from: args)))
                audit.record(client: client, action: "capture_secret", secretName: name, decision: "provided")
                return toolReply(id: id, text: try mintedCredentialText(record: record, client: client, purpose: purpose))

            case "fill_browser_field":
                guard let name = args["name"] as? String, let selector = args["selector"] as? String else {
                    return reply(id: id, errorMessage: "name and selector are required")
                }
                let purpose = args["purpose"] as? String ?? "(no purpose given)"
                let cdpBase = args["cdp_url"] as? String ?? "http://127.0.0.1:9222"
                // Resolve the host rather than prefix-matching: "http://127.0.0.1.evil.com"
                // starts with the loopback literal but is an attacker's server.
                guard HostPolicy.isLoopbackEndpoint(cdpBase) else {
                    return toolReply(id: id, text: "cdp_url must be a loopback endpoint (127.0.0.1, localhost, or ::1).")
                }
                guard let record = try vault.record(named: name) else {
                    return toolReply(id: id, text: "No secret named “\(name)”. Use capture_secret to have the user provide it securely.")
                }
                let pages: [CDPPage]
                do {
                    pages = try BrowserFiller.pages(cdpBase: cdpBase)
                } catch {
                    return toolReply(id: id, text: "\(error)")
                }
                let filter = args["page_url_contains"] as? String
                let allowedHosts = record.policy.allowedHosts
                guard !allowedHosts.isEmpty else {
                    return toolReply(id: id, text: "“\(name)” has no allowed hosts, so it cannot be filled into any page. Re-save it with the host(s) it belongs to.")
                }
                let candidate = pages.first { page in
                    guard let host = URL(string: page.url)?.host else { return false }
                    if let filter, !page.url.contains(filter) { return false }
                    return HostPolicy.matches(host: host, allowedHosts: allowedHosts)
                }
                guard let candidate else {
                    return toolReply(id: id, text: "No open browser page matching allowed hosts \(allowedHosts.joined(separator: ", ")). Open pages: \(pages.map(\.url).joined(separator: ", ")). Navigate to the login page first.")
                }
                let reason = "\(client) wants to fill “\(name)” into ‘\(selector)’ on \(candidate.url) — purpose: \(purpose)"
                guard approve(reason: reason, client: client, action: "fill_browser_field", secretName: name) else {
                    return toolReply(id: id, text: "The user denied the fill.")
                }
                // Re-read the page after approval: a CDP target id survives
                // navigation, so the page the user approved could have moved to
                // another origin while the Touch ID prompt was up.
                let live = (try? BrowserFiller.pages(cdpBase: cdpBase))?
                    .first { $0.webSocketDebuggerUrl == candidate.webSocketDebuggerUrl }
                guard let live, live.url == candidate.url,
                      let liveHost = URL(string: live.url)?.host,
                      HostPolicy.matches(host: liveHost, allowedHosts: allowedHosts) else {
                    return toolReply(id: id, text: "Aborted: the page changed after you approved (was \(candidate.url), now \(live?.url ?? "gone")). Nothing was filled.")
                }
                let secretValue = String(data: try vault.revealValue(of: record), encoding: .utf8) ?? ""
                do {
                    try BrowserFiller.fill(value: secretValue, selector: selector, page: live)
                } catch {
                    return toolReply(id: id, text: "\(error)")
                }
                return toolReply(id: id, text: "Filled “\(name)” into ‘\(selector)’ on \(candidate.url). Submit the form to continue — never read the field's value back.")

            default:
                return reply(id: id, errorMessage: "unknown tool: \(tool)")
            }
        } catch {
            return reply(id: id, errorMessage: "\(error)")
        }
    }

    /// Runs the human ceremony and records the outcome either way — a denial is
    /// as much a part of the audit trail as a release.
    private func approve(reason: String, client: String, action: String, secretName: String?) -> Bool {
        let approved = ApprovalCeremony.approve(reason: reason) { detail in
            NSLog("agent-creds: approval unavailable: \(detail)")
        }
        audit.record(client: client, action: action, secretName: secretName,
                     decision: approved ? "approved" : "denied")
        return approved
    }

    /// Reads the optional injection scheme from tool arguments. Defaults to
    /// bearer; `header` covers X-Api-Key and "token "-prefixed credentials.
    private static func injection(from args: [String: Any]) -> CredentialInjection {
        switch args["injection"] as? String {
        case "basic":
            return .basic(username: args["username"] as? String ?? "")
        case "header":
            return .header(name: args["header_name"] as? String ?? "Authorization",
                           prefix: args["header_prefix"] as? String ?? "")
        default:
            return .bearer
        }
    }

    private func minter(for kind: SecretKind) -> CredentialMinter {
        // TODO Phase 3: dispatch to provider-native minters by kind.
        ProxyHandleMinter()
    }

    /// Unwraps the root, mints a temp handle, and serializes it for the agent.
    private func mintedCredentialText(record: SecretRecord, client: String, purpose: String) throws -> String {
        let root = try vault.revealValue(of: record)
        let cred = try minter(for: record.kind).mint(
            record: record, rootSecret: root,
            request: MintRequest(client: client, secretName: record.name, purpose: purpose,
                                 ttlSeconds: record.policy.defaultTTLSeconds))
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return String(data: try encoder.encode(cred), encoding: .utf8) ?? "{}"
    }

    // MARK: - JSON-RPC plumbing

    private func reply(id: Any?, result: [String: Any]) -> Data? {
        encode(["jsonrpc": "2.0", "id": id ?? NSNull(), "result": result])
    }

    private func reply(id: Any?, errorMessage: String) -> Data? {
        encode(["jsonrpc": "2.0", "id": id ?? NSNull(),
                "error": ["code": -32000, "message": errorMessage]])
    }

    private func toolReply(id: Any?, text: String) -> Data? {
        reply(id: id, result: ["content": [["type": "text", "text": text]]])
    }

    private func encode(_ object: [String: Any]) -> Data? {
        try? JSONSerialization.data(withJSONObject: object)
    }
}
