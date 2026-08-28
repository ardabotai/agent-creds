import Foundation
import AgentCredsCore

/// Fills a secret into a field of a browser the agent is automating, over the
/// Chrome DevTools Protocol. Works with Playwright, agent-browser, or any
/// Chromium launched with --remote-debugging-port: the daemon connects to the
/// page itself and sets the value browser-side, so the secret never enters the
/// agent's context — and the page URL shown in the approval prompt comes from
/// CDP, not from the agent's claims.
enum BrowserFillError: Error, CustomStringConvertible {
    case cdpUnreachable(String)
    case fillFailed(String)

    var description: String {
        switch self {
        case .cdpUnreachable(let detail):
            return "cannot reach the browser's CDP endpoint: \(detail). Launch the browser with --remote-debugging-port (Playwright: chromium.launch(args: [\"--remote-debugging-port=9222\"]) or connect_over_cdp)."
        case .fillFailed(let detail):
            return "fill failed: \(detail)"
        }
    }
}

struct CDPPage: Decodable {
    let type: String?
    let url: String
    let title: String?
    let webSocketDebuggerUrl: String?
}

enum BrowserFiller {
    static func pages(cdpBase: String) throws -> [CDPPage] {
        guard let url = URL(string: "\(cdpBase)/json/list") else {
            throw BrowserFillError.cdpUnreachable("invalid cdp_url")
        }
        let semaphore = DispatchSemaphore(value: 0)
        var body: Data?
        var failure: Error?
        URLSession.shared.dataTask(with: url) { data, _, error in
            body = data
            failure = error
            semaphore.signal()
        }.resume()
        guard semaphore.wait(timeout: .now() + 5) == .success else {
            throw BrowserFillError.cdpUnreachable("timeout")
        }
        if let failure { throw BrowserFillError.cdpUnreachable(failure.localizedDescription) }
        guard let body, let pages = try? JSONDecoder().decode([CDPPage].self, from: body) else {
            throw BrowserFillError.cdpUnreachable("could not parse /json/list")
        }
        return pages.filter { ($0.type ?? "page") == "page" }
    }

    static func fill(value: String, selector: String, page: CDPPage) throws {
        guard let wsString = page.webSocketDebuggerUrl, let wsURL = URL(string: wsString) else {
            throw BrowserFillError.fillFailed("page exposes no webSocketDebuggerUrl (another client may be attached exclusively)")
        }
        // JSON-encode strings straight into the JS for correct escaping.
        func jsString(_ string: String) throws -> String {
            let encoded = String(data: try JSONEncoder().encode([string]), encoding: .utf8)!
            return String(encoded.dropFirst().dropLast())
        }
        let js = """
        (() => {
          const el = document.querySelector(\(try jsString(selector)));
          if (!el) return "no element matches selector";
          const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
          const desc = Object.getOwnPropertyDescriptor(proto, "value");
          if (desc && desc.set) { desc.set.call(el, \(try jsString(value))); } else { el.value = \(try jsString(value)); }
          el.dispatchEvent(new Event("input", { bubbles: true }));
          el.dispatchEvent(new Event("change", { bubbles: true }));
          return "ok";
        })()
        """
        let payload: [String: Any] = [
            "id": 1,
            "method": "Runtime.evaluate",
            "params": ["expression": js, "returnByValue": true],
        ]
        let task = URLSession.shared.webSocketTask(with: wsURL)
        task.resume()
        defer { task.cancel(with: .normalClosure, reason: nil) }

        let payloadText = String(data: try JSONSerialization.data(withJSONObject: payload), encoding: .utf8)!
        let sendSemaphore = DispatchSemaphore(value: 0)
        var sendError: Error?
        task.send(.string(payloadText)) { error in
            sendError = error
            sendSemaphore.signal()
        }
        guard sendSemaphore.wait(timeout: .now() + 5) == .success, sendError == nil else {
            throw BrowserFillError.fillFailed("websocket send failed")
        }

        // Events may interleave; read until the reply to id 1 or timeout.
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            let receiveSemaphore = DispatchSemaphore(value: 0)
            var message: URLSessionWebSocketTask.Message?
            task.receive { result in
                if case .success(let received) = result { message = received }
                receiveSemaphore.signal()
            }
            guard receiveSemaphore.wait(timeout: .now() + 5) == .success, let message else { break }
            guard case .string(let text) = message,
                  let object = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any],
                  object["id"] as? Int == 1 else { continue }
            if let error = object["error"] as? [String: Any] {
                throw BrowserFillError.fillFailed("CDP error: \(error["message"] as? String ?? "unknown")")
            }
            let outcome = ((object["result"] as? [String: Any])?["result"] as? [String: Any])?["value"] as? String
            guard let outcome else { throw BrowserFillError.fillFailed("unexpected CDP reply") }
            guard outcome == "ok" else { throw BrowserFillError.fillFailed(outcome) }
            return
        }
        throw BrowserFillError.fillFailed("no reply from page (timeout)")
    }
}
