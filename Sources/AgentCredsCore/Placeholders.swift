import Foundation

/// The user's identity for signup flows, configured via `agentcreds identity`.
public struct Identity: Codable {
    public var email: String?
    public var username: String?

    public init(email: String? = nil, username: String? = nil) {
        self.email = email
        self.username = username
    }

    public static var fileURL: URL { IPCPaths.directory.appendingPathComponent("identity.json") }

    public static func load() -> Identity {
        guard let data = try? Data(contentsOf: fileURL),
              let identity = try? JSONDecoder().decode(Identity.self, from: data) else {
            return Identity()
        }
        return identity
    }

    public func save() throws {
        try FileManager.default.createDirectory(at: Identity.fileURL.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: Identity.fileURL, options: .atomic)
    }
}

public enum PasswordGenerator {
    // Symbol set chosen to be JSON- and mostly form-safe (no quotes, backslash,
    // '&', '+', '=' which corrupt common body encodings).
    static let upper = "ABCDEFGHJKMNPQRSTUVWXYZ"
    static let lower = "abcdefghjkmnpqrstuvwxyz"
    static let digits = "23456789"
    static let symbols = "!@#$%^*-_."

    /// Cryptographically random (SystemRandomNumberGenerator is CSPRNG-backed
    /// on Apple platforms), guaranteed to contain all four character classes.
    public static func generate(length: Int = 24) -> String {
        precondition(length >= 8)
        let all = Array(upper + lower + digits + symbols)
        var chars: [Character] = [
            upper.randomElement()!, lower.randomElement()!,
            digits.randomElement()!, symbols.randomElement()!,
        ]
        while chars.count < length { chars.append(all.randomElement()!) }
        return String(chars.shuffled())
    }
}

/// The substitution DSL. Agents embed `{{acred:...}}` placeholders in request
/// paths, headers, or bodies; the egress proxy swaps them for real values
/// before the request leaves the machine. Directives:
///
///   {{acred:password.generate}}        new password (stable within a grant)
///   {{acred:password.generate:tag}}    a second, independently generated one
///   {{acred:password.confirm}}         same value again, for confirm fields
///   {{acred:email}}                    the user's configured email
///   {{acred:username}}                 the user's configured username
public enum PlaceholderEngine {
    public struct Context {
        public let identity: Identity
        /// Present only for signup grants; password.* requires it.
        public let signup: SignupGrant?

        public init(identity: Identity, signup: SignupGrant?) {
            self.identity = identity
            self.signup = signup
        }
    }

    public enum SubstitutionError: Error, CustomStringConvertible {
        case unknownDirective(String)
        case identityMissing(String)
        case signupRequired(String)

        public var description: String {
            switch self {
            case .unknownDirective(let d):
                return "unknown placeholder directive “\(d)”"
            case .identityMissing(let what):
                return "no \(what) configured — ask the user to run: agentcreds identity --\(what) <value>"
            case .signupRequired(let d):
                return "“\(d)” is only available on a signup grant (use begin_signup)"
            }
        }
    }

    private static let pattern = try! NSRegularExpression(
        pattern: "\\{\\{acred:([a-zA-Z.]+)(?::([^}]*))?\\}\\}")

    public static func containsPlaceholders(_ input: String) -> Bool {
        input.contains("{{acred:")
    }

    /// Replaces every placeholder. `transform` (e.g. percent-encoding for URL
    /// paths) is applied to inserted values; `injectedSecrets` returns the raw
    /// generated values so callers can scrub them from responses.
    public static func substitute(_ input: String, context: Context,
                                  transform: ((String) -> String)? = nil)
        throws -> (output: String, injectedSecrets: [String]) {
        var result = ""
        var secrets: [String] = []
        var cursor = input.startIndex
        let ns = input as NSString

        for match in pattern.matches(in: input, range: NSRange(location: 0, length: ns.length)) {
            guard let range = Range(match.range, in: input) else { continue }
            result += input[cursor..<range.lowerBound]
            let directive = ns.substring(with: match.range(at: 1))
            let arg = match.range(at: 2).location == NSNotFound ? nil : ns.substring(with: match.range(at: 2))
            let (value, isSecret) = try resolve(directive: directive, arg: arg, context: context)
            let emitted = transform.map { $0(value) } ?? value
            result += emitted
            if isSecret {
                // Report both forms: `transform` (percent-encoding for URL
                // paths) changes the bytes on the wire, and the response
                // scrubber can only redact what it is told to look for.
                secrets.append(value)
                if emitted != value { secrets.append(emitted) }
            }
            cursor = range.upperBound
        }
        result += input[cursor...]
        return (result, secrets)
    }

    /// Returns the value and whether it must be scrubbed from responses.
    private static func resolve(directive: String, arg: String?,
                                context: Context) throws -> (value: String, isSecret: Bool) {
        switch directive {
        case "password.generate", "password.confirm":
            guard let grant = context.signup else { throw SubstitutionError.signupRequired(directive) }
            return (grant.password(forTag: arg ?? "default"), true)
        case "email":
            guard let email = context.identity.email else { throw SubstitutionError.identityMissing("email") }
            return (email, false)
        case "username":
            guard let username = context.identity.username else { throw SubstitutionError.identityMissing("username") }
            return (username, false)
        default:
            throw SubstitutionError.unknownDirective(directive)
        }
    }
}
