import Foundation

public enum EnvName {
    /// Derives a conventional environment-variable name from a secret name,
    /// e.g. "github/token" -> "GITHUB_TOKEN".
    public static func derive(from secretName: String) -> String {
        var name = String(secretName.uppercased().map { ch -> Character in
            ch.isLetter || ch.isNumber ? ch : "_"
        })
        while name.contains("__") { name = name.replacingOccurrences(of: "__", with: "_") }
        name = name.trimmingCharacters(in: CharacterSet(charactersIn: "_"))
        if let first = name.first, first.isNumber { name = "_" + name }
        return name.isEmpty ? "SECRET" : name
    }
}
