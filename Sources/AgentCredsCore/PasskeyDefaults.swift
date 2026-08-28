import Foundation

public enum PasskeyDefaults {
    /// Relying party for passkey enrollment. Must serve
    /// /.well-known/apple-app-site-association with a `webcredentials` entry
    /// naming this app's team and bundle identifier, and the app must declare
    /// the matching associated-domains entitlement.
    public static let relyingParty = "agentcreds.ardabot.ai"
    public static let bundleIdentifier = "ai.ardabot.agentcreds"
    public static let teamIdentifier = "3CQT7X643L"
}
