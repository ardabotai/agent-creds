import Foundation

public enum PasskeyDefaults {
    /// Relying party for passkey enrollment. Must serve
    /// /.well-known/apple-app-site-association with a `webcredentials` entry
    /// naming this app's team and bundle identifier, and the app must declare
    /// the matching associated-domains entitlement.
    /// Override with AGENTCREDS_RELYING_PARTY. Moving to a custom domain later
    /// is this line plus the matching entitlement — the association file itself
    /// is identical, since it only names the team and bundle identifier.
    public static let relyingParty = "agentcreds.vercel.app"
    public static let bundleIdentifier = "ai.ardabot.agentcreds"
    public static let teamIdentifier = "3CQT7X643L"
}
