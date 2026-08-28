import Foundation
import LocalAuthentication

/// The human ceremony that gates every release. Shared by the daemon and the
/// CLI so both enforce identical approval semantics.
///
/// Phase 2: also push an ApprovalRequest record to CloudKit so the iPhone can
/// answer with Face ID — first device to respond wins.
public enum ApprovalCeremony {
    /// Blocking; called from a worker thread while the caller waits. Returns
    /// true only if the user authenticated with Touch ID (or the password
    /// fallback). `onUnavailable` reports why no prompt could be shown.
    public static func approve(reason: String,
                               onUnavailable: ((String) -> Void)? = nil) -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            onUnavailable?(error?.localizedDescription ?? "no authentication method available")
            return false
        }
        let semaphore = DispatchSemaphore(value: 0)
        var approved = false
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
            approved = success
            semaphore.signal()
        }
        semaphore.wait()
        return approved
    }
}
