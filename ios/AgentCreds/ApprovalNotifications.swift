import SwiftUI
import UserNotifications
import CompanionProtocol

@MainActor @Observable
final class ApprovalNotifications {
    static let shared = ApprovalNotifications()
    var permission = "Not enabled"
    var delivery = "Connect to your Mac to register"
    var registration: PushRegistration?
    var pendingRoute: Route?
    struct Route: Equatable { let requestID: UUID; let pairingID: UUID }

    func enable() async {
        do {
            _ = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
            await refresh()
        } catch { permission = "Could not request notification permission" }
    }
    func refresh() async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        switch settings.authorizationStatus {
        case .authorized, .provisional, .ephemeral:
            permission = settings.alertSetting == .enabled ? "Allowed" : "Alerts disabled in Settings"
            UIApplication.shared.registerForRemoteNotifications()
        case .denied:
            permission = "Disabled in Settings"; registration = nil
        case .notDetermined: permission = "Not enabled"; registration = nil
        @unknown default: permission = "Check Settings"; registration = nil
        }
    }
    func received(_ data: Data) {
        #if DEBUG
        let environment = "sandbox"
        #else
        let environment = "production"
        #endif
        registration = PushRegistration(token: data.map { String(format: "%02x", $0) }.joined(), environment: environment)
    }
    func route(_ info: [AnyHashable: Any]) {
        guard let route = ApprovalNotification.route(info) else { return }
        pendingRoute = Route(requestID: route.requestID, pairingID: route.pairingID)
    }
}

final class NotificationAppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let review = UNNotificationAction(identifier: ApprovalNotification.reviewAction, title: "Review request", options: [.foreground, .authenticationRequired])
        center.setNotificationCategories([UNNotificationCategory(identifier: ApprovalNotification.category, actions: [review], intentIdentifiers: [], options: [])])
        return true
    }
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in ApprovalNotifications.shared.received(deviceToken) }
    }
    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        Task { @MainActor in ApprovalNotifications.shared.delivery = "Apple registration failed; check signing and connection" }
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        guard [UNNotificationDefaultActionIdentifier, ApprovalNotification.reviewAction].contains(response.actionIdentifier) else { completionHandler(); return }
        Task { @MainActor in
            ApprovalNotifications.shared.route(response.notification.request.content.userInfo)
            completionHandler()
        }
    }
}

struct NotificationSettingsView: View {
    var store: CompanionStore
    private var notifications: ApprovalNotifications { .shared }
    var body: some View {
        Section {
            LabeledContent("Permission", value: notifications.permission)
            Text(notifications.delivery).font(.callout).foregroundStyle(.secondary)
            Button("Enable approval notifications") { Task { await notifications.enable(); await store.syncNotifications() } }.disabled(store.isDemo)
            Button("Open notification settings") {
                if let url = URL(string: UIApplication.openNotificationSettingsURLString) { UIApplication.shared.open(url) }
            }
        } header: { Text("Approval notifications") } footer: {
            Text("Alerts contain no credential details. Tap to unlock and review. Delivery depends on Apple notification settings, an online Mac and configured push delivery. The relay connects your devices across networks.")
        }
    }
}
