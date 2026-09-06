import SwiftUI
import CompanionProtocol

@main
struct AgentCredsApp: App {
    @UIApplicationDelegateAdaptor(NotificationAppDelegate.self) private var appDelegate
    @State private var store = CompanionStore()
    @Environment(\.scenePhase) private var phase
    var body: some Scene {
        WindowGroup {
            CompanionRoot(store: store)
                .tint(Color(red: 0.19, green: 0.36, blue: 0.32))
                .onOpenURL { store.open($0) }
                .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { if let url = $0.webpageURL { store.open(url) } }
                .onChange(of: phase) { _, value in
                    if value == .background { store.lock() }
                    if value == .active { Task { await ApprovalNotifications.shared.refresh(); await store.syncNotifications() } }
                }
                .task { await ApprovalNotifications.shared.refresh(); await store.consumeNotification() }
                .onChange(of: ApprovalNotifications.shared.pendingRoute) { _, _ in Task { await store.consumeNotification() } }
                .onChange(of: ApprovalNotifications.shared.registration) { _, _ in Task { await store.syncNotifications() } }
        }
    }
}

struct CompanionRoot: View {
    @Bindable var store: CompanionStore
    @State private var scanning = false
    @State private var manualPairing = false
    @State private var pairingCode = ""
    var body: some View {
        Group {
            if store.locked || store.snapshot == nil {
                welcome
            } else {
                TabView(selection: $store.section) {
                    RequestsView(store: store).tabItem { Label("Requests", systemImage: "checkmark.shield") }.tag(CompanionStore.Section.requests)
                        .badge(store.snapshot?.requests.filter { $0.effectiveStatus() == .pending }.count ?? 0)
                    VaultView(store: store).tabItem { Label("Vault", systemImage: "key.horizontal") }.tag(CompanionStore.Section.vault)
                    ActivityView(store: store).tabItem { Label("Activity", systemImage: "clock") }.tag(CompanionStore.Section.activity)
                    devices.tabItem { Label("Devices", systemImage: "laptopcomputer.and.iphone") }.tag(CompanionStore.Section.devices)
                }
                .safeAreaInset(edge: .top, spacing: 0) {
                    if store.isDemo {
                        HStack { Image(systemName: "sparkles"); Text("Demo vault · synthetic data"); Spacer(); Button("Exit") { Task { await store.disconnect() } } }
                            .font(.caption.weight(.medium)).padding(.horizontal, 18).padding(.vertical, 8).background(Color.yellow.opacity(0.15))
                    }
                }
            }
        }
        .sheet(isPresented: $scanning) { PairingScanner { code in scanning = false; Task { await store.pair(code: code) } } }
        .sheet(isPresented: $manualPairing) {
            NavigationStack {
                Form {
                    Section("Pairing code") { SecureField("Paste code from your Mac", text: $pairingCode).textInputAutocapitalization(.never).autocorrectionDisabled() }
                    Text("Only use a code shown by your own Mac. Both devices need internet access.").foregroundStyle(.secondary)
                    Button("Connect") { let code = pairingCode; pairingCode = ""; manualPairing = false; Task { await store.pair(code: code) } }.disabled(pairingCode.isEmpty)
                }.navigationTitle("Pair Mac").toolbar { Button("Cancel") { pairingCode = ""; manualPairing = false } }
            }
        }
        .alert("Needs attention", isPresented: Binding(get: { store.error != nil }, set: { if !$0 { store.error = nil } })) {
            Button("OK", role: .cancel) { store.error = nil }
        } message: { Text(store.error ?? "") }
        .sheet(isPresented: Binding(get: { store.selectedRequest != nil && !store.locked }, set: { if !$0 { store.selectedRequest = nil } })) {
            if let id = store.selectedRequest { ApprovalDetail(store: store, id: id) }
        }
        .task(id: store.locked) {
            guard !store.locked else { return }
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(8))
                if !Task.isCancelled { await store.refresh() }
            }
        }
    }
    private var welcome: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    HStack { Label("agent-creds", systemImage: "key.horizontal.fill").font(.headline); Spacer(); Text("COMPANION").font(.caption2.weight(.semibold)).tracking(2).foregroundStyle(.secondary) }
                    Spacer(minLength: 40)
                    Image(systemName: "checkmark.shield.fill").font(.system(size: 64)).foregroundStyle(.tint).padding(26).background(.tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 30))
                    Text("Your credentials.\nYour call.").font(.system(size: 42, weight: .semibold, design: .rounded)).tracking(-1)
                    Text("Manage your vault and review agent requests from your iPhone. Unlock with your Mac or a trusted iPhone.").font(.title3).foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 18) {
                        Label("Review the destination before every release", systemImage: "arrow.up.right.square")
                        Label("Approve with Face ID or your passcode", systemImage: "faceid")
                        Label("No secret values in agent conversations", systemImage: "bubble.left.and.text.bubble.right")
                    }.font(.subheadline).foregroundStyle(.secondary)
                    if store.pendingLink != nil { Text("A credential request is waiting. Connect to its Mac to review it.").font(.callout).padding().background(.tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 16)) }
                    if store.pairing != nil {
                        Button { Task { await store.unlock() } } label: { Label("Unlock companion", systemImage: "faceid").frame(maxWidth: .infinity).padding(8) }.buttonStyle(.borderedProminent)
                    }
                    Button { scanning = true } label: { Label("Scan Mac Code", systemImage: "qrcode.viewfinder").frame(maxWidth: .infinity).padding(8) }.buttonStyle(.borderedProminent)
                    Button("Enter pairing code") { manualPairing = true }.frame(maxWidth: .infinity)
                    Button("Explore the demo") { store.startDemo() }.frame(maxWidth: .infinity).foregroundStyle(.secondary)
                    if store.busy { ProgressView("Connecting securely…").frame(maxWidth: .infinity) }
                }.padding(28).frame(maxWidth: 600)
            }.frame(maxWidth: .infinity).background(Color(.systemGroupedBackground))
        }
    }
    private var devices: some View {
        NavigationStack {
            List {
                Section {
                    Label(store.snapshot?.macName ?? "Mac", systemImage: "laptopcomputer").font(.headline)
                    LabeledContent("Connection", value: store.isDemo ? "Demo" : (store.pairing?.relay != nil ? "Encrypted relay" : "Local network"))
                    LabeledContent("iPhone control", value: store.hasOwnerControl ? "Independent owner" : "Mac confirmation required")
                    if !store.hasOwnerControl && !store.isDemo {
                        Button("Enable iPhone control") { Task { await store.enableOwnerControl() } }.disabled(store.busy)
                    }
                    LabeledContent("Vault protection", value: store.snapshot?.protection.capitalized ?? "Unknown")
                    if let date = store.lastSync { LabeledContent("Last synced") { Text(date, style: .relative) } }
                } header: { Text("Your Mac") } footer: { Text("Your Mac must stay online. A trusted iPhone can authorize vault changes and releases independently. Trusted relay pairing survives Mac restarts. You can revoke it at any time from your Mac.") }
                Section {
                    Button("Refresh connection") { Task { await store.refresh() } }
                    Button("Disconnect this iPhone", role: .destructive) { Task { await store.disconnect() } }
                }
                NotificationSettingsView(store: store)
                Section("Pairing") { Text("On your Mac, open the agent-creds menu → Pair iPhone. Use Disconnect All Companions on the Mac to revoke access immediately.").foregroundStyle(.secondary) }
            }.navigationTitle("Devices")
        }
    }
}

struct RequestsView: View {
    @Bindable var store: CompanionStore
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    HStack { Label(store.snapshot?.macName ?? "Mac", systemImage: "laptopcomputer").font(.caption); Spacer(); Text(store.isDemo ? "DEMO" : "PAIRED").font(.caption2.weight(.semibold)).tracking(1.5) }.foregroundStyle(.secondary)
                    Text("Stay in control.").font(.largeTitle.bold())
                    Text("Review what your agents need, where it goes, and how long they can use it.").foregroundStyle(.secondary)
                    if let notice = store.notice { NoticeCard(text: notice) }
                    let pending = store.snapshot?.requests.filter { $0.effectiveStatus() == .pending } ?? []
                    HStack { Text("Needs your approval").font(.headline); Spacer(); Text("\(pending.count)").foregroundStyle(.secondary) }
                    if pending.isEmpty { ContentUnavailableView("All caught up", systemImage: "checkmark.shield", description: Text("New credential requests will appear here. You can also open a request link from your agent.")) }
                    ForEach(pending) { request in
                        Button { store.selectedRequest = request.id } label: { RequestCard(request: request) }.buttonStyle(.plain)
                    }
                    let other = store.snapshot?.requests.filter { $0.effectiveStatus() != .pending } ?? []
                    if !other.isEmpty {
                        Text("Recent requests").font(.headline)
                        ForEach(other) { request in Button { store.selectedRequest = request.id } label: { RequestCard(request: request) }.buttonStyle(.plain) }
                    }
                }.padding(22).frame(maxWidth: 760)
            }.frame(maxWidth: .infinity).background(Color(.systemGroupedBackground)).navigationTitle("Requests").navigationBarTitleDisplayMode(.inline)
                .refreshable { await store.refresh() }
        }
    }
}

struct RequestCard: View {
    let request: CredentialRequest
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "terminal").font(.title3).frame(width: 44, height: 44).background(.tint.opacity(0.09), in: RoundedRectangle(cornerRadius: 14))
                VStack(alignment: .leading, spacing: 3) { Text(request.agent).font(.headline); Text(request.credentialName).font(.subheadline).foregroundStyle(.secondary) }
                Spacer(); Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
            }
            Text(request.purpose).font(.subheadline).lineLimit(3)
            HStack { Label(request.hosts.first ?? "No destination", systemImage: "globe").lineLimit(1); Spacer(); Text(statusLabel(request.effectiveStatus())).lineLimit(1) }.font(.caption).foregroundStyle(.secondary)
        }.padding(20).background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 24))
    }
}

func statusLabel(_ status: CredentialRequest.Status) -> String {
    switch status {
    case .pending: return "Review request"
    case .awaitingMacUnlock: return "Mac unlock required"
    case .releasing: return "Releasing access"
    case .ready: return "Ready for agent"
    case .denied: return "Denied"
    case .expired: return "Expired"
    case .failed: return "Not released"
    case .redeemed: return "Delivered to agent"
    }
}

struct ApprovalDetail: View {
    @Bindable var store: CompanionStore
    let id: UUID
    @State private var duration = 120
    @Environment(\.dismiss) private var dismiss
    private var request: CredentialRequest? { store.snapshot?.requests.first { $0.id == id } }
    var body: some View {
        NavigationStack {
            Group {
            if let request {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let status = request.effectiveStatus(at: context.date)
                    ScrollView {
                        VStack(alignment: .leading, spacing: 24) {
                            Image(systemName: status == .pending ? "checkmark.shield" : "shield.lefthalf.filled").font(.system(size: 44)).foregroundStyle(.tint)
                            Text("\(request.agent) needs\nyour permission.").font(.largeTitle.bold())
                            Text(request.credentialName).font(.title2.weight(.medium))
                            VStack(alignment: .leading, spacing: 10) {
                                Label("Agent’s stated purpose", systemImage: "text.bubble").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                                Text(request.purpose)
                                Text("The agent name and purpose are supplied by the client. Verify they match what you asked for.").font(.caption).foregroundStyle(.secondary)
                            }.padding(18).background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 18))
                            VStack(alignment: .leading, spacing: 12) { Text("Allowed destinations").font(.headline); ForEach(request.hosts, id: \.self) { Label($0, systemImage: "globe").font(.body.monospaced()) } }
                            if status == .pending {
                                Picker("Allow access for", selection: $duration) {
                                    ForEach(Array(Set([min(120, request.maximumDuration), min(900, request.maximumDuration), request.maximumDuration])).sorted(), id: \.self) { value in Text(value < 60 ? "\(value) seconds" : "\(value / 60) minutes").tag(value) }
                                }.pickerStyle(.menu)
                                HStack { Text("Request expires").foregroundStyle(.secondary); Spacer(); Text(request.expiresAt, style: .timer).monospacedDigit() }.font(.caption)
                                NoticeCard(text: store.hasOwnerControl ? "Face ID or your passcode authorizes this request. Your Mac releases a scoped handle without another prompt. The agent never receives the stored value." : "Your iPhone records the decision. Unlock on your Mac to release a scoped handle. Enable independent iPhone control in Devices.")
                                Button { Task { _ = await store.perform(CompanionCommand(action: .approve, requestID: id, duration: duration)) } } label: { Label(store.busy ? "Confirming…" : "Approve request", systemImage: "faceid").frame(maxWidth: .infinity).padding(8) }.buttonStyle(.borderedProminent).disabled(store.busy)
                                Button("Deny request", role: .destructive) { Task { _ = await store.perform(CompanionCommand(action: .deny, requestID: id, duration: 1)) } }.frame(maxWidth: .infinity).disabled(store.busy)
                            } else { NoticeCard(text: statusLabel(status)); if let notice = store.notice { Text(notice).foregroundStyle(.secondary) } }
                        }.padding(24).frame(maxWidth: 650)
                    }.frame(maxWidth: .infinity).background(Color(.systemGroupedBackground))
                }.onAppear { duration = min(120, request.maximumDuration) }
            } else { ContentUnavailableView("Request unavailable", systemImage: "clock.badge.exclamationmark") }
            }.navigationTitle("Review request").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}

struct NoticeCard: View {
    let text: String
    var body: some View { Label(text, systemImage: "info.circle").font(.callout).foregroundStyle(.secondary).padding(16).frame(maxWidth: .infinity, alignment: .leading).background(.tint.opacity(0.06), in: RoundedRectangle(cornerRadius: 16)) }
}

struct ActivityView: View {
    var store: CompanionStore
    var body: some View {
        NavigationStack {
            List {
                ForEach(store.snapshot?.activity ?? []) { event in
                    VStack(alignment: .leading, spacing: 5) { Text(event.title).font(.headline); Text(event.detail).font(.subheadline).foregroundStyle(.secondary); Text(event.date, style: .relative).font(.caption).foregroundStyle(.tertiary) }.padding(.vertical, 5)
                }
            }.overlay { if store.snapshot?.activity.isEmpty == true { ContentUnavailableView("No activity yet", systemImage: "clock") } }.navigationTitle("Activity").refreshable { await store.refresh() }
        }
    }
}
