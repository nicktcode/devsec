# damit Phase 3: Menubar App

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a native macOS menubar app that wraps the existing DevsecCore library, providing continuous background scanning with notifications, one-click whitelisting, and a settings panel. Distributed as a signed .dmg via Gumroad.

**Architecture:** SwiftUI menubar app using the MenuBarExtra API (macOS 14+). Shares the DevsecCore library with the CLI. Runs scans on a configurable timer, persists state between launches, sends native macOS notifications for new findings.

**Tech Stack:** SwiftUI, DevsecCore (existing library), UserNotifications framework, LaunchAtLogin package, macOS 14.0+

---

## File Structure

```
damit/
├── Package.swift                          # Updated: add DevsecApp executable target
├── Sources/
│   ├── DevsecCore/                        # Existing - no changes
│   ├── damit-cli/                        # Existing - no changes
│   └── DevsecApp/
│       ├── DevsecApp.swift                # @main, MenuBarExtra entry point
│       ├── AppState.swift                 # ObservableObject: scan state, findings, schedule
│       ├── Views/
│       │   ├── MenuBarIcon.swift          # Status icon (green/yellow/red circle)
│       │   ├── PopoverView.swift          # Main popover: module summary + recent findings
│       │   ├── FindingRow.swift           # Single finding row with actions
│       │   ├── ModuleSummaryRow.swift     # Single module status row
│       │   ├── SettingsView.swift         # Settings window: interval, modules, whitelist, launch at login
│       │   └── FullReportView.swift       # Scrollable list of all findings
│       └── Services/
│           ├── ScanScheduler.swift        # Timer-based scan scheduling
│           └── NotificationService.swift  # UserNotifications wrapper
└── Tests/
    └── DevsecAppTests/
        └── AppStateTests.swift            # Tests for AppState logic
```

---

## Task 1: Add DevsecApp Target to Package.swift

**Files:**
- Modify: `Package.swift`

- [ ] **Step 1: Add LaunchAtLogin dependency and DevsecApp target**

Update `Package.swift` to add:

```swift
// In dependencies array:
.package(url: "https://github.com/sindresorhus/LaunchAtLogin-Modern.git", from: "1.1.0"),

// In targets array:
.executableTarget(
    name: "DevsecApp",
    dependencies: [
        "DevsecCore",
        .product(name: "LaunchAtLogin", package: "LaunchAtLogin-Modern"),
    ],
    path: "Sources/DevsecApp"
),
```

- [ ] **Step 2: Create minimal DevsecApp entry point**

Create `Sources/DevsecApp/DevsecApp.swift`:

```swift
import SwiftUI
import DevsecCore

@main
struct DevsecMenuBarApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        MenuBarExtra {
            PopoverView(appState: appState)
        } label: {
            MenuBarIcon(status: appState.overallStatus)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(appState: appState)
        }
    }
}
```

- [ ] **Step 3: Create stub files so it compiles**

Create minimal stubs for `AppState.swift`, `PopoverView.swift`, `MenuBarIcon.swift`, `SettingsView.swift` so the target builds:

`Sources/DevsecApp/AppState.swift`:

```swift
import SwiftUI
import DevsecCore

enum ScanStatus: String {
    case clean
    case warnings
    case critical
    case scanning
    case idle
}

@MainActor
final class AppState: ObservableObject {
    @Published var overallStatus: ScanStatus = .idle
    @Published var lastScanResult: FullScanResult?
    @Published var lastScanTime: Date?
    @Published var isScanning: Bool = false
    @Published var scanInterval: TimeInterval = 300

    // Module enable/disable
    @Published var enabledModules: Set<ScanModule> = [
        .env, .history, .ssh, .documents, .aiTools, .credentialFiles
    ]
}
```

`Sources/DevsecApp/Views/MenuBarIcon.swift`:

```swift
import SwiftUI

struct MenuBarIcon: View {
    let status: ScanStatus

    var body: some View {
        Image(systemName: iconName)
            .foregroundColor(iconColor)
    }

    private var iconName: String {
        switch status {
        case .clean: return "checkmark.shield.fill"
        case .warnings: return "exclamationmark.shield.fill"
        case .critical: return "xmark.shield.fill"
        case .scanning: return "shield.lefthalf.filled"
        case .idle: return "shield"
        }
    }

    private var iconColor: Color {
        switch status {
        case .clean: return .green
        case .warnings: return .yellow
        case .critical: return .red
        case .scanning: return .blue
        case .idle: return .gray
        }
    }
}
```

`Sources/DevsecApp/Views/PopoverView.swift`:

```swift
import SwiftUI
import DevsecCore

struct PopoverView: View {
    @ObservedObject var appState: AppState

    var body: some View {
        Text("damit")
            .padding()
    }
}
```

`Sources/DevsecApp/Views/SettingsView.swift`:

```swift
import SwiftUI

struct SettingsView: View {
    @ObservedObject var appState: AppState

    var body: some View {
        Text("Settings")
            .padding()
    }
}
```

- [ ] **Step 4: Verify it builds**

```bash
swift build --target DevsecApp
```

- [ ] **Step 5: Commit**

```bash
git add Package.swift Sources/DevsecApp/
git commit -m "feat: add DevsecApp menubar target with stubs"
```

---

## Task 2: AppState - Core State Management

**Files:**
- Modify: `Sources/DevsecApp/AppState.swift`

- [ ] **Step 1: Implement full AppState**

Replace `Sources/DevsecApp/AppState.swift`:

```swift
import SwiftUI
import DevsecCore

enum ScanStatus: String {
    case clean
    case warnings
    case critical
    case scanning
    case idle
}

@MainActor
final class AppState: ObservableObject {
    // Scan state
    @Published var overallStatus: ScanStatus = .idle
    @Published var lastScanResult: FullScanResult?
    @Published var lastScanTime: Date?
    @Published var isScanning: Bool = false
    @Published var errorMessage: String?

    // Settings
    @Published var scanInterval: TimeInterval = 300 {
        didSet { scheduler.updateInterval(scanInterval) }
    }
    @Published var enabledModules: Set<ScanModule> = [
        .env, .history, .ssh, .documents, .aiTools, .credentialFiles
    ]
    @Published var notificationsEnabled: Bool = true

    // Services
    private let whitelist = WhitelistManager()
    private let findingStore = FindingStore()
    private lazy var scheduler = ScanScheduler(appState: self)
    private let notificationService = NotificationService()

    init() {
        scheduler = ScanScheduler(appState: self)
        if notificationsEnabled {
            notificationService.requestPermission()
        }
    }

    func startScheduledScanning() {
        scheduler.start()
    }

    func stopScheduledScanning() {
        scheduler.stop()
    }

    func runScan() async {
        guard !isScanning else { return }

        isScanning = true
        overallStatus = .scanning
        errorMessage = nil

        do {
            let orchestrator = ScanOrchestrator(
                whitelist: whitelist,
                findingStore: findingStore,
                modules: enabledModules
            )
            let result = try await orchestrator.scan()

            lastScanResult = result
            lastScanTime = Date()

            if result.criticalCount > 0 {
                overallStatus = .critical
            } else if result.highCount > 0 || result.mediumCount > 0 {
                overallStatus = .warnings
            } else {
                overallStatus = .clean
            }

            // Notify on new findings
            if result.newCount > 0 && notificationsEnabled {
                notificationService.sendNewFindingsNotification(count: result.newCount, critical: result.criticalCount)
            }
        } catch {
            errorMessage = error.localizedDescription
            overallStatus = .idle
        }

        isScanning = false
    }

    func whitelistFinding(_ finding: Finding) {
        whitelist.addFinding(finding.id)
        try? whitelist.save()

        // Re-filter current results
        if var result = lastScanResult {
            let filtered = whitelist.filterFindings(result.findings)
            lastScanResult = FullScanResult(
                results: result.results,
                findings: filtered,
                totalDuration: result.totalDuration,
                newCount: filtered.filter(\.isNew).count,
                criticalCount: filtered.filter { $0.severity == .critical }.count,
                highCount: filtered.filter { $0.severity == .high }.count,
                mediumCount: filtered.filter { $0.severity == .medium }.count,
                lowCount: filtered.filter { $0.severity == .low }.count
            )
        }
    }

    var nextScanTime: Date? {
        guard let last = lastScanTime else { return nil }
        return last.addingTimeInterval(scanInterval)
    }

    var timeUntilNextScan: String {
        guard let next = nextScanTime else { return "not scheduled" }
        let remaining = next.timeIntervalSinceNow
        if remaining <= 0 { return "now" }
        let minutes = Int(remaining) / 60
        let seconds = Int(remaining) % 60
        if minutes > 0 {
            return "in \(minutes)m \(seconds)s"
        }
        return "in \(seconds)s"
    }
}
```

- [ ] **Step 2: Verify it builds**

```bash
swift build --target DevsecApp
```

- [ ] **Step 3: Commit**

```bash
git add Sources/DevsecApp/AppState.swift
git commit -m "feat: implement AppState with scan management and whitelist support"
```

---

## Task 3: ScanScheduler and NotificationService

**Files:**
- Create: `Sources/DevsecApp/Services/ScanScheduler.swift`
- Create: `Sources/DevsecApp/Services/NotificationService.swift`

- [ ] **Step 1: Implement ScanScheduler**

Create `Sources/DevsecApp/Services/ScanScheduler.swift`:

```swift
import Foundation

@MainActor
final class ScanScheduler {
    private weak var appState: AppState?
    private var timer: Timer?

    init(appState: AppState) {
        self.appState = appState
    }

    func start() {
        stop()
        let interval = appState?.scanInterval ?? 300
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.appState?.runScan()
            }
        }
        // Run initial scan immediately
        Task {
            await appState?.runScan()
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    func updateInterval(_ interval: TimeInterval) {
        guard timer != nil else { return }
        start() // restart with new interval
    }
}
```

- [ ] **Step 2: Implement NotificationService**

Create `Sources/DevsecApp/Services/NotificationService.swift`:

```swift
import UserNotifications

final class NotificationService {

    func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    func sendNewFindingsNotification(count: Int, critical: Int) {
        let content = UNMutableNotificationContent()
        content.title = "damit"

        if critical > 0 {
            content.body = "\(count) new finding\(count == 1 ? "" : "s") detected (\(critical) critical)"
            content.sound = .default
        } else {
            content.body = "\(count) new finding\(count == 1 ? "" : "s") detected"
            content.sound = .default
        }

        let request = UNNotificationRequest(
            identifier: "damit-scan-\(UUID().uuidString)",
            content: content,
            trigger: nil // deliver immediately
        )

        UNUserNotificationCenter.current().add(request)
    }
}
```

- [ ] **Step 3: Verify it builds**

```bash
swift build --target DevsecApp
```

- [ ] **Step 4: Commit**

```bash
git add Sources/DevsecApp/Services/
git commit -m "feat: add scan scheduler and notification service"
```

---

## Task 4: PopoverView - Module Summary and Findings

**Files:**
- Modify: `Sources/DevsecApp/Views/PopoverView.swift`
- Create: `Sources/DevsecApp/Views/ModuleSummaryRow.swift`
- Create: `Sources/DevsecApp/Views/FindingRow.swift`

- [ ] **Step 1: Implement ModuleSummaryRow**

Create `Sources/DevsecApp/Views/ModuleSummaryRow.swift`:

```swift
import SwiftUI
import DevsecCore

struct ModuleSummaryRow: View {
    let module: ScanModule
    let findingCount: Int

    var body: some View {
        HStack {
            statusIcon
            Text(moduleLabel)
                .font(.system(.body, design: .monospaced))
            Spacer()
            if findingCount == 0 {
                Text("ok")
                    .foregroundColor(.secondary)
                    .font(.system(.body, design: .monospaced))
            } else {
                Text("\(findingCount)")
                    .foregroundColor(findingCount > 0 ? .red : .secondary)
                    .font(.system(.body, design: .monospaced))
                    .bold()
            }
        }
    }

    private var statusIcon: some View {
        Group {
            if findingCount == 0 {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.green)
            } else {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.orange)
            }
        }
        .font(.caption)
    }

    private var moduleLabel: String {
        switch module {
        case .env: return "Env Files"
        case .history: return "History"
        case .ssh: return "SSH Keys"
        case .documents: return "Documents"
        case .aiTools: return "AI Tools"
        case .credentialFiles: return "Credentials"
        case .git: return "Git"
        case .ports: return "Ports"
        case .clipboard: return "Clipboard"
        case .permissions: return "Permissions"
        }
    }
}
```

- [ ] **Step 2: Implement FindingRow**

Create `Sources/DevsecApp/Views/FindingRow.swift`:

```swift
import SwiftUI
import DevsecCore

struct FindingRow: View {
    let finding: Finding
    let onWhitelist: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                severityBadge
                if finding.isNew {
                    Text("NEW")
                        .font(.caption2)
                        .bold()
                        .padding(.horizontal, 4)
                        .padding(.vertical, 1)
                        .background(Color.blue.opacity(0.2))
                        .cornerRadius(3)
                }
                Spacer()
                Button("Whitelist") {
                    onWhitelist()
                }
                .buttonStyle(.borderless)
                .font(.caption)
            }

            if let path = finding.filePath {
                Text(abbreviatePath(path))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Text(finding.description)
                .font(.caption)
                .lineLimit(2)
        }
        .padding(.vertical, 4)
    }

    private var severityBadge: some View {
        Text(finding.severity.rawValue.uppercased())
            .font(.caption2)
            .bold()
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(severityColor.opacity(0.2))
            .foregroundColor(severityColor)
            .cornerRadius(4)
    }

    private var severityColor: Color {
        switch finding.severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .info: return .gray
        }
    }

    private func abbreviatePath(_ path: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if path.hasPrefix(home) {
            return "~" + String(path.dropFirst(home.count))
        }
        return path
    }
}
```

- [ ] **Step 3: Implement full PopoverView**

Replace `Sources/DevsecApp/Views/PopoverView.swift`:

```swift
import SwiftUI
import DevsecCore

struct PopoverView: View {
    @ObservedObject var appState: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            header
            Divider()

            // Module summary
            moduleSummary
            Divider()

            // Recent findings (top 5)
            if let result = appState.lastScanResult, !result.findings.isEmpty {
                recentFindings(result.findings)
                Divider()
            }

            // Actions
            actions
        }
        .frame(width: 340)
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            Text("damit")
                .font(.headline)
            Spacer()
            statusIndicator
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var statusIndicator: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
            Text(statusText)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }

    private var statusColor: Color {
        switch appState.overallStatus {
        case .clean: return .green
        case .warnings: return .yellow
        case .critical: return .red
        case .scanning: return .blue
        case .idle: return .gray
        }
    }

    private var statusText: String {
        switch appState.overallStatus {
        case .clean: return "clean"
        case .warnings: return "warnings"
        case .critical: return "critical"
        case .scanning: return "scanning..."
        case .idle: return "idle"
        }
    }

    // MARK: - Module Summary

    private var moduleSummary: some View {
        VStack(alignment: .leading, spacing: 2) {
            if let result = appState.lastScanResult {
                ForEach(result.results, id: \.module) { scanResult in
                    ModuleSummaryRow(
                        module: scanResult.module,
                        findingCount: scanResult.findings.count
                    )
                }
            } else {
                Text("No scan results yet")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            // Scan timing
            HStack {
                if let time = appState.lastScanTime {
                    Text("Last scan: \(time, style: .relative) ago")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Text("Next: \(appState.timeUntilNextScan)")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .padding(.top, 4)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    // MARK: - Recent Findings

    private func recentFindings(_ findings: [Finding]) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Recent Findings")
                .font(.caption)
                .bold()
                .foregroundColor(.secondary)
                .padding(.horizontal, 12)
                .padding(.top, 8)
                .padding(.bottom, 4)

            ForEach(Array(findings.prefix(5))) { finding in
                FindingRow(finding: finding) {
                    appState.whitelistFinding(finding)
                }
                .padding(.horizontal, 12)
                if finding.id != findings.prefix(5).last?.id {
                    Divider().padding(.horizontal, 12)
                }
            }

            if findings.count > 5 {
                Text("+ \(findings.count - 5) more")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 4)
            }
        }
    }

    // MARK: - Actions

    private var actions: some View {
        VStack(spacing: 0) {
            Button {
                Task { await appState.runScan() }
            } label: {
                HStack {
                    Image(systemName: "arrow.clockwise")
                    Text("Scan Now")
                    Spacer()
                }
            }
            .buttonStyle(.borderless)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .disabled(appState.isScanning)

            Divider()

            Button {
                if #available(macOS 14.0, *) {
                    NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
                } else {
                    NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
                }
            } label: {
                HStack {
                    Image(systemName: "gear")
                    Text("Settings...")
                    Spacer()
                }
            }
            .buttonStyle(.borderless)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)

            Divider()

            Button {
                NSApplication.shared.terminate(nil)
            } label: {
                HStack {
                    Text("Quit damit")
                    Spacer()
                }
            }
            .buttonStyle(.borderless)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
    }
}
```

- [ ] **Step 4: Verify it builds**

```bash
swift build --target DevsecApp
```

- [ ] **Step 5: Commit**

```bash
git add Sources/DevsecApp/Views/
git commit -m "feat: add popover view with module summary, findings, and actions"
```

---

## Task 5: SettingsView

**Files:**
- Modify: `Sources/DevsecApp/Views/SettingsView.swift`

- [ ] **Step 1: Implement full SettingsView**

Replace `Sources/DevsecApp/Views/SettingsView.swift`:

```swift
import SwiftUI
import DevsecCore
import LaunchAtLogin

struct SettingsView: View {
    @ObservedObject var appState: AppState

    var body: some View {
        TabView {
            generalTab
                .tabItem {
                    Label("General", systemImage: "gear")
                }

            modulesTab
                .tabItem {
                    Label("Modules", systemImage: "square.grid.2x2")
                }

            whitelistTab
                .tabItem {
                    Label("Whitelist", systemImage: "list.bullet")
                }
        }
        .frame(width: 450, height: 320)
    }

    // MARK: - General Tab

    private var generalTab: some View {
        Form {
            Section("Scanning") {
                Picker("Scan interval", selection: $appState.scanInterval) {
                    Text("1 minute").tag(TimeInterval(60))
                    Text("5 minutes").tag(TimeInterval(300))
                    Text("15 minutes").tag(TimeInterval(900))
                    Text("30 minutes").tag(TimeInterval(1800))
                    Text("1 hour").tag(TimeInterval(3600))
                }
            }

            Section("Notifications") {
                Toggle("Enable notifications", isOn: $appState.notificationsEnabled)
            }

            Section("Startup") {
                LaunchAtLogin.Toggle("Launch at login")
            }
        }
        .padding()
    }

    // MARK: - Modules Tab

    private var modulesTab: some View {
        Form {
            Section("Active Scan Modules") {
                moduleToggle(.env, label: "Environment Files (.env)")
                moduleToggle(.history, label: "Shell History")
                moduleToggle(.ssh, label: "SSH Keys")
                moduleToggle(.documents, label: "Documents (PDF, Word, etc.)")
                moduleToggle(.aiTools, label: "AI Tool Configs")
                moduleToggle(.credentialFiles, label: "Credential Files")
            }
        }
        .padding()
    }

    private func moduleToggle(_ module: ScanModule, label: String) -> some View {
        Toggle(label, isOn: Binding(
            get: { appState.enabledModules.contains(module) },
            set: { enabled in
                if enabled {
                    appState.enabledModules.insert(module)
                } else {
                    appState.enabledModules.remove(module)
                }
            }
        ))
    }

    // MARK: - Whitelist Tab

    private var whitelistTab: some View {
        VStack(alignment: .leading) {
            Text("Whitelisted Findings")
                .font(.headline)

            let whitelist = WhitelistManager()
            let findings = whitelist.allFindings

            if findings.isEmpty {
                Text("No findings are whitelisted.")
                    .foregroundColor(.secondary)
                    .padding(.top, 8)
                Spacer()
            } else {
                List {
                    ForEach(findings, id: \.self) { findingId in
                        HStack {
                            Text(findingId)
                                .font(.system(.caption, design: .monospaced))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer()
                            Button("Remove") {
                                whitelist.removeFinding(findingId)
                                try? whitelist.save()
                            }
                            .buttonStyle(.borderless)
                            .foregroundColor(.red)
                            .font(.caption)
                        }
                    }
                }
            }
        }
        .padding()
    }
}
```

- [ ] **Step 2: Verify it builds**

```bash
swift build --target DevsecApp
```

- [ ] **Step 3: Commit**

```bash
git add Sources/DevsecApp/Views/SettingsView.swift
git commit -m "feat: add settings view with interval, modules, and whitelist management"
```

---

## Task 6: Wire Up App Lifecycle

**Files:**
- Modify: `Sources/DevsecApp/DevsecApp.swift`

- [ ] **Step 1: Update DevsecApp with lifecycle management**

Replace `Sources/DevsecApp/DevsecApp.swift`:

```swift
import SwiftUI
import DevsecCore

@main
struct DevsecMenuBarApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        MenuBarExtra {
            PopoverView(appState: appState)
        } label: {
            MenuBarIcon(status: appState.overallStatus)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(appState: appState)
        }
    }

    init() {
        // Start scheduled scanning after a brief delay to let the app settle
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            Task { @MainActor in
                // Access the actual instance through the environment
                // The initial scan is triggered by AppState.startScheduledScanning()
            }
        }
    }
}
```

Note: The scheduler needs to be started from AppState. Update AppState init to auto-start:

In `AppState.swift`, update init:

```swift
init() {
    scheduler = ScanScheduler(appState: self)
    if notificationsEnabled {
        notificationService.requestPermission()
    }
    // Start scanning after a brief delay
    Task { @MainActor [weak self] in
        try? await Task.sleep(for: .seconds(2))
        self?.startScheduledScanning()
    }
}
```

- [ ] **Step 2: Build and test the app**

```bash
swift build --target DevsecApp
swift run DevsecApp &
```

Verify:
- Menubar icon appears
- Click opens popover
- Scan runs automatically after 2 seconds
- Findings appear in popover
- Whitelist button works
- Settings window opens

- [ ] **Step 3: Commit**

```bash
git add Sources/DevsecApp/
git commit -m "feat: wire up app lifecycle with auto-start scanning"
```

---

## Task 7: FullReportView

**Files:**
- Create: `Sources/DevsecApp/Views/FullReportView.swift`
- Modify: `Sources/DevsecApp/Views/PopoverView.swift` (add "View Full Report" button)

- [ ] **Step 1: Implement FullReportView**

Create `Sources/DevsecApp/Views/FullReportView.swift`:

```swift
import SwiftUI
import DevsecCore

struct FullReportView: View {
    let findings: [Finding]
    let onWhitelist: (Finding) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Summary bar
            HStack {
                Text("\(findings.count) findings")
                    .font(.headline)
                Spacer()
                let critical = findings.filter { $0.severity == .critical }.count
                let high = findings.filter { $0.severity == .high }.count
                if critical > 0 {
                    Text("\(critical) critical")
                        .foregroundColor(.red)
                        .font(.caption)
                        .bold()
                }
                if high > 0 {
                    Text("\(high) high")
                        .foregroundColor(.orange)
                        .font(.caption)
                        .bold()
                }
            }
            .padding()

            Divider()

            // Scrollable findings list
            List(findings) { finding in
                VStack(alignment: .leading, spacing: 4) {
                    FindingRow(finding: finding) {
                        onWhitelist(finding)
                    }

                    // Extra detail in full report
                    HStack(spacing: 12) {
                        Label("Git: \(finding.gitRisk.rawValue)", systemImage: "arrow.triangle.branch")
                        Label("Local: \(finding.localRisk.rawValue)", systemImage: "lock.shield")
                    }
                    .font(.caption2)
                    .foregroundColor(.secondary)

                    Text(finding.recommendation)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .lineLimit(3)

                    Text("ID: \(finding.id)")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                .padding(.vertical, 4)
            }
        }
        .frame(minWidth: 500, minHeight: 400)
    }
}
```

- [ ] **Step 2: Add "View Full Report" button to PopoverView**

In `PopoverView.swift`, add a state variable and button before the actions section:

Add `@State private var showingFullReport = false` to PopoverView.

In the actions section, add a "View Full Report" button that opens a new window:

```swift
Button {
    showingFullReport = true
} label: {
    HStack {
        Image(systemName: "doc.text")
        Text("View Full Report")
        Spacer()
    }
}
.buttonStyle(.borderless)
.padding(.horizontal, 12)
.padding(.vertical, 6)
.sheet(isPresented: $showingFullReport) {
    if let result = appState.lastScanResult {
        FullReportView(findings: result.findings) { finding in
            appState.whitelistFinding(finding)
        }
    }
}
```

- [ ] **Step 3: Verify it builds**

```bash
swift build --target DevsecApp
```

- [ ] **Step 4: Commit**

```bash
git add Sources/DevsecApp/Views/
git commit -m "feat: add full report view with detailed findings"
```

---

## Task 8: Build, Test, and Polish

- [ ] **Step 1: Build the release binary**

```bash
swift build -c release --target DevsecApp
```

- [ ] **Step 2: Run and verify the app manually**

```bash
.build/release/DevsecApp &
```

Test:
- Menubar icon appears
- Scan runs on startup
- Popover shows module summary and findings
- Whitelist button removes findings
- Settings window opens (cmd+,)
- Module toggles work
- Scan interval picker works
- "Scan Now" button works
- "View Full Report" opens detail view
- Quit works

- [ ] **Step 3: Fix any issues found**

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "fix: polish menubar app after manual testing"
```

- [ ] **Step 5: Push**

```bash
git push
```
