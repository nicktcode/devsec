import SwiftUI
import Charts
import LaunchAtLogin
import DevsecCore

// MARK: - SettingsView

struct SettingsView: View {
    @ObservedObject var appState: AppState
    @State private var selectedTab: SettingsTab = .general

    var body: some View {
        TabView(selection: $selectedTab) {
            GeneralTab(appState: appState)
                .tabItem { Label("General", systemImage: "gear") }
                .tag(SettingsTab.general)

            ModulesTab(appState: appState)
                .tabItem { Label("Modules", systemImage: "square.grid.2x2") }
                .tag(SettingsTab.modules)

            LimitsTab()
                .tabItem { Label("Limits", systemImage: "ruler") }
                .tag(SettingsTab.limits)

            WhitelistTab(whitelist: appState.whitelist)
                .tabItem { Label("Whitelist", systemImage: "list.bullet.indent") }
                .tag(SettingsTab.whitelist)

            ExclusionsTab()
                .tabItem { Label("Exclusions", systemImage: "folder.badge.minus") }
                .tag(SettingsTab.exclusions)

            PermissionsTab(appState: appState)
                .tabItem { Label("Permissions", systemImage: "lock.shield") }
                .tag(SettingsTab.permissions)

            DiagnosticsTab(appState: appState)
                .tabItem { Label("Diagnostics", systemImage: "waveform.path.ecg") }
                .tag(SettingsTab.diagnostics)

            HistoryTab(historyStore: appState.historyStore)
                .tabItem { Label("History", systemImage: "clock.arrow.circlepath") }
                .tag(SettingsTab.history)
        }
        .frame(width: 520, height: 420)
        .onAppear {
            if let pending = appState.pendingSettingsTab {
                selectedTab = pending
                appState.pendingSettingsTab = nil
            }
        }
        // Also react mid-flight. if the window is already open and the
        // banner sets the pending tab, switch to it.
        .onChange(of: appState.pendingSettingsTab) { _, newValue in
            if let pending = newValue {
                selectedTab = pending
                appState.pendingSettingsTab = nil
            }
        }
    }
}

// MARK: - Shared Row Components

/// One settings row: title on the left, optional caption below the title,
/// control aligned to the right edge of the row. Every settings tab uses
/// this to produce a visually consistent list of rows where controls
/// line up regardless of label width.
private struct SettingsRow<Trailing: View>: View {
    let title: String
    let subtitle: String?
    @ViewBuilder let trailing: () -> Trailing

    init(_ title: String, subtitle: String? = nil, @ViewBuilder trailing: @escaping () -> Trailing) {
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .medium))
                if let subtitle {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            trailing()
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 12)
    }
}

/// Grouped container for a list of ``SettingsRow`` views. Draws a single
/// rounded border around the rows with dividers between them. the
/// native-ish macOS grouped-form look.
private struct SettingsSection<Content: View>: View {
    let header: String?
    let footer: String?
    @ViewBuilder let content: () -> Content

    init(
        header: String? = nil,
        footer: String? = nil,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.header = header
        self.footer = footer
        self.content = content
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let header {
                Text(header.uppercased())
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 2)
            }
            _VariadicDividerStack {
                content()
            }
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color.primary.opacity(0.03))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(Color.primary.opacity(0.1), lineWidth: 0.5)
            )
            if let footer {
                Text(footer)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 2)
            }
        }
    }
}

/// Internal helper that inserts a hairline divider between each direct
/// subview of a variadic content closure. Keeps ``SettingsSection``
/// clean. callers just stack rows without worrying about separators.
private struct _VariadicDividerStack<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        _VariadicView.Tree(DividerLayout()) {
            content()
        }
    }

    private struct DividerLayout: _VariadicView.UnaryViewRoot {
        func body(children: _VariadicView.Children) -> some View {
            VStack(spacing: 0) {
                ForEach(Array(children.enumerated()), id: \.offset) { idx, child in
                    child
                    if idx < children.count - 1 {
                        Divider()
                            .padding(.horizontal, 12)
                    }
                }
            }
        }
    }
}

// MARK: - GeneralTab

private struct GeneralTab: View {
    @ObservedObject var appState: AppState

    private let intervalOptions: [(label: String, value: TimeInterval)] = [
        ("1 minute",   60),
        ("5 minutes",  300),
        ("15 minutes", 900),
        ("30 minutes", 1800),
        ("1 hour",     3600),
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                SettingsSection(header: "Scanning") {
                    SettingsRow(
                        "Scan Interval",
                        subtitle: "How often damit re-scans your home directory in the background."
                    ) {
                        Picker("", selection: $appState.scanInterval) {
                            ForEach(intervalOptions, id: \.value) { option in
                                Text(option.label).tag(option.value)
                            }
                        }
                        .pickerStyle(.menu)
                        .labelsHidden()
                        .frame(width: 150)
                    }
                }

                SettingsSection(header: "Notifications") {
                    SettingsRow(
                        "Enable Notifications",
                        subtitle: "Send a macOS notification when new findings appear."
                    ) {
                        Toggle("", isOn: $appState.notificationsEnabled)
                            .toggleStyle(.switch)
                            .labelsHidden()
                    }
                }

                SettingsSection(header: "System") {
                    SettingsRow(
                        "Launch at Login",
                        subtitle: "Start damit automatically when you sign in."
                    ) {
                        LaunchAtLogin.Toggle("")
                            .toggleStyle(.switch)
                            .labelsHidden()
                    }
                }
            }
            .padding()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

// MARK: - ModulesTab

private struct ModulesTab: View {
    @ObservedObject var appState: AppState

    /// Modules with an actual scanner implementation. We don't surface the
    /// placeholder enum cases (git/ports/clipboard/permissions) in the UI.
    private let implementedModules: [ScanModule] = [
        .env, .history, .ssh, .documents, .aiTools, .credentialFiles, .appleNotes
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                SettingsSection(
                    header: "Scanners",
                    footer: "Turn modules off if you don't want those locations scanned. Apple Notes is off by default and requires a one-time Automation prompt."
                ) {
                    ForEach(implementedModules, id: \.self) { module in
                        SettingsRow(
                            moduleLabel(module),
                            subtitle: moduleCaption(module)
                        ) {
                            Toggle("", isOn: Binding(
                                get: { appState.enabledModules.contains(module) },
                                set: { enabled in
                                    if enabled {
                                        let wasDisabled = !appState.enabledModules.contains(module)
                                        appState.enabledModules.insert(module)
                                        // Surface the TCC Automation prompt
                                        // right when the user opts in.
                                        if module == .appleNotes && wasDisabled {
                                            Task.detached(priority: .userInitiated) {
                                                _ = AppleNotesScanner.requestAccess()
                                            }
                                        }
                                    } else {
                                        appState.enabledModules.remove(module)
                                    }
                                }
                            ))
                            .toggleStyle(.switch)
                            .labelsHidden()
                        }
                    }
                }
            }
            .padding()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func moduleLabel(_ module: ScanModule) -> String {
        switch module {
        case .env:             return "Env Files"
        case .history:         return "Shell History"
        case .ssh:             return "SSH Keys"
        case .documents:       return "Documents"
        case .aiTools:         return "AI Tools"
        case .credentialFiles: return "Credential Files"
        case .appleNotes:      return "Apple Notes"
        default:               return module.rawValue.capitalized
        }
    }

    private func moduleCaption(_ module: ScanModule) -> String? {
        switch module {
        case .env:             return "Scans .env files for exposed API keys, tokens, and passwords."
        case .history:         return "Scans ~/.zsh_history, ~/.bash_history for secrets pasted into commands."
        case .ssh:             return "Scans ~/.ssh/ and home directory for private keys + checks file permissions."
        case .documents:       return "Scans text documents in your home directory via Spotlight."
        case .aiTools:         return "Scans Cursor, Continue, Aider, and other AI tool configs for API keys."
        case .credentialFiles: return "Finds password exports, keychain dumps, and certificate files."
        case .appleNotes:      return "Opt-in. Scans unlocked Apple Notes for pasted secrets. Requires Automation permission."
        default:               return nil
        }
    }
}

// MARK: - LimitsTab

private struct LimitsTab: View {
    @State private var fileSizeMB: Double = Double(ScanLimits.maxFileSizeMB)
    @State private var lineLengthKB: Double = Double(ScanLimits.maxLineLengthKB)

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                SettingsSection(
                    header: "Scan Limits",
                    footer: "These caps protect against pathological inputs (multi-GB JSON dumps, minified bundles) that would otherwise stall the scan."
                ) {
                    limitSliderRow(
                        title: "Max file size",
                        unit: "MB",
                        value: $fileSizeMB,
                        range: ScanLimits.fileSizeRangeMB,
                        defaultValue: ScanLimits.defaultMaxFileSizeMB,
                        commit: { ScanLimits.maxFileSizeMB = Int(fileSizeMB) }
                    )

                    limitSliderRow(
                        title: "Max line length",
                        unit: "KB",
                        value: $lineLengthKB,
                        range: ScanLimits.lineLengthRangeKB,
                        defaultValue: ScanLimits.defaultMaxLineLengthKB,
                        commit: { ScanLimits.maxLineLengthKB = Int(lineLengthKB) }
                    )
                }

                HStack {
                    Spacer()
                    Button("Reset to Defaults") {
                        ScanLimits.maxFileSizeMB = ScanLimits.defaultMaxFileSizeMB
                        ScanLimits.maxLineLengthKB = ScanLimits.defaultMaxLineLengthKB
                        fileSizeMB = Double(ScanLimits.defaultMaxFileSizeMB)
                        lineLengthKB = Double(ScanLimits.defaultMaxLineLengthKB)
                    }
                }
            }
            .padding()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    /// Slider row variant of ``SettingsRow``. Layout: title on the left,
    /// current value on the right; the slider sits as a full-width
    /// second line so it has room to actually drag smoothly.
    @ViewBuilder
    private func limitSliderRow(
        title: String,
        unit: String,
        value: Binding<Double>,
        range: ClosedRange<Int>,
        defaultValue: Int,
        commit: @escaping () -> Void
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text(title)
                    .font(.system(size: 13, weight: .medium))
                Spacer(minLength: 12)
                Text("\(Int(value.wrappedValue)) \(unit)")
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .font(.system(size: 12))
            }
            Slider(
                value: value,
                in: Double(range.lowerBound)...Double(range.upperBound),
                step: 1,
                onEditingChanged: { editing in
                    if !editing { commit() }
                }
            )
            Text("Default: \(defaultValue) \(unit) · Range: \(range.lowerBound)–\(range.upperBound) \(unit)")
                .font(.caption)
                .foregroundStyle(.secondary.opacity(0.8))
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 12)
    }
}

// MARK: - WhitelistTab

private struct WhitelistTab: View {
    let whitelist: WhitelistManager
    @State private var findings: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Findings you've silenced with the bell-slash button. Remove an entry to start alerting on it again.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal)
                .padding(.top, 10)

            if findings.isEmpty {
                VStack(spacing: 4) {
                    Image(systemName: "list.bullet.indent")
                        .font(.system(size: 22))
                        .foregroundStyle(.secondary.opacity(0.5))
                    Text("No whitelisted findings")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
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
                                reload()
                            }
                            .buttonStyle(.borderless)
                            .foregroundStyle(.red)
                            .font(.caption)
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear { reload() }
    }

    private func reload() {
        findings = whitelist.allFindings
    }
}

// MARK: - PermissionsTab

/// Settings tab that mirrors the onboarding screen. same status query,
/// same grant buttons. plus a "Re-open onboarding" escape hatch for
/// users who dismissed it too quickly or want to walk through again.
private struct PermissionsTab: View {
    @ObservedObject var appState: AppState
    @Environment(\.openWindow) private var openWindow
    @State private var statuses: [PermissionsStore.Permission: PermissionsStore.Status] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("macOS privacy permissions damit uses. Grant these once and scanning runs silently after that.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ForEach(PermissionsStore.Permission.allCases) { perm in
                permissionRow(perm)
            }

            Spacer()

            HStack {
                Button("Re-check") { refresh() }
                Spacer()
                Button("Open Onboarding") {
                    NSApp.activate(ignoringOtherApps: true)
                    openWindow(id: "onboarding")
                }
            }
        }
        .padding()
        .frame(maxHeight: .infinity, alignment: .topLeading)
        .onAppear { refresh() }
    }

    @ViewBuilder
    private func permissionRow(_ perm: PermissionsStore.Permission) -> some View {
        let status = statuses[perm] ?? .notDetermined

        HStack(alignment: .top, spacing: 10) {
            Image(systemName: iconName(status))
                .font(.system(size: 15))
                .foregroundStyle(iconColor(status))
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 2) {
                Text(perm.displayTitle)
                    .font(.system(size: 12, weight: .semibold))
                Text(perm.displaySummary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()

            if status != .granted {
                Button("Open Settings") {
                    if let url = PermissionsStore.settingsURL(for: perm) {
                        NSWorkspace.shared.open(url)
                    }
                }
                .controlSize(.small)
            }
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .strokeBorder(Color.primary.opacity(0.1), lineWidth: 0.5)
        )
    }

    private func iconName(_ s: PermissionsStore.Status) -> String {
        switch s {
        case .granted:        return "checkmark.circle.fill"
        case .denied:         return "exclamationmark.triangle.fill"
        case .notDetermined:  return "questionmark.circle.fill"
        }
    }

    private func iconColor(_ s: PermissionsStore.Status) -> Color {
        switch s {
        case .granted:        return .green
        case .denied:         return .orange
        case .notDetermined:  return .secondary
        }
    }

    private func refresh() {
        for perm in PermissionsStore.Permission.allCases {
            statuses[perm] = PermissionsStore.status(for: perm)
        }
    }
}

// MARK: - ExclusionsTab

private struct ExclusionsTab: View {
    @State private var paths: [String] = []
    @State private var draft: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Folders listed here are skipped by the Documents scanner. Useful for source trees (like damit's own) where test fixtures and pattern definitions look like real secrets.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 6) {
                TextField("/absolute/path or ~/Repos/myproject", text: $draft)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { addDraft() }

                Button("Add") { addDraft() }
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                Button {
                    pickFolder()
                } label: {
                    Image(systemName: "folder")
                }
                .help("Choose a folder")
            }

            // Scrollable combined list: user-added exclusions (editable) on
            // top, canonical built-in exclusions (read-only, with reasons)
            // below. Surfacing the built-ins lets the user understand *why*
            // their node_modules / .venv / ZxcvbnData folders were skipped
            // without having to dig through source code.
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    userExclusionsSection
                    builtInExclusionsSection
                }
                .padding(.top, 4)
            }
        }
        .padding()
        .onAppear { reload() }
        // Refresh when excludeFolder() is called from elsewhere (e.g. the
        // Full Report's per-card "exclude folder" button). Without this, the
        // @State snapshot goes stale and the tab looks like nothing happened.
        .onReceive(NotificationCenter.default.publisher(
            for: ScanExclusions.didChangeNotification
        )) { _ in
            reload()
        }
    }

    // MARK: - User Exclusions Section

    @ViewBuilder
    private var userExclusionsSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("YOUR EXCLUSIONS")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.secondary)

            if paths.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "folder.badge.minus")
                        .foregroundStyle(.secondary.opacity(0.5))
                    Text("No exclusions yet. add a folder above, or use the folder button on any finding.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 8)
                .padding(.horizontal, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .strokeBorder(Color.primary.opacity(0.1), lineWidth: 0.5)
                )
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(paths.enumerated()), id: \.element) { index, path in
                        HStack {
                            Text(abbreviated(path))
                                .font(.system(.caption, design: .monospaced))
                                .lineLimit(1)
                                .truncationMode(.middle)

                            Spacer()

                            Button("Remove") {
                                ScanExclusions.remove(path)
                                reload()
                            }
                            .buttonStyle(.borderless)
                            .foregroundStyle(.red)
                            .font(.caption)
                        }
                        .padding(.vertical, 6)
                        .padding(.horizontal, 10)

                        if index < paths.count - 1 {
                            Divider()
                        }
                    }
                }
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .strokeBorder(Color.primary.opacity(0.1), lineWidth: 0.5)
                )
            }
        }
    }

    // MARK: - Built-in Exclusions Section

    @ViewBuilder
    private var builtInExclusionsSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Text("BUILT-IN EXCLUSIONS")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
                Text("always on")
                    .font(.system(size: 9))
                    .foregroundStyle(.secondary.opacity(0.6))
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.primary.opacity(0.06)))
            }

            Text("These paths are skipped by every scanner. They're known to be caches, vendored dependencies, or third-party library data that would otherwise flood the report with fake findings.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            VStack(spacing: 0) {
                let groups = BuiltInScanExclusions.rulesByCategory
                ForEach(Array(groups.enumerated()), id: \.element.category) { groupIdx, group in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(group.category.uppercased())
                            .font(.system(size: 9, weight: .semibold))
                            .foregroundStyle(.secondary.opacity(0.7))
                            .padding(.top, groupIdx == 0 ? 8 : 10)
                            .padding(.horizontal, 10)

                        ForEach(group.rules) { rule in
                            VStack(alignment: .leading, spacing: 1) {
                                HStack(spacing: 6) {
                                    Text(rule.pattern)
                                        .font(.system(.caption, design: .monospaced))
                                    if rule.kind == .componentPrefix {
                                        Text("prefix")
                                            .font(.system(size: 8, weight: .semibold))
                                            .foregroundStyle(.secondary.opacity(0.7))
                                            .padding(.horizontal, 4)
                                            .padding(.vertical, 1)
                                            .background(Capsule().fill(Color.primary.opacity(0.05)))
                                    }
                                }
                                Text(rule.reason)
                                    .font(.system(size: 10))
                                    .foregroundStyle(.secondary.opacity(0.7))
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            .padding(.vertical, 4)
                            .padding(.horizontal, 10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    if groupIdx < groups.count - 1 {
                        Divider().padding(.horizontal, 8)
                    }
                }
            }
            .padding(.bottom, 6)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .strokeBorder(Color.primary.opacity(0.1), lineWidth: 0.5)
            )
        }
    }

    private func addDraft() {
        let value = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return }
        ScanExclusions.add(value)
        draft = ""
        reload()
    }

    private func pickFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Exclude"
        if panel.runModal() == .OK, let url = panel.url {
            ScanExclusions.add(url.path)
            reload()
        }
    }

    private func reload() {
        paths = ScanExclusions.paths
    }

    private func abbreviated(_ path: String) -> String {
        let home = NSHomeDirectory()
        if path.hasPrefix(home) {
            return "~" + path.dropFirst(home.count)
        }
        return path
    }
}

// MARK: - DiagnosticsTab

/// Shows the recent file-system change events that triggered scans,
/// so users can answer "why did damit run a scan just now?". Each row
/// includes the timestamp, the number of paths in the burst, and up to
/// 5 sample paths. Paths that match ``BuiltInScanExclusions`` or the
/// user's own exclusions never reach this list. they're filtered at
/// the watcher level before the callback fires.
private struct DiagnosticsTab: View {
    @ObservedObject var appState: AppState

    private let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .none
        f.timeStyle = .medium
        return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Recent file-change events that triggered a scan. If you're seeing too many, identify the source here and add it to your Exclusions.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if appState.recentFileChanges.isEmpty {
                Spacer()
                HStack {
                    Spacer()
                    VStack(spacing: 6) {
                        Image(systemName: "waveform.path.ecg")
                            .font(.system(size: 24))
                            .foregroundStyle(.secondary.opacity(0.4))
                        Text("No file-change events recorded yet")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(appState.recentFileChanges) { event in
                            eventCard(event)
                        }
                    }
                }
            }

            HStack {
                Text("\(appState.recentFileChanges.count) events logged")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Clear") {
                    appState.recentFileChanges.removeAll()
                }
                .controlSize(.small)
                .disabled(appState.recentFileChanges.isEmpty)
            }
        }
        .padding()
        .frame(maxHeight: .infinity, alignment: .topLeading)
    }

    @ViewBuilder
    private func eventCard(_ event: AppState.FileChangeEvent) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(timeFormatter.string(from: event.timestamp))
                    .font(.system(size: 11, weight: .semibold))
                Text("·")
                    .foregroundStyle(.secondary)
                Text("\(event.totalPaths) path\(event.totalPaths == 1 ? "" : "s")")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Spacer()
            }
            ForEach(event.samplePaths, id: \.self) { path in
                Text(abbreviate(path))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(Color.primary.opacity(0.03))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .strokeBorder(Color.primary.opacity(0.08), lineWidth: 0.5)
        )
    }

    private func abbreviate(_ path: String) -> String {
        let home = NSHomeDirectory()
        return path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }
}

// MARK: - HistoryTab

private struct HistoryTab: View {
    let historyStore: ScanHistoryStore
    @State private var records: [ScanHistoryRecord] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            summaryHeader

            if records.isEmpty {
                Spacer()
                VStack(spacing: 4) {
                    Image(systemName: "chart.line.uptrend.xyaxis")
                        .font(.system(size: 22))
                        .foregroundStyle(.secondary.opacity(0.5))
                    Text("No scan history yet")
                        .foregroundStyle(.secondary)
                    Text("History records accumulate after each scan.")
                        .font(.caption)
                        .foregroundStyle(.secondary.opacity(0.7))
                }
                .frame(maxWidth: .infinity, alignment: .center)
                Spacer()
            } else {
                chartSection

                Divider()

                recentScansList
            }
        }
        .padding()
        .onAppear { reload() }
    }

    private var summaryHeader: some View {
        HStack(spacing: 16) {
            summaryTile(
                value: "\(historyStore.totalFixed)",
                label: "Secrets secured",
                color: .green,
                icon: "checkmark.shield.fill"
            )
            summaryTile(
                value: "\(records.count)",
                label: "Scans run",
                color: .blue,
                icon: "arrow.triangle.2.circlepath"
            )
            summaryTile(
                value: "\(records.last?.totalFindings ?? 0)",
                label: "Current findings",
                color: records.last?.totalFindings == 0 ? .green : .orange,
                icon: "doc.text.magnifyingglass"
            )
        }
    }

    private func summaryTile(value: String, label: String, color: Color, icon: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(color)
                Text(label.uppercased())
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(.secondary)
            }
            Text(value)
                .font(.system(size: 22, weight: .bold, design: .rounded))
                .foregroundStyle(.primary)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(color.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(color.opacity(0.2), lineWidth: 0.5)
        )
    }

    private var chartSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("FINDINGS OVER TIME")
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.secondary)

            Chart {
                ForEach(records) { record in
                    LineMark(
                        x: .value("Date", record.date),
                        y: .value("Findings", record.totalFindings)
                    )
                    .foregroundStyle(.orange)
                    .interpolationMethod(.monotone)

                    AreaMark(
                        x: .value("Date", record.date),
                        y: .value("Findings", record.totalFindings)
                    )
                    .foregroundStyle(
                        LinearGradient(
                            colors: [.orange.opacity(0.3), .orange.opacity(0.0)],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                    .interpolationMethod(.monotone)
                }
            }
            .frame(height: 120)
            .chartYAxis {
                AxisMarks(position: .leading)
            }
        }
    }

    private var recentScansList: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("RECENT SCANS")
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.secondary)

            ScrollView {
                VStack(spacing: 4) {
                    ForEach(records.reversed().prefix(20)) { record in
                        scanRow(record)
                    }
                }
            }
        }
    }

    private func scanRow(_ record: ScanHistoryRecord) -> some View {
        HStack(spacing: 8) {
            Text(record.date, format: .dateTime.month(.abbreviated).day().hour().minute())
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 110, alignment: .leading)

            Text("\(record.totalFindings) findings")
                .font(.system(size: 11))

            if record.fixedSincePrevious > 0 {
                Text("-\(record.fixedSincePrevious) fixed")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.green)
            }
            if record.newFindings > 0 {
                Text("+\(record.newFindings) new")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.blue)
            }

            Spacer()

            if record.critical > 0 {
                badge("\(record.critical)C", color: .red)
            }
            if record.high > 0 {
                badge("\(record.high)H", color: .orange)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(Color.primary.opacity(0.04))
        )
    }

    private func badge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .semibold, design: .rounded))
            .foregroundStyle(color)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(Capsule().fill(color.opacity(0.15)))
    }

    private func reload() {
        records = historyStore.allRecords
    }
}
