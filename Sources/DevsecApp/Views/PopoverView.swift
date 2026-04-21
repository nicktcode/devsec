import SwiftUI
import DevsecCore

// MARK: - VisualEffectBackground

struct VisualEffectBackground: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let container = NSView()
        let effectView = NSVisualEffectView()
        effectView.material = .hudWindow
        effectView.blendingMode = .behindWindow
        effectView.state = .active
        effectView.isEmphasized = true
        effectView.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(effectView)

        let tintView = NSView()
        tintView.wantsLayer = true
        if NSApp.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua {
            tintView.layer?.backgroundColor = NSColor.black.withAlphaComponent(0.25).cgColor
        } else {
            tintView.layer?.backgroundColor = NSColor.white.withAlphaComponent(0.4).cgColor
        }
        tintView.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(tintView)

        NSLayoutConstraint.activate([
            effectView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            effectView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            effectView.topAnchor.constraint(equalTo: container.topAnchor),
            effectView.bottomAnchor.constraint(equalTo: container.bottomAnchor),
            tintView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            tintView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            tintView.topAnchor.constraint(equalTo: container.topAnchor),
            tintView.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])
        return container
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        if let tintView = nsView.subviews.last {
            tintView.wantsLayer = true
            if NSApp.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua {
                tintView.layer?.backgroundColor = NSColor.black.withAlphaComponent(0.25).cgColor
            } else {
                tintView.layer?.backgroundColor = NSColor.white.withAlphaComponent(0.4).cgColor
            }
        }
    }
}

// MARK: - PopoverView

struct PopoverView: View {
    @ObservedObject var appState: AppState
    @Environment(\.openSettings) private var openSettings
    @Environment(\.openWindow) private var openWindow
    @State private var tickAnchor: Date = .init(timeIntervalSince1970: 0)

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerSection
            permissionsBanner
            summaryCard
            moduleList
            recentFindings
            footerSection
        }
        .frame(width: 300)
        .padding(.bottom, 8)
        .onAppear {
            NSApp?.appearance = NSAppearance(named: .darkAqua)
        }
    }

    // MARK: - Permissions Banner

    /// Compact banner shown when a required permission is missing. Tapping
    /// it re-opens the onboarding window. Hidden once Full Disk Access
    /// (the one required-baseline permission) is granted; Notes is
    /// opt-in so we don't nag about it here.
    @ViewBuilder
    private var permissionsBanner: some View {
        if PermissionsStore.status(for: .fullDiskAccess) != .granted {
            Button {
                // Open damit's own Settings window with the Permissions
                // tab preselected. From there the user can decide whether
                // to open macOS System Settings (Open Settings… button)
                // or walk through the full onboarding. Goes through a
                // shared pending-tab flag on AppState instead of trying
                // to poke into SwiftUI's scene registry.
                appState.pendingSettingsTab = .permissions
                NSApp.activate(ignoringOtherApps: true)
                openSettings()
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.orange)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Full Disk Access not granted")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(.primary)
                        Text("Tap to grant in System Settings")
                            .font(.system(size: 9))
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundColor(.secondary.opacity(0.6))
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.orange.opacity(0.12))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(Color.orange.opacity(0.3), lineWidth: 0.5)
                )
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 12)
            .padding(.bottom, 8)
        }
    }

    // MARK: - Window Actions

    private func showFullReport() {
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: "full-report")
        // SwiftUI's `.defaultPosition(.center)` only fires on the very first
        // open; after that AppKit restores the saved frame, which for a
        // menubar app tends to land near a screen edge. Force-center on every
        // open. Dispatch async so the window is actually in the list by the
        // time we look for it.
        DispatchQueue.main.async {
            if let window = NSApp.windows.first(where: { $0.title == "Security Report" }) {
                window.center()
                window.makeKeyAndOrderFront(nil)
            }
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(spacing: 8) {
            Text("damit")
                .font(.system(size: 15, weight: .bold, design: .rounded))
                .foregroundColor(.primary)

            Spacer()

            statusPill
        }
        .padding(.horizontal, 16)
        .padding(.top, 14)
        .padding(.bottom, 10)
    }

    private var statusPill: some View {
        HStack(spacing: 5) {
            if appState.overallStatus == .scanning {
                ProgressView()
                    .scaleEffect(0.5)
                    .frame(width: 10, height: 10)
            } else {
                Circle()
                    .fill(statusColor)
                    .frame(width: 6, height: 6)
            }

            Text(statusText)
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(statusColor)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(Capsule().fill(statusColor.opacity(0.12)))
    }

    // MARK: - Summary Card

    private var summaryCard: some View {
        VStack(spacing: 8) {
            if appState.isScanning {
                scanningContent
            } else if let result = appState.lastScanResult {
                resultContent(result)
            } else {
                HStack {
                    Text("No scan results yet")
                        .font(.system(size: 12))
                        .foregroundColor(.secondary)
                    Spacer()
                }
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(Color.primary.opacity(0.1), lineWidth: 0.5)
        )
        .padding(.horizontal, 12)
        .padding(.bottom, 8)
    }

    private var scanningContent: some View {
        VStack(spacing: 6) {
            // Trigger reason line (FSEvents-triggered or manual scans).
            // Absent for scheduled runs so the common case stays quiet.
            if let trigger = appState.lastScanTrigger.displayText {
                HStack(spacing: 4) {
                    Image(systemName: "bolt.fill")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.blue.opacity(0.8))
                    Text(trigger)
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(.blue.opacity(0.8))
                    Spacer()
                }
            }

            HStack {
                Text(appState.scanProgress)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.primary)
                Spacer()
                Text("\(appState.completedModules)/\(appState.totalModules)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary.opacity(0.6))
            }

            // Detail line showing current activity
            if !appState.scanDetail.isEmpty {
                HStack {
                    Text(appState.scanDetail)
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                }
                .transition(.opacity)
                .animation(.easeInOut(duration: 0.2), value: appState.scanDetail)
            }

            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 2.5)
                        .fill(Color.primary.opacity(0.08))
                        .frame(height: 5)

                    RoundedRectangle(cornerRadius: 2.5)
                        .fill(Color.blue)
                        .frame(
                            width: appState.totalModules > 0
                                ? geo.size.width * CGFloat(appState.completedModules) / CGFloat(appState.totalModules)
                                : 0,
                            height: 5
                        )
                        .animation(.easeInOut(duration: 0.6), value: appState.completedModules)
                }
            }
            .frame(height: 5)
        }
    }

    private func resultContent(_ result: FullScanResult) -> some View {
        VStack(spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text("\(result.findings.count)")
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                    .foregroundColor(.primary)

                Text(result.findings.count == 1 ? "finding" : "findings")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(.secondary)

                Spacer()

                if result.newCount > 0 {
                    Text("\(result.newCount) new")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(.blue)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(Color.blue.opacity(0.12)))
                }
            }

            severityBar(result: result)
                .frame(height: 5)

            TimelineView(.periodic(from: tickAnchor, by: 1)) { _ in
                HStack {
                    if let lastScanTime = appState.lastScanTime {
                        Text("Last scan: \(timeAgo(lastScanTime))")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary.opacity(0.6))
                    }
                    Spacer()
                    Text(appState.timeUntilNextScan)
                        .font(.system(size: 10))
                        .foregroundColor(.secondary.opacity(0.6))
                }
            }

            if result.offloadedCount > 0 {
                HStack(spacing: 4) {
                    Image(systemName: "icloud.and.arrow.down")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundColor(.cyan)
                    Text("\(result.offloadedCount) in iCloud. will scan when downloaded")
                        .font(.system(size: 9))
                        .foregroundColor(.secondary.opacity(0.7))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                }
            }
        }
    }

    // MARK: - Module List

    /// Canonical display order for the module list. We show every implemented
    /// module in this order so the UI is stable. enabled modules get their
    /// scan result, disabled ones render an "Off" pill so the user can see at
    /// a glance what's opted out (e.g. Apple Notes).
    private static let displayOrder: [ScanModule] = [
        .env, .history, .ssh, .documents, .aiTools, .credentialFiles, .appleNotes,
    ]

    private var moduleList: some View {
        Group {
            if let scan = appState.lastScanResult {
                VStack(alignment: .leading, spacing: 0) {
                    Text("MODULES")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundColor(.secondary.opacity(0.6))
                        .padding(.horizontal, 14)
                        .padding(.bottom, 4)

                    // Build a stable, always-present row per implemented
                    // module. ScanResults are keyed by module so we can
                    // attach the matching one (or nil for disabled).
                    let resultsByModule = Dictionary(
                        uniqueKeysWithValues: scan.results.map { ($0.module, $0) }
                    )
                    let rows = Self.displayOrder.map { module in
                        (module: module, result: resultsByModule[module])
                    }

                    VStack(spacing: 0) {
                        ForEach(Array(rows.enumerated()), id: \.element.module) { index, row in
                            ModuleSummaryRow(
                                module: row.module,
                                result: row.result,
                                isEnabled: appState.enabledModules.contains(row.module)
                            )

                            if index < rows.count - 1 {
                                Divider()
                                    .padding(.horizontal, 16)
                            }
                        }
                    }
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .strokeBorder(Color.primary.opacity(0.1), lineWidth: 0.5)
                    )
                    .padding(.horizontal, 12)
                }
                .padding(.bottom, 8)
            }
        }
    }

    // MARK: - Severity Bar

    /// Stacked horizontal bar showing the severity breakdown of findings.
    /// Replaces the previous "fake progress" bar that confused users. this
    /// one actually encodes information (how many critical vs. high vs. the
    /// rest). If there are no findings, the bar fills green ("all clear").
    @ViewBuilder
    private func severityBar(result: FullScanResult) -> some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 2.5)
                    .fill(Color.primary.opacity(0.08))
                    .frame(height: 5)

                if result.findings.isEmpty {
                    RoundedRectangle(cornerRadius: 2.5)
                        .fill(Color.green)
                        .frame(width: geo.size.width, height: 5)
                } else {
                    let total = max(result.findings.count, 1)
                    let segments: [(Int, Color)] = [
                        (result.criticalCount, .red),
                        (result.highCount,     .orange),
                        (result.mediumCount,   .yellow),
                        (result.lowCount,      .blue),
                    ].filter { $0.0 > 0 }

                    HStack(spacing: 1) {
                        ForEach(Array(segments.enumerated()), id: \.offset) { _, seg in
                            Rectangle()
                                .fill(seg.1)
                                .frame(
                                    width: geo.size.width * CGFloat(seg.0) / CGFloat(total),
                                    height: 5
                                )
                        }
                        Spacer(minLength: 0)
                    }
                    .clipShape(RoundedRectangle(cornerRadius: 2.5))
                    .animation(.easeInOut(duration: 0.6), value: result.findings.count)
                }
            }
        }
    }

    // MARK: - Recent Findings

    /// One group of semantically-duplicate findings for the recent-findings
    /// list. The popover is a 300pt-wide space. showing three identical
    /// "Heroku API Key found in shell history" cards wastes it. We collapse
    /// by (filePath, description) and surface a "×N" chip instead.
    private struct FindingGroup: Identifiable {
        let representative: Finding
        let count: Int
        var id: String { representative.id }
    }

    /// Groups findings by (filePath, description). Preserves the input
    /// order and keeps the highest-severity / first-seen finding as the
    /// group's representative (input is already severity-sorted).
    private func groupedFindings(_ findings: [Finding]) -> [FindingGroup] {
        var indexByKey: [String: Int] = [:]
        var groups: [FindingGroup] = []
        for f in findings {
            let key = "\(f.module.rawValue)|\(f.filePath ?? "")|\(f.description)"
            if let idx = indexByKey[key] {
                groups[idx] = FindingGroup(
                    representative: groups[idx].representative,
                    count: groups[idx].count + 1
                )
            } else {
                indexByKey[key] = groups.count
                groups.append(FindingGroup(representative: f, count: 1))
            }
        }
        return groups
    }

    private var recentFindings: some View {
        Group {
            if let result = appState.lastScanResult, !result.findings.isEmpty {
                let groups = groupedFindings(result.findings)
                let topGroups = Array(groups.prefix(3))
                let shownFindingCount = topGroups.reduce(0) { $0 + $1.count }
                let remaining = result.findings.count - shownFindingCount

                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("RECENT FINDINGS")
                            .font(.system(size: 9, weight: .semibold))
                            .foregroundColor(.secondary.opacity(0.6))

                        Spacer()

                        if remaining > 0 {
                            Button {
                                showFullReport()
                            } label: {
                                Text("+\(remaining) more")
                                    .font(.system(size: 10, weight: .medium))
                                    .foregroundColor(.secondary.opacity(0.6))
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 14)

                    VStack(spacing: 4) {
                        ForEach(topGroups) { group in
                            FindingRow(
                                finding: group.representative,
                                count: group.count
                            ) {
                                appState.whitelistFinding(group.representative)
                            }
                        }
                    }
                    .padding(.horizontal, 12)
                }
                .padding(.bottom, 8)
            }
        }
    }

    // MARK: - Footer

    private var footerSection: some View {
        VStack(spacing: 8) {
            Button {
                Task {
                    appState.lastScanTrigger = .manual
                    await appState.runScan()
                }
            } label: {
                HStack(spacing: 6) {
                    if appState.isScanning {
                        ProgressView()
                            .scaleEffect(0.6)
                            .frame(width: 12, height: 12)
                    } else {
                        Image(systemName: "arrow.triangle.2.circlepath")
                            .font(.system(size: 11, weight: .semibold))
                    }
                    Text(appState.isScanning ? "Scanning" : "Scan Now")
                        .font(.system(size: 12, weight: .semibold))
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 7)
                .background(Color.primary.opacity(0.08))
                .foregroundColor(appState.isScanning ? .secondary : .primary)
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
            .buttonStyle(.plain)
            .disabled(appState.isScanning)

            // Three equal-width slots so "Full Report" is truly centered in
            // the popover width. A plain HStack + two Spacers makes the
            // middle item drift toward whichever side has a longer label.
            HStack(spacing: 0) {
                HStack {
                    Button {
                        // MenuBarExtra apps are LSUIElement. the Settings
                        // window won't come forward unless we activate first.
                        NSApp.activate(ignoringOtherApps: true)
                        openSettings()
                    } label: {
                        Image(systemName: "gearshape")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundColor(.secondary)
                            .frame(width: 22, height: 22)
                    }
                    .buttonStyle(.plain)
                    .help("Settings")
                    Spacer()
                }
                .frame(maxWidth: .infinity)

                HStack {
                    Spacer()
                    if appState.lastScanResult != nil {
                        Button {
                            showFullReport()
                        } label: {
                            Text("Full Report")
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                    Spacer()
                }
                .frame(maxWidth: .infinity)

                HStack {
                    Spacer()
                    Button {
                        NSApplication.shared.terminate(nil)
                    } label: {
                        Text("Quit")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary.opacity(0.6))
                    }
                    .buttonStyle(.plain)
                }
                .frame(maxWidth: .infinity)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Color.primary.opacity(0.04))
    }

    // MARK: - Status Helpers

    private var statusColor: Color {
        switch appState.overallStatus {
        case .clean:    return .green
        case .warnings: return .yellow
        case .critical: return .red
        case .scanning: return .blue
        case .idle:     return .gray
        }
    }

    private var statusText: String {
        switch appState.overallStatus {
        case .clean:    return "Secure"
        case .warnings: return "Warnings"
        case .critical: return "Critical"
        case .scanning: return "Scanning"
        case .idle:     return "Idle"
        }
    }

    private func timeAgo(_ date: Date) -> String {
        let elapsed = -date.timeIntervalSinceNow
        if elapsed < 60 {
            return "\(Int(elapsed))s ago"
        } else if elapsed < 3600 {
            return "\(Int(elapsed / 60))m ago"
        } else {
            return "\(Int(elapsed / 3600))h ago"
        }
    }
}
