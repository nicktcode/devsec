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
    @State private var showingFullReport = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerSection
            summaryCard
            moduleList
            recentFindings
            footerSection
        }
        .frame(width: 300)
        .background(VisualEffectBackground())
        .padding(.bottom, 8)
        .sheet(isPresented: $showingFullReport) {
            FullReportView(appState: appState)
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(spacing: 8) {
            Text("devsec")
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
        VStack(spacing: 8) {
            HStack {
                Text(appState.scanProgress)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.primary)
                Spacer()
                Text("\(appState.completedModules)/\(appState.totalModules)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary.opacity(0.6))
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

            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 2.5)
                        .fill(Color.primary.opacity(0.08))
                        .frame(height: 5)

                    RoundedRectangle(cornerRadius: 2.5)
                        .fill(statusColor)
                        .frame(
                            width: result.findings.isEmpty
                                ? geo.size.width
                                : max(geo.size.width * 0.15, 20),
                            height: 5
                        )
                        .animation(.easeInOut(duration: 0.6), value: result.findings.count)
                }
            }
            .frame(height: 5)

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
    }

    // MARK: - Module List

    private var moduleList: some View {
        Group {
            if let result = appState.lastScanResult {
                VStack(alignment: .leading, spacing: 0) {
                    Text("MODULES")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundColor(.secondary.opacity(0.6))
                        .padding(.horizontal, 14)
                        .padding(.bottom, 4)

                    VStack(spacing: 0) {
                        ForEach(Array(result.results.enumerated()), id: \.element.module) { index, scanResult in
                            ModuleSummaryRow(result: scanResult)

                            if index < result.results.count - 1 {
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

    // MARK: - Recent Findings

    private var recentFindings: some View {
        Group {
            if let result = appState.lastScanResult, !result.findings.isEmpty {
                let topFindings = Array(result.findings.prefix(3))
                let remaining = result.findings.count - topFindings.count

                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("RECENT FINDINGS")
                            .font(.system(size: 9, weight: .semibold))
                            .foregroundColor(.secondary.opacity(0.6))

                        Spacer()

                        if remaining > 0 {
                            Button {
                                showingFullReport = true
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
                        ForEach(topFindings) { finding in
                            FindingRow(finding: finding) {
                                appState.whitelistFinding(finding)
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
                Task { await appState.runScan() }
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
                    Text(appState.isScanning ? "Scanning..." : "Scan Now")
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

            HStack {
                Button {
                    NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
                } label: {
                    Text("Settings")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)

                Spacer()

                if appState.lastScanResult != nil {
                    Button {
                        showingFullReport = true
                    } label: {
                        Text("Full Report")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)

                    Spacer()
                }

                Button {
                    NSApplication.shared.terminate(nil)
                } label: {
                    Text("Quit")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary.opacity(0.6))
                }
                .buttonStyle(.plain)
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
        case .scanning: return "Scanning..."
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
