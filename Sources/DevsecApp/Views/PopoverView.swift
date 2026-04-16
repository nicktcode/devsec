import SwiftUI
import DevsecCore

// MARK: - Design Constants

private enum DS {
    static let bg        = Color(red: 0.11, green: 0.11, blue: 0.118)    // #1C1C1E
    static let cardBg    = Color(red: 0.173, green: 0.173, blue: 0.18)   // #2C2C2E
    static let subtle    = Color.white.opacity(0.06)
    static let radius: CGFloat = 10
    static let cardPad: CGFloat = 12
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
        .frame(width: 320)
        .background(DS.bg)
        .preferredColorScheme(.dark)
        .sheet(isPresented: $showingFullReport) {
            FullReportView(appState: appState)
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(spacing: 8) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(statusColor)

            Text("devsec")
                .font(.system(size: 15, weight: .bold, design: .rounded))
                .foregroundStyle(.white)

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
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(statusColor)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(statusColor.opacity(0.12))
        .clipShape(Capsule())
    }

    // MARK: - Summary Card

    private var summaryCard: some View {
        VStack(spacing: 8) {
            if let result = appState.lastScanResult {
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text("\(result.findings.count)")
                        .font(.system(size: 28, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)

                    Text(result.findings.count == 1 ? "finding" : "findings")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Color.white.opacity(0.5))

                    Spacer()

                    if result.newCount > 0 {
                        Text("\(result.newCount) new")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(.blue)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .background(Color.blue.opacity(0.15))
                            .clipShape(Capsule())
                    }
                }

                // Status bar
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 2)
                            .fill(Color.white.opacity(0.08))
                            .frame(height: 4)

                        RoundedRectangle(cornerRadius: 2)
                            .fill(statusColor)
                            .frame(
                                width: result.findings.isEmpty
                                    ? geo.size.width
                                    : max(geo.size.width * 0.15, 20),
                                height: 4
                            )
                    }
                }
                .frame(height: 4)

                // Timing info
                HStack {
                    if let lastScanTime = appState.lastScanTime {
                        Text("Last scan: \(timeAgo(lastScanTime))")
                            .font(.system(size: 10))
                            .foregroundStyle(Color.white.opacity(0.4))
                    }
                    Spacer()
                    Text(appState.timeUntilNextScan)
                        .font(.system(size: 10))
                        .foregroundStyle(Color.white.opacity(0.4))
                }
            } else {
                HStack {
                    Text("No scan results yet")
                        .font(.system(size: 12))
                        .foregroundStyle(Color.white.opacity(0.5))
                    Spacer()
                }
            }
        }
        .padding(DS.cardPad)
        .background(DS.cardBg)
        .clipShape(RoundedRectangle(cornerRadius: DS.radius))
        .padding(.horizontal, 12)
        .padding(.bottom, 8)
    }

    // MARK: - Module List

    private var moduleList: some View {
        Group {
            if let result = appState.lastScanResult {
                VStack(alignment: .leading, spacing: 0) {
                    Text("MODULES")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(Color.white.opacity(0.35))
                        .padding(.horizontal, 14)
                        .padding(.bottom, 4)

                    VStack(spacing: 0) {
                        ForEach(Array(result.results.enumerated()), id: \.element.module) { index, scanResult in
                            ModuleSummaryRow(result: scanResult)

                            if index < result.results.count - 1 {
                                Divider()
                                    .background(Color.white.opacity(0.06))
                                    .padding(.horizontal, 10)
                            }
                        }
                    }
                    .background(DS.cardBg)
                    .clipShape(RoundedRectangle(cornerRadius: DS.radius))
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
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(Color.white.opacity(0.35))

                        Spacer()

                        if remaining > 0 {
                            Button {
                                showingFullReport = true
                            } label: {
                                Text("+\(remaining) more")
                                    .font(.system(size: 10, weight: .medium))
                                    .foregroundStyle(Color.white.opacity(0.35))
                            }
                            .buttonStyle(.borderless)
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
            // Scan button
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
                .background(statusColor.opacity(appState.isScanning ? 0.15 : 0.2))
                .foregroundStyle(appState.isScanning ? statusColor.opacity(0.6) : statusColor)
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
            .buttonStyle(.borderless)
            .disabled(appState.isScanning)

            // Settings / Report / Quit row
            HStack {
                Button {
                    NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
                } label: {
                    Text("Settings")
                        .font(.system(size: 11))
                        .foregroundStyle(Color.white.opacity(0.4))
                }
                .buttonStyle(.borderless)

                Spacer()

                if appState.lastScanResult != nil {
                    Button {
                        showingFullReport = true
                    } label: {
                        Text("Full Report")
                            .font(.system(size: 11))
                            .foregroundStyle(Color.white.opacity(0.4))
                    }
                    .buttonStyle(.borderless)

                    Spacer()
                }

                Button {
                    NSApplication.shared.terminate(nil)
                } label: {
                    Text("Quit")
                        .font(.system(size: 11))
                        .foregroundStyle(Color.white.opacity(0.3))
                }
                .buttonStyle(.borderless)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(DS.subtle)
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
