import SwiftUI
import DevsecCore

// MARK: - PopoverView

struct PopoverView: View {
    @ObservedObject var appState: AppState
    @State private var showingFullReport = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            headerSection

            Divider()

            // Module summary
            if let result = appState.lastScanResult {
                moduleSummarySection(result: result)
                Divider()
            }

            // Recent findings
            if let result = appState.lastScanResult, !result.findings.isEmpty {
                recentFindingsSection(result: result)
                Divider()
            }

            // Actions
            actionsSection
        }
        .frame(width: 340)
        .sheet(isPresented: $showingFullReport) {
            FullReportView(appState: appState)
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(spacing: 8) {
            Text("devsec")
                .font(.headline)
                .fontWeight(.semibold)

            Spacer()

            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)

            Text(statusText)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

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
        case .clean:    return "All clear"
        case .warnings: return "Warnings"
        case .critical: return "Critical"
        case .scanning: return "Scanning..."
        case .idle:     return "Idle"
        }
    }

    // MARK: - Module Summary

    private func moduleSummarySection(result: FullScanResult) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(result.results, id: \.module) { scanResult in
                ModuleSummaryRow(result: scanResult)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 1)
            }

            HStack {
                if let lastScanTime = appState.lastScanTime {
                    Text("Last scan: \(timeAgo(lastScanTime))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text(appState.timeUntilNextScan)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.top, 4)
            .padding(.bottom, 6)
        }
        .padding(.top, 6)
    }

    // MARK: - Recent Findings

    private func recentFindingsSection(result: FullScanResult) -> some View {
        let topFindings = Array(result.findings.prefix(5))
        let remaining = result.findings.count - topFindings.count

        return VStack(alignment: .leading, spacing: 0) {
            Text("Recent Findings")
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 12)
                .padding(.top, 8)
                .padding(.bottom, 4)

            ForEach(topFindings) { finding in
                FindingRow(finding: finding) {
                    appState.whitelistFinding(finding)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 2)
            }

            if remaining > 0 {
                Text("+ \(remaining) more")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 12)
                    .padding(.top, 4)
            }

            Spacer(minLength: 6)
        }
    }

    // MARK: - Actions

    private var actionsSection: some View {
        VStack(spacing: 4) {
            Button {
                Task { await appState.runScan() }
            } label: {
                HStack {
                    if appState.isScanning {
                        ProgressView()
                            .scaleEffect(0.7)
                            .frame(width: 14, height: 14)
                    }
                    Text(appState.isScanning ? "Scanning..." : "Scan Now")
                }
                .frame(maxWidth: .infinity)
            }
            .disabled(appState.isScanning)
            .buttonStyle(.borderedProminent)

            if appState.lastScanResult != nil {
                Button("View Full Report") {
                    showingFullReport = true
                }
                .frame(maxWidth: .infinity)
                .buttonStyle(.bordered)
            }

            HStack {
                Button("Settings...") {
                    NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
                }
                .buttonStyle(.borderless)
                .font(.caption)

                Spacer()

                Button("Quit devsec") {
                    NSApplication.shared.terminate(nil)
                }
                .buttonStyle(.borderless)
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .padding(12)
    }

    // MARK: - Helpers

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
