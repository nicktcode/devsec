import SwiftUI
import DevsecCore

// MARK: - FullReportView

struct FullReportView: View {
    @ObservedObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    private let bg = Color(red: 0.11, green: 0.11, blue: 0.118)
    private let cardBg = Color(red: 0.173, green: 0.173, blue: 0.18)

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerBar
            Divider().background(Color.white.opacity(0.08))
            contentArea
        }
        .frame(minWidth: 520, minHeight: 440)
        .background(bg)
        .preferredColorScheme(.dark)
    }

    // MARK: - Header

    private var headerBar: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Security Report")
                    .font(.system(size: 15, weight: .bold))
                    .foregroundStyle(.white)

                if let result = appState.lastScanResult {
                    Text("Scanned in \(String(format: "%.1f", result.totalDuration))s")
                        .font(.system(size: 11))
                        .foregroundStyle(Color.white.opacity(0.4))
                }
            }

            Spacer()

            if let result = appState.lastScanResult {
                summaryPills(result: result)
            }

            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Color.white.opacity(0.5))
                    .frame(width: 24, height: 24)
                    .background(Color.white.opacity(0.08))
                    .clipShape(Circle())
            }
            .buttonStyle(.borderless)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private func summaryPills(result: FullScanResult) -> some View {
        HStack(spacing: 6) {
            statPill(count: result.findings.count, label: "Total", color: .white.opacity(0.7))

            if result.criticalCount > 0 {
                statPill(count: result.criticalCount, label: "Critical", color: .red)
            }
            if result.highCount > 0 {
                statPill(count: result.highCount, label: "High", color: .orange)
            }
            if result.mediumCount > 0 {
                statPill(count: result.mediumCount, label: "Medium", color: .yellow)
            }
            if result.newCount > 0 {
                statPill(count: result.newCount, label: "New", color: .blue)
            }
        }
    }

    private func statPill(count: Int, label: String, color: Color) -> some View {
        HStack(spacing: 3) {
            Text("\(count)")
                .font(.system(size: 12, weight: .bold, design: .rounded))
                .foregroundStyle(color)
            Text(label)
                .font(.system(size: 10))
                .foregroundStyle(Color.white.opacity(0.4))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(color.opacity(0.1))
        .clipShape(Capsule())
    }

    // MARK: - Content

    private var contentArea: some View {
        Group {
            if let result = appState.lastScanResult {
                if result.findings.isEmpty {
                    emptyState
                } else {
                    findingsList(result: result)
                }
            } else {
                noDataState
            }
        }
    }

    private func findingsList(result: FullScanResult) -> some View {
        ScrollView {
            LazyVStack(spacing: 6) {
                ForEach(result.findings) { finding in
                    FindingDetailCard(finding: finding, cardBg: cardBg) {
                        appState.whitelistFinding(finding)
                    }
                }
            }
            .padding(12)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Spacer()
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 36))
                .foregroundStyle(.green.opacity(0.6))
            Text("All clear")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white)
            Text("No security findings detected.")
                .font(.system(size: 12))
                .foregroundStyle(Color.white.opacity(0.5))
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var noDataState: some View {
        VStack(spacing: 8) {
            Spacer()
            Image(systemName: "shield")
                .font(.system(size: 36))
                .foregroundStyle(Color.white.opacity(0.3))
            Text("No scan results")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white)
            Text("Run a scan to see your security report.")
                .font(.system(size: 12))
                .foregroundStyle(Color.white.opacity(0.5))
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - FindingDetailCard

private struct FindingDetailCard: View {
    let finding: Finding
    let cardBg: Color
    let onWhitelist: () -> Void

    var body: some View {
        HStack(spacing: 0) {
            // Severity accent bar
            RoundedRectangle(cornerRadius: 2)
                .fill(severityColor)
                .frame(width: 3)
                .padding(.vertical, 4)

            VStack(alignment: .leading, spacing: 6) {
                // Top row: severity + module + new indicator + whitelist
                HStack(spacing: 6) {
                    Text(finding.severity.rawValue.uppercased())
                        .font(.system(size: 10, weight: .bold, design: .rounded))
                        .foregroundStyle(severityColor)

                    Text(finding.module.rawValue)
                        .font(.system(size: 10))
                        .foregroundStyle(Color.white.opacity(0.4))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.white.opacity(0.06))
                        .clipShape(Capsule())

                    if finding.isNew {
                        Circle()
                            .fill(Color.blue)
                            .frame(width: 5, height: 5)
                    }

                    Spacer()

                    Button(action: onWhitelist) {
                        Image(systemName: "eye.slash")
                            .font(.system(size: 11))
                            .foregroundStyle(Color.white.opacity(0.35))
                    }
                    .buttonStyle(.borderless)
                    .help("Whitelist this finding")
                }

                // File path
                if let path = finding.filePath {
                    HStack(spacing: 4) {
                        Text(abbreviatedPath(path))
                            .font(.system(size: 10, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .foregroundStyle(Color.white.opacity(0.5))

                        if let line = finding.lineNumber {
                            Text(":\(line)")
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(Color.white.opacity(0.35))
                        }
                    }
                }

                // Description
                Text(finding.description)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.white.opacity(0.75))
                    .fixedSize(horizontal: false, vertical: true)

                // Risk levels
                HStack(spacing: 12) {
                    riskLabel(title: "Git Risk", level: finding.gitRisk)
                    riskLabel(title: "Local Risk", level: finding.localRisk)
                    Spacer()
                }

                // Recommendation
                Text(finding.recommendation)
                    .font(.system(size: 10))
                    .foregroundStyle(Color.white.opacity(0.4))
                    .fixedSize(horizontal: false, vertical: true)

                // Finding ID
                Text(finding.id)
                    .font(.system(size: 8, design: .monospaced))
                    .foregroundStyle(Color.white.opacity(0.2))
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .padding(.leading, 10)
            .padding(.trailing, 4)
        }
        .padding(10)
        .background(cardBg)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - Helpers

    private var severityColor: Color {
        switch finding.severity {
        case .critical: return .red
        case .high:     return .orange
        case .medium:   return .yellow
        case .low:      return .blue
        case .info:     return .gray
        }
    }

    private func riskLabel(title: String, level: RiskLevel) -> some View {
        HStack(spacing: 3) {
            Text(title + ":")
                .font(.system(size: 9))
                .foregroundStyle(Color.white.opacity(0.35))
            Text(level.rawValue.capitalized)
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(riskColor(level))
        }
    }

    private func riskColor(_ level: RiskLevel) -> Color {
        switch level {
        case .none:     return Color.white.opacity(0.3)
        case .low:      return .blue
        case .medium:   return .yellow
        case .high:     return .orange
        case .critical: return .red
        }
    }

    private func abbreviatedPath(_ path: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if path.hasPrefix(home) {
            return "~" + path.dropFirst(home.count)
        }
        return path
    }
}
