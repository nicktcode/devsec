import SwiftUI
import DevsecCore

// MARK: - FullReportView

struct FullReportView: View {
    @ObservedObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerBar

            Divider()
                .padding(.horizontal, 16)

            contentArea
        }
        .frame(minWidth: 520, minHeight: 440)
        .background(VisualEffectBackground())
    }

    // MARK: - Header

    private var headerBar: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Security Report")
                    .font(.system(size: 15, weight: .bold))
                    .foregroundColor(.primary)

                if let result = appState.lastScanResult {
                    Text("Scanned in \(String(format: "%.1f", result.totalDuration))s")
                        .font(.system(size: 10))
                        .foregroundColor(.secondary.opacity(0.6))
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
                    .foregroundColor(.secondary)
                    .frame(width: 24, height: 24)
                    .background(Color.primary.opacity(0.08))
                    .clipShape(Circle())
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private func summaryPills(result: FullScanResult) -> some View {
        HStack(spacing: 6) {
            statPill(count: result.findings.count, label: "Total", color: .secondary)

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
                .foregroundColor(color)
            Text(label)
                .font(.system(size: 9))
                .foregroundColor(.secondary.opacity(0.6))
        }
        .padding(.horizontal, 5)
        .padding(.vertical, 1)
        .background(Capsule().fill(color.opacity(0.12)))
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
                    FindingDetailCard(finding: finding) {
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
                .foregroundColor(.green.opacity(0.6))
            Text("All clear")
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(.primary)
            Text("No security findings detected.")
                .font(.system(size: 12))
                .foregroundColor(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var noDataState: some View {
        VStack(spacing: 8) {
            Spacer()
            Image(systemName: "shield")
                .font(.system(size: 36))
                .foregroundColor(.secondary.opacity(0.6))
            Text("No scan results")
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(.primary)
            Text("Run a scan to see your security report.")
                .font(.system(size: 12))
                .foregroundColor(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - FindingDetailCard

private struct FindingDetailCard: View {
    let finding: Finding
    let onWhitelist: () -> Void

    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                // Top row: severity + module + new indicator + whitelist
                HStack(spacing: 6) {
                    Text(finding.severity.rawValue.uppercased())
                        .font(.system(size: 10, weight: .bold, design: .rounded))
                        .foregroundColor(severityColor)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(severityColor.opacity(0.12)))

                    Text(finding.module.rawValue)
                        .font(.system(size: 9))
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(Color.primary.opacity(0.08)))

                    if finding.isNew {
                        Circle()
                            .fill(Color.blue)
                            .frame(width: 6, height: 6)
                    }

                    Spacer()

                    Button(action: onWhitelist) {
                        Image(systemName: "eye.slash")
                            .font(.system(size: 11))
                            .foregroundColor(isHovered ? .primary : .secondary.opacity(0.6))
                    }
                    .buttonStyle(.plain)
                    .onHover { hovering in isHovered = hovering }
                    .help("Whitelist this finding")
                }

                // File path
                if let path = finding.filePath {
                    HStack(spacing: 4) {
                        Text(abbreviatedPath(path))
                            .font(.system(size: 10, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .foregroundColor(.secondary.opacity(0.6))

                        if let line = finding.lineNumber {
                            Text(":\(line)")
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.secondary.opacity(0.4))
                        }
                    }
                }

                // Description
                Text(finding.description)
                    .font(.system(size: 11))
                    .foregroundColor(.primary.opacity(0.85))
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
                    .foregroundColor(.secondary.opacity(0.6))
                    .fixedSize(horizontal: false, vertical: true)

                // Finding ID
                Text(finding.id)
                    .font(.system(size: 8, design: .monospaced))
                    .foregroundColor(.secondary.opacity(0.3))
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .padding(.leading, 10)
            .padding(.trailing, 4)
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(Color.primary.opacity(0.1), lineWidth: 0.5)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.clear)
                .overlay(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 2)
                        .fill(severityColor)
                        .frame(width: 3)
                        .padding(.vertical, 4)
                }
                .clipShape(RoundedRectangle(cornerRadius: 8))
        )
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
                .foregroundColor(.secondary.opacity(0.6))
            Text(level.rawValue.capitalized)
                .font(.system(size: 9, weight: .medium))
                .foregroundColor(riskColor(level))
        }
    }

    private func riskColor(_ level: RiskLevel) -> Color {
        switch level {
        case .none:     return .secondary.opacity(0.4)
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
