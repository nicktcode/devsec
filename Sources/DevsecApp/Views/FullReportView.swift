import SwiftUI
import DevsecCore

// MARK: - FullReportView

struct FullReportView: View {
    @ObservedObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Title bar
            HStack {
                Text("Full Report")
                    .font(.headline)
                Spacer()
                Button("Close") { dismiss() }
                    .buttonStyle(.borderless)
            }
            .padding()

            Divider()

            if let result = appState.lastScanResult {
                // Summary bar
                summaryBar(result: result)

                Divider()

                // Findings list
                if result.findings.isEmpty {
                    Spacer()
                    Text("No findings detected.")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                    Spacer()
                } else {
                    List(result.findings) { finding in
                        FindingDetailRow(finding: finding) {
                            appState.whitelistFinding(finding)
                        }
                    }
                    .listStyle(.plain)
                }
            } else {
                Spacer()
                Text("No scan results available. Run a scan first.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
                Spacer()
            }
        }
        .frame(minWidth: 500, minHeight: 400)
    }

    // MARK: - Summary Bar

    private func summaryBar(result: FullScanResult) -> some View {
        HStack(spacing: 16) {
            summaryPill(
                count: result.findings.count,
                label: "Total",
                color: .primary
            )

            if result.criticalCount > 0 {
                summaryPill(
                    count: result.criticalCount,
                    label: "Critical",
                    color: .red
                )
            }

            if result.highCount > 0 {
                summaryPill(
                    count: result.highCount,
                    label: "High",
                    color: .orange
                )
            }

            if result.mediumCount > 0 {
                summaryPill(
                    count: result.mediumCount,
                    label: "Medium",
                    color: .yellow
                )
            }

            if result.lowCount > 0 {
                summaryPill(
                    count: result.lowCount,
                    label: "Low",
                    color: .blue
                )
            }

            Spacer()

            if result.newCount > 0 {
                Text("\(result.newCount) new")
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Color.blue.opacity(0.15))
                    .foregroundStyle(.blue)
                    .cornerRadius(4)
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }

    private func summaryPill(count: Int, label: String, color: Color) -> some View {
        HStack(spacing: 4) {
            Text("\(count)")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(color)
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - FindingDetailRow

private struct FindingDetailRow: View {
    let finding: Finding
    let onWhitelist: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            FindingRow(finding: finding, onWhitelist: onWhitelist)

            HStack(spacing: 12) {
                riskLabel(title: "Git Risk", level: finding.gitRisk)
                riskLabel(title: "Local Risk", level: finding.localRisk)
                Spacer()
            }

            Text(finding.recommendation)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Text(finding.id)
                .font(.system(size: 9, design: .monospaced))
                .foregroundStyle(Color.gray.opacity(0.6))
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .padding(.vertical, 4)
    }

    private func riskLabel(title: String, level: RiskLevel) -> some View {
        HStack(spacing: 3) {
            Text(title + ":")
                .font(.caption2)
                .foregroundStyle(.secondary)
            Text(level.rawValue.capitalized)
                .font(.caption2.weight(.medium))
                .foregroundStyle(riskColor(level))
        }
    }

    private func riskColor(_ level: RiskLevel) -> Color {
        switch level {
        case .none:     return .secondary
        case .low:      return .blue
        case .medium:   return .yellow
        case .high:     return .orange
        case .critical: return .red
        }
    }
}
