import SwiftUI
import Foundation
import UniformTypeIdentifiers
import AppKit
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
        .frame(
            minWidth: 520,
            idealWidth: 680,
            maxWidth: .infinity,
            minHeight: 440,
            idealHeight: 640,
            maxHeight: .infinity
        )
        // A standalone window should be opaque. the popover's hudWindow
        // vibrancy only makes sense for a menu-attached panel. Here the content
        // sits over arbitrary desktop windows and must stay readable.
        .background(Color(NSColor.windowBackgroundColor))
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

            if let result = appState.lastScanResult, !result.findings.isEmpty {
                exportMenu(result: result)
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
            if result.offloadedCount > 0 {
                statPill(count: result.offloadedCount, label: "iCloud", color: .cyan)
            }
        }
    }

    /// Export menu with JSON / CSV options. Writes to a user-picked
    /// location via NSSavePanel so we never surprise-drop files in the
    /// home directory. Masked previews are preserved so nothing
    /// sensitive leaves the app.
    private func exportMenu(result: FullScanResult) -> some View {
        Menu {
            Button("Export as JSON") {
                export(result: result, format: .json)
            }
            Button("Export as CSV") {
                export(result: result, format: .csv)
            }
        } label: {
            Image(systemName: "square.and.arrow.up")
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(.secondary)
                .frame(width: 24, height: 24)
                .background(Color.primary.opacity(0.08))
                .clipShape(Circle())
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Export findings")
    }

    private enum ExportFormat { case json, csv }

    private func export(result: FullScanResult, format: ExportFormat) {
        let panel = NSSavePanel()
        panel.title = "Export damit findings"
        let stamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        switch format {
        case .json:
            panel.nameFieldStringValue = "damit-findings-\(stamp).json"
            panel.allowedContentTypes = [.json]
        case .csv:
            panel.nameFieldStringValue = "damit-findings-\(stamp).csv"
            panel.allowedContentTypes = [.commaSeparatedText]
        }
        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            switch format {
            case .json:
                if let data = FindingExporter.exportJSON(result.findings) {
                    try data.write(to: url, options: .atomic)
                }
            case .csv:
                let csv = FindingExporter.exportCSV(result.findings)
                try csv.data(using: .utf8)?.write(to: url, options: .atomic)
            }
        } catch {
            NSAlert(error: error).runModal()
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
        // Using List (not ScrollView+LazyVStack) for two reasons at scale:
        //   1. List is natively lazy, so rendering hundreds of cards is fast.
        //   2. List correctly measures variable-height rows, so we avoid the
        //      "ghost gap" layout jitter LazyVStack produces when rows differ
        //      in height (description/recommendation can wrap to multiple
        //      lines).
        List {
            if result.offloadedCount > 0 {
                offloadedBanner(count: result.offloadedCount)
                    .listRowSeparator(.hidden)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 6, leading: 12, bottom: 6, trailing: 12))
            }
            ForEach(result.findings) { finding in
                FindingDetailCard(
                    finding: finding,
                    isAcknowledged: AcknowledgeStore.isAcknowledged(finding.id),
                    onWhitelist: { appState.whitelistFinding(finding) },
                    onToggleAcknowledge: {
                        if AcknowledgeStore.isAcknowledged(finding.id) {
                            appState.unacknowledgeFinding(finding)
                        } else {
                            appState.acknowledgeFinding(finding)
                        }
                    },
                    onExcludeFolder: finding.filePath.map { path in
                        { appState.excludeFolder(for: path) }
                    },
                    onAutoFix: AutoFix.canAutoFix(finding) ? {
                        switch AutoFix.apply(finding) {
                        case .applied(let desc):
                            // Re-run scan so the fixed finding disappears.
                            Task { await appState.runScan() }
                            let a = NSAlert()
                            a.messageText = "Fix applied"
                            a.informativeText = desc
                            a.runModal()
                        case .failed(let msg):
                            let a = NSAlert()
                            a.alertStyle = .warning
                            a.messageText = "Couldn't apply fix"
                            a.informativeText = msg
                            a.runModal()
                        case .unsupported:
                            break
                        }
                    } : nil
                )
                .listRowSeparator(.hidden)
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets(top: 3, leading: 12, bottom: 3, trailing: 12))
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
    }

    private func offloadedBanner(count: Int) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "icloud.and.arrow.down")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.cyan)
            VStack(alignment: .leading, spacing: 2) {
                Text("\(count) file\(count == 1 ? "" : "s") in iCloud were not scanned")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(.primary)
                Text("They will be checked on the next scan once macOS downloads them locally.")
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
            }
            Spacer()
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.cyan.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(Color.cyan.opacity(0.25), lineWidth: 0.5)
        )
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
    let isAcknowledged: Bool
    let onWhitelist: () -> Void
    let onToggleAcknowledge: () -> Void
    let onExcludeFolder: (() -> Void)?
    /// When non-nil, an "Apply fix" button appears. Invoked to run an
    /// auto-remediation specific to the finding (e.g. `chmod 600` for
    /// SSH key permission issues).
    let onAutoFix: (() -> Void)?

    @State private var isHovered = false
    @State private var excludeHovered = false
    @State private var ackHovered = false
    @State private var fixHovered = false

    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                // Top row: severity + module + new indicator + whitelist
                HStack(spacing: 6) {
                    Text(finding.severity.rawValue.uppercased())
                        .font(.system(size: 10, weight: .bold, design: .rounded))
                        .foregroundColor(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(severityColor))

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

                    if let onAutoFix {
                        Button(action: onAutoFix) {
                            Image(systemName: "wand.and.stars")
                                .font(.system(size: 11))
                                .foregroundColor(fixHovered ? .green : .green.opacity(0.85))
                        }
                        .buttonStyle(.plain)
                        .onHover { hovering in fixHovered = hovering }
                        .help("Apply fix. runs the recommended action automatically")
                    }

                    if let onExcludeFolder {
                        Button(action: onExcludeFolder) {
                            Image(systemName: "folder.badge.minus")
                                .font(.system(size: 11))
                                .foregroundColor(excludeHovered ? .primary : .secondary.opacity(0.6))
                        }
                        .buttonStyle(.plain)
                        .onHover { hovering in excludeHovered = hovering }
                        .help("Exclude this folder from future scans")
                    }

                    // Acknowledge. keep the finding visible but stop it
                    // from counting toward the menubar alert state. Useful
                    // for things like shell history where you accept the
                    // local risk but know it won't be committed.
                    Button(action: onToggleAcknowledge) {
                        Image(systemName: isAcknowledged ? "checkmark.seal.fill" : "checkmark.seal")
                            .font(.system(size: 11))
                            .foregroundColor(
                                isAcknowledged
                                    ? .green
                                    : (ackHovered ? .primary : .secondary.opacity(0.6))
                            )
                    }
                    .buttonStyle(.plain)
                    .onHover { hovering in ackHovered = hovering }
                    .help(
                        isAcknowledged
                            ? "Acknowledged. click to un-acknowledge"
                            : "Acknowledge. keep visible but stop alerting"
                    )

                    Button(action: onWhitelist) {
                        Image(systemName: "bell.slash")
                            .font(.system(size: 11))
                            .foregroundColor(isHovered ? .primary : .secondary.opacity(0.6))
                    }
                    .buttonStyle(.plain)
                    .onHover { hovering in isHovered = hovering }
                    .help("Whitelist. hide this finding entirely")
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
        // Fade acknowledged cards so they read as "known / accepted" but
        // remain readable if you want to revisit them.
        .opacity(isAcknowledged ? 0.55 : 1.0)
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
