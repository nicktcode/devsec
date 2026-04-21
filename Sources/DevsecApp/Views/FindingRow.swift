import SwiftUI
import DevsecCore

// MARK: - FindingRow

struct FindingRow: View {
    let finding: Finding
    /// How many findings this row represents. `> 1` means the popover has
    /// collapsed a group of (file, description) duplicates into a single
    /// card to keep "Recent Findings" readable. The representative finding
    /// is still passed through `finding` (highest severity wins).
    let count: Int
    let onWhitelist: () -> Void

    @State private var isHovered = false

    init(finding: Finding, count: Int = 1, onWhitelist: @escaping () -> Void) {
        self.finding = finding
        self.count = count
        self.onWhitelist = onWhitelist
    }

    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(finding.severity.rawValue.uppercased())
                        .font(.system(size: 9, weight: .bold, design: .rounded))
                        .foregroundColor(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(severityColor))

                    if count > 1 {
                        Text("×\(count)")
                            .font(.system(size: 9, weight: .bold, design: .rounded))
                            .foregroundColor(severityColor)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Capsule().fill(severityColor.opacity(0.15)))
                    }

                    if finding.isNew {
                        Circle()
                            .fill(Color.blue)
                            .frame(width: 6, height: 6)
                    }

                    Spacer()

                    Button(action: onWhitelist) {
                        Image(systemName: "bell.slash")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary.opacity(0.6))
                    }
                    .buttonStyle(.plain)
                    .onHover { hovering in isHovered = hovering }
                    .help("Whitelist. stop alerting on this finding")
                }

                if let path = finding.filePath {
                    Text(abbreviatedPath(path))
                        .font(.system(size: 10, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .foregroundColor(.secondary.opacity(0.6))
                }

                Text(finding.description)
                    .font(.caption)
                    .lineLimit(2)
                    .foregroundColor(.secondary)
            }
            .padding(.leading, 8)
            .padding(.trailing, 4)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(Color.primary.opacity(0.1), lineWidth: 0.5)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.clear)
                .overlay(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 1.5)
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

    private func abbreviatedPath(_ path: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if path.hasPrefix(home) {
            return "~" + path.dropFirst(home.count)
        }
        return path
    }
}
