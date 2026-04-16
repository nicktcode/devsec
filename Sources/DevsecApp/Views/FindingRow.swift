import SwiftUI
import DevsecCore

// MARK: - FindingRow

struct FindingRow: View {
    let finding: Finding
    let onWhitelist: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                SeverityBadge(severity: finding.severity)

                if finding.isNew {
                    NewBadge()
                }

                Spacer()

                Button("Whitelist", action: onWhitelist)
                    .buttonStyle(.borderless)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let path = finding.filePath {
                Text(abbreviatedPath(path))
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .foregroundStyle(.secondary)
            }

            Text(finding.description)
                .font(.caption)
                .lineLimit(2)
                .foregroundStyle(.primary)
        }
        .padding(.vertical, 2)
    }

    private func abbreviatedPath(_ path: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if path.hasPrefix(home) {
            return "~" + path.dropFirst(home.count)
        }
        return path
    }
}

// MARK: - SeverityBadge

private struct SeverityBadge: View {
    let severity: Severity

    var body: some View {
        Text(severity.rawValue.uppercased())
            .font(.system(size: 9, weight: .semibold))
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(backgroundColor)
            .foregroundStyle(foregroundColor)
            .cornerRadius(3)
    }

    private var backgroundColor: Color {
        switch severity {
        case .critical: return Color.red.opacity(0.2)
        case .high:     return Color.orange.opacity(0.2)
        case .medium:   return Color.yellow.opacity(0.2)
        case .low:      return Color.blue.opacity(0.2)
        case .info:     return Color.gray.opacity(0.2)
        }
    }

    private var foregroundColor: Color {
        switch severity {
        case .critical: return .red
        case .high:     return .orange
        case .medium:   return Color(red: 0.6, green: 0.5, blue: 0.0)
        case .low:      return .blue
        case .info:     return .gray
        }
    }
}

// MARK: - NewBadge

private struct NewBadge: View {
    var body: some View {
        Text("NEW")
            .font(.system(size: 9, weight: .semibold))
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(Color.blue.opacity(0.2))
            .foregroundStyle(.blue)
            .cornerRadius(3)
    }
}
