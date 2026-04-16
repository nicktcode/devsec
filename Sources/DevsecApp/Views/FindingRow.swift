import SwiftUI
import DevsecCore

// MARK: - FindingRow

struct FindingRow: View {
    let finding: Finding
    let onWhitelist: () -> Void

    var body: some View {
        HStack(spacing: 0) {
            // Severity accent bar
            RoundedRectangle(cornerRadius: 1.5)
                .fill(severityColor)
                .frame(width: 3)
                .padding(.vertical, 2)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(finding.severity.rawValue.uppercased())
                        .font(.system(size: 9, weight: .bold, design: .rounded))
                        .foregroundStyle(severityColor)

                    if finding.isNew {
                        Circle()
                            .fill(Color.blue)
                            .frame(width: 5, height: 5)
                    }

                    Spacer()

                    Button(action: onWhitelist) {
                        Image(systemName: "eye.slash")
                            .font(.system(size: 10))
                            .foregroundStyle(Color.white.opacity(0.35))
                    }
                    .buttonStyle(.borderless)
                    .help("Whitelist this finding")
                }

                if let path = finding.filePath {
                    Text(abbreviatedPath(path))
                        .font(.system(size: 10, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .foregroundStyle(Color.white.opacity(0.5))
                }

                Text(finding.description)
                    .font(.system(size: 11))
                    .lineLimit(2)
                    .foregroundStyle(Color.white.opacity(0.7))
            }
            .padding(.leading, 8)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Color.white.opacity(0.04))
        .clipShape(RoundedRectangle(cornerRadius: 6))
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
