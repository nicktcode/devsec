import SwiftUI
import DevsecCore

// MARK: - ModuleSummaryRow

struct ModuleSummaryRow: View {
    let result: ScanResult

    var body: some View {
        HStack(spacing: 6) {
            if result.findings.isEmpty {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.caption)
                Text(moduleLabel)
                    .font(.system(.caption, design: .monospaced))
                Spacer()
                Text("ok")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            } else {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.caption)
                Text(moduleLabel)
                    .font(.system(.caption, design: .monospaced))
                Spacer()
                Text("\(result.findings.count)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.orange)
            }
        }
    }

    private var moduleLabel: String {
        switch result.module {
        case .env:             return "Env Files"
        case .history:         return "History"
        case .ssh:             return "SSH Keys"
        case .documents:       return "Documents"
        case .aiTools:         return "AI Tools"
        case .credentialFiles: return "Credentials"
        default:               return result.module.rawValue
        }
    }
}
