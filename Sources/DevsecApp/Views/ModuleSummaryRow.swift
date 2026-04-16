import SwiftUI
import DevsecCore

// MARK: - ModuleSummaryRow

struct ModuleSummaryRow: View {
    let result: ScanResult

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: moduleIcon)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(result.findings.isEmpty ? .secondary : badgeColor)
                .frame(width: 20, alignment: .center)

            Text(moduleLabel)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(.primary)

            Spacer()

            if result.findings.isEmpty {
                Image(systemName: "checkmark")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(.green)
            } else {
                Text("\(result.findings.count)")
                    .font(.system(size: 10, weight: .bold, design: .rounded))
                    .foregroundColor(badgeColor)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(badgeColor.opacity(0.12)))
            }
        }
        .padding(.vertical, 5)
        .padding(.horizontal, 10)
    }

    // MARK: - Module Metadata

    private var moduleIcon: String {
        switch result.module {
        case .ssh:             return "lock.shield"
        case .env:             return "doc.text"
        case .history:         return "clock"
        case .documents:       return "doc.richtext"
        case .aiTools:         return "cpu"
        case .credentialFiles: return "key.fill"
        default:               return "shield"
        }
    }

    private var moduleLabel: String {
        switch result.module {
        case .env:             return "Env Files"
        case .history:         return "Shell History"
        case .ssh:             return "SSH Keys"
        case .documents:       return "Documents"
        case .aiTools:         return "AI Tools"
        case .credentialFiles: return "Credentials"
        default:               return result.module.rawValue
        }
    }

    private var badgeColor: Color {
        let hasCritical = result.findings.contains { $0.severity == .critical }
        let hasHigh = result.findings.contains { $0.severity == .high }
        if hasCritical { return .red }
        if hasHigh { return .orange }
        return .yellow
    }
}
