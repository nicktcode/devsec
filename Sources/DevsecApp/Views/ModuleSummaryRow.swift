import SwiftUI
import DevsecCore

// MARK: - ModuleSummaryRow

struct ModuleSummaryRow: View {
    let result: ScanResult

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: moduleIcon)
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(result.findings.isEmpty ? Color.secondary : badgeColor)
                .frame(width: 20, alignment: .center)

            Text(moduleLabel)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(Color.white.opacity(0.85))

            Spacer()

            if result.findings.isEmpty {
                Image(systemName: "checkmark")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Color.green.opacity(0.8))
            } else {
                Text("\(result.findings.count)")
                    .font(.system(size: 11, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .frame(minWidth: 20)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 2)
                    .background(badgeColor.opacity(0.85))
                    .clipShape(Capsule())
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
