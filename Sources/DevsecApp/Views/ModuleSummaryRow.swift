import SwiftUI
import DevsecCore

// MARK: - ModuleSummaryRow

/// One row in the popover's MODULES list.
///
/// Can render three states:
///  - **Active + findings**: icon + name + colored count badge
///  - **Active + clean**: icon + name + green checkmark
///  - **Disabled**: dimmed icon + name + "Off" pill. Lets the user see at a
///    glance which scanners are opted out (e.g. Apple Notes) without having
///    to open Settings.
struct ModuleSummaryRow: View {
    let module: ScanModule
    /// `nil` when the module did not produce a ScanResult in the most recent
    /// scan (either because it's disabled, or because it was just enabled and
    /// hasn't run yet). Use `isEnabled` to distinguish the two.
    let result: ScanResult?
    /// Whether the module is currently in ``AppState.enabledModules``. This
    /// is the authoritative source for the "Off" label. don't infer it from
    /// `result == nil` because a newly-enabled module has no result yet.
    let isEnabled: Bool

    init(module: ScanModule, result: ScanResult?, isEnabled: Bool) {
        self.module = module
        self.result = result
        self.isEnabled = isEnabled
    }

    /// Back-compat convenience for existing call sites that always had a
    /// result. Assumes the module is enabled (otherwise it wouldn't have run).
    init(result: ScanResult) {
        self.module = result.module
        self.result = result
        self.isEnabled = true
    }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: moduleIcon)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(iconColor)
                .frame(width: 20, alignment: .center)

            Text(moduleLabel)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(isEnabled ? .primary : .secondary.opacity(0.6))

            Spacer()

            trailingIndicator
        }
        .padding(.vertical, 5)
        .padding(.horizontal, 10)
    }

    // MARK: - Trailing Indicator

    @ViewBuilder
    private var trailingIndicator: some View {
        if !isEnabled {
            // Explicitly disabled. stays dim until the user toggles it on.
            Text("Off")
                .font(.system(size: 9, weight: .semibold))
                .foregroundColor(.secondary.opacity(0.6))
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(Capsule().fill(Color.primary.opacity(0.06)))
        } else if let result {
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
        } else {
            // Enabled but no scan result yet (usually because the user just
            // toggled it on and the next scan hasn't fired). Show a neutral
            // "Pending" chip so the row doesn't look like it's broken.
            Text("Pending")
                .font(.system(size: 9, weight: .semibold))
                .foregroundColor(.blue.opacity(0.8))
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(Capsule().fill(Color.blue.opacity(0.12)))
        }
    }

    // MARK: - Derived State

    private var iconColor: Color {
        if !isEnabled { return .secondary.opacity(0.35) }
        guard let result, !result.findings.isEmpty else { return .secondary }
        return badgeColor
    }

    // MARK: - Module Metadata

    private var moduleIcon: String {
        switch module {
        case .ssh:             return "lock.shield"
        case .env:             return "doc.text"
        case .history:         return "clock"
        case .documents:       return "doc.richtext"
        case .aiTools:         return "cpu"
        case .credentialFiles: return "key.fill"
        case .appleNotes:      return "note.text"
        default:               return "shield"
        }
    }

    private var moduleLabel: String {
        switch module {
        case .env:             return "Env Files"
        case .history:         return "Shell History"
        case .ssh:             return "SSH Keys"
        case .documents:       return "Documents"
        case .aiTools:         return "AI Tools"
        case .credentialFiles: return "Credentials"
        case .appleNotes:      return "Apple Notes"
        default:               return module.rawValue
        }
    }

    private var badgeColor: Color {
        guard let result else { return .secondary }
        let hasCritical = result.findings.contains { $0.severity == .critical }
        let hasHigh = result.findings.contains { $0.severity == .high }
        if hasCritical { return .red }
        if hasHigh { return .orange }
        return .yellow
    }
}
