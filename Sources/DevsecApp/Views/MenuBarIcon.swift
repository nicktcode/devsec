import SwiftUI

// MARK: - MenuBarIcon

struct MenuBarIcon: View {
    let status: ScanStatus

    var body: some View {
        Image(systemName: symbolName)
            .symbolRenderingMode(.hierarchical)
            .foregroundStyle(statusColor)
    }

    private var symbolName: String {
        switch status {
        case .clean:    return "checkmark.shield.fill"
        case .warnings: return "exclamationmark.shield.fill"
        case .critical: return "xmark.shield.fill"
        case .scanning: return "shield.lefthalf.filled"
        case .idle:     return "shield"
        }
    }

    private var statusColor: Color {
        switch status {
        case .clean:    return .green
        case .warnings: return .yellow
        case .critical: return .red
        case .scanning: return .blue
        case .idle:     return .gray
        }
    }
}
