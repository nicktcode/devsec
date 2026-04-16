import SwiftUI

// MARK: - MenuBarIcon

struct MenuBarIcon: View {
    let status: ScanStatus

    var body: some View {
        Image(systemName: symbolName)
            .symbolRenderingMode(.hierarchical)
    }

    private var symbolName: String {
        switch status {
        case .idle:
            return "shield"
        case .scanning:
            return "shield.lefthalf.filled"
        case .clean:
            return "shield.fill"
        case .warnings:
            return "shield.fill"
        case .critical:
            return "exclamationmark.shield.fill"
        }
    }
}
