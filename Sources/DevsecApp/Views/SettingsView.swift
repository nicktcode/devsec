import SwiftUI

// MARK: - SettingsView

struct SettingsView: View {
    @ObservedObject var appState: AppState

    var body: some View {
        Text("Settings")
            .padding()
    }
}
