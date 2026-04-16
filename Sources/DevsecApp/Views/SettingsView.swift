import SwiftUI
import LaunchAtLogin
import DevsecCore

// MARK: - SettingsView

struct SettingsView: View {
    @ObservedObject var appState: AppState

    var body: some View {
        TabView {
            GeneralTab(appState: appState)
                .tabItem { Label("General", systemImage: "gear") }

            ModulesTab(appState: appState)
                .tabItem { Label("Modules", systemImage: "square.grid.2x2") }

            WhitelistTab()
                .tabItem { Label("Whitelist", systemImage: "list.bullet.indent") }
        }
        .frame(width: 450, height: 320)
    }
}

// MARK: - GeneralTab

private struct GeneralTab: View {
    @ObservedObject var appState: AppState

    private let intervalOptions: [(label: String, value: TimeInterval)] = [
        ("1 minute",   60),
        ("5 minutes",  300),
        ("15 minutes", 900),
        ("30 minutes", 1800),
        ("1 hour",     3600),
    ]

    var body: some View {
        Form {
            Picker("Scan Interval", selection: $appState.scanInterval) {
                ForEach(intervalOptions, id: \.value) { option in
                    Text(option.label).tag(option.value)
                }
            }
            .pickerStyle(.menu)

            Toggle("Enable Notifications", isOn: $appState.notificationsEnabled)

            LaunchAtLogin.Toggle("Launch at Login")
        }
        .padding()
    }
}

// MARK: - ModulesTab

private struct ModulesTab: View {
    @ObservedObject var appState: AppState

    var body: some View {
        Form {
            ForEach(ScanModule.allCases, id: \.self) { module in
                Toggle(moduleLabel(module), isOn: Binding(
                    get: { appState.enabledModules.contains(module) },
                    set: { enabled in
                        if enabled {
                            appState.enabledModules.insert(module)
                        } else {
                            appState.enabledModules.remove(module)
                        }
                    }
                ))
            }
        }
        .padding()
    }

    private func moduleLabel(_ module: ScanModule) -> String {
        switch module {
        case .env:             return "Env Files"
        case .history:         return "Shell History"
        case .ssh:             return "SSH Keys"
        case .documents:       return "Documents"
        case .aiTools:         return "AI Tools"
        case .credentialFiles: return "Credential Files"
        default:               return module.rawValue.capitalized
        }
    }
}

// MARK: - WhitelistTab

private struct WhitelistTab: View {
    @State private var whitelist = WhitelistManager()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if whitelist.allFindings.isEmpty {
                Spacer()
                Text("No whitelisted findings")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
                Spacer()
            } else {
                List {
                    ForEach(whitelist.allFindings, id: \.self) { findingId in
                        HStack {
                            Text(findingId)
                                .font(.system(.caption, design: .monospaced))
                                .lineLimit(1)
                                .truncationMode(.middle)

                            Spacer()

                            Button("Remove") {
                                whitelist.removeFinding(findingId)
                                try? whitelist.save()
                            }
                            .buttonStyle(.borderless)
                            .foregroundStyle(.red)
                            .font(.caption)
                        }
                    }
                }
            }
        }
        .padding(.vertical, 8)
    }
}
