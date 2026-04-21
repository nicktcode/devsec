import SwiftUI
import DevsecCore

@main
struct DevsecMenuBarApp: App {
    @StateObject private var appState = AppState()
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        MenuBarExtra {
            PopoverView(appState: appState)
                // The onboarding window is opened via SwiftUI's
                // openWindow environment. which is only available
                // inside a view. This bridge observes the flag on
                // AppState and calls openWindow when it flips.
                .background(OnboardingBridge(appState: appState))
        } label: {
            MenuBarIcon(
                status: appState.overallStatus,
                badgeCount: appState.alertCount
            )
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(appState: appState)
        }

        // Full Report as its own window. not a sheet on the MenuBarExtra
        // popover. A sheet inside the popover is fragile: any click near the
        // popover's edge dismisses the popover and tears down the sheet with
        // it, which makes per-card buttons (Exclude, Whitelist) unclickable.
        Window("Security Report", id: "full-report") {
            FullReportView(appState: appState)
        }
        .windowResizability(.contentSize)
        // Without an explicit default position, macOS places the window
        // wherever AppKit's window-cascade last left off. which for a
        // LSUIElement app typically lands it near a screen edge. Center it.
        .defaultPosition(.center)

        // Onboarding. Auto-opens on first launch (see AppState init);
        // also re-openable from Settings → Permissions.
        Window("Welcome to damit", id: "onboarding") {
            OnboardingView(appState: appState)
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)
    }
}

// MARK: - OnboardingBridge

/// Invisible helper view that lives inside the MenuBarExtra scene so it
/// has access to SwiftUI's `openWindow` environment. Watches
/// ``AppState/shouldPresentOnboarding`` and opens the onboarding scene
/// when it flips true, then resets it.
private struct OnboardingBridge: View {
    @ObservedObject var appState: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Color.clear
            .frame(width: 0, height: 0)
            .onChange(of: appState.shouldPresentOnboarding) { _, newValue in
                guard newValue else { return }
                NSApp.activate(ignoringOtherApps: true)
                openWindow(id: "onboarding")
                appState.shouldPresentOnboarding = false
            }
    }
}
