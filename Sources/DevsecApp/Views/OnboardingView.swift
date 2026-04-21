import SwiftUI
import AppKit
import DevsecCore

// MARK: - OnboardingView

/// First-run (and re-openable) onboarding that walks the user through
/// macOS privacy permissions in one place instead of letting them trickle
/// out during scans.
///
/// Per-permission rows show the current granted/denied state with a
/// matching icon. A "Grant" button opens the correct System Settings
/// pane; when the user tabs back to damit we re-poll and update. The
/// window can also be reached later from Settings → Permissions.
struct OnboardingView: View {
    @Environment(\.dismissWindow) private var dismissWindow
    @ObservedObject var appState: AppState

    /// Re-polled when the view appears, when the window becomes key (user
    /// returned from System Settings), and when a Recheck button is
    /// pressed. Kept as a dictionary so the layout is declarative.
    @State private var statuses: [PermissionsStore.Permission: PermissionsStore.Status] = [:]
    @State private var refreshTimer: Timer? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(PermissionsStore.Permission.allCases) { perm in
                        permissionRow(perm)
                    }
                }
                .padding(16)
            }
            Divider()
            footer
        }
        .frame(width: 520, height: 440)
        .onAppear {
            refreshAll()
            startWindowFocusPolling()
        }
        .onDisappear {
            refreshTimer?.invalidate()
            refreshTimer = nil
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 28))
                .foregroundStyle(.tint)

            VStack(alignment: .leading, spacing: 3) {
                Text("Set up damit")
                    .font(.title3.bold())
                Text("damit scans your home directory for exposed credentials. Grant the permissions below once and scanning works silently after that.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()
        }
        .padding(16)
    }

    // MARK: - Permission Row

    @ViewBuilder
    private func permissionRow(_ perm: PermissionsStore.Permission) -> some View {
        let status = statuses[perm] ?? .notDetermined

        HStack(alignment: .top, spacing: 12) {
            statusIcon(for: status)
                .frame(width: 20, height: 20)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(perm.displayTitle)
                        .font(.headline)
                    if perm.isRequiredBaseline {
                        Text("recommended")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Capsule().fill(Color.primary.opacity(0.08)))
                    } else {
                        Text("optional")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Capsule().fill(Color.primary.opacity(0.08)))
                    }
                }

                Text(perm.displaySummary)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if status == .granted {
                    Text("Granted.")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.green)
                } else {
                    HStack(spacing: 8) {
                        Button(grantButtonTitle(for: perm, status: status)) {
                            grant(perm)
                        }
                        .controlSize(.small)

                        Button("Re-check") {
                            refresh(perm)
                        }
                        .controlSize(.small)
                        .buttonStyle(.borderless)
                    }
                    .padding(.top, 2)
                }
            }

            Spacer()
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.primary.opacity(0.04))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(
                    status == .granted
                        ? Color.green.opacity(0.25)
                        : Color.orange.opacity(0.35),
                    lineWidth: 0.8
                )
        )
    }

    @ViewBuilder
    private func statusIcon(for status: PermissionsStore.Status) -> some View {
        switch status {
        case .granted:
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 18))
                .foregroundStyle(.green)
        case .denied:
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 18))
                .foregroundStyle(.orange)
        case .notDetermined:
            Image(systemName: "questionmark.circle.fill")
                .font(.system(size: 18))
                .foregroundStyle(.secondary)
        }
    }

    private func grantButtonTitle(for perm: PermissionsStore.Permission, status: PermissionsStore.Status) -> String {
        switch perm {
        case .fullDiskAccess:
            return "Open System Settings"
        case .appleNotesAutomation:
            return status == .notDetermined ? "Request Access" : "Open System Settings"
        }
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            Button("Re-check All") {
                refreshAll()
            }
            Spacer()
            Button("Done") {
                OnboardingState.markCompleted()
                dismissWindow(id: "onboarding")
            }
            .keyboardShortcut(.defaultAction)
        }
        .padding(12)
    }

    // MARK: - Actions

    private func refreshAll() {
        for perm in PermissionsStore.Permission.allCases {
            statuses[perm] = PermissionsStore.status(for: perm)
        }
    }

    private func refresh(_ perm: PermissionsStore.Permission) {
        statuses[perm] = PermissionsStore.status(for: perm)
    }

    private func grant(_ perm: PermissionsStore.Permission) {
        switch perm {
        case .appleNotesAutomation where statuses[perm] == .notDetermined:
            // First-time Notes access: the probe itself triggers the
            // native TCC prompt. Run it on a background task so the
            // onboarding window stays responsive.
            Task.detached(priority: .userInitiated) {
                _ = AppleNotesScanner.requestAccess()
                await MainActor.run { refresh(perm) }
            }
        default:
            if let url = PermissionsStore.settingsURL(for: perm) {
                NSWorkspace.shared.open(url)
            }
        }
    }

    /// Polls the permission statuses every 2 seconds while the window is
    /// visible. That's enough to pick up a user who granted FDA in
    /// System Settings and tabbed back to damit. System Settings
    /// doesn't notify us, but the poll closes the loop invisibly.
    private func startWindowFocusPolling() {
        refreshTimer?.invalidate()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
            Task { @MainActor in refreshAll() }
        }
    }
}

// MARK: - OnboardingState

/// "Has the user completed onboarding?" backed by UserDefaults.
/// Public so the app-level scene logic can read it to decide whether to
/// auto-open the onboarding window on launch.
public enum OnboardingState {
    private static let key = "damit.onboarding.completed"

    public static var isCompleted: Bool {
        UserDefaults.standard.bool(forKey: key)
    }

    public static func markCompleted() {
        UserDefaults.standard.set(true, forKey: key)
    }

    public static func reset() {
        UserDefaults.standard.removeObject(forKey: key)
    }
}
