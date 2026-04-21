import Foundation

// MARK: - PermissionsStore

/// Runtime queries + launch-helpers for the macOS privacy permissions
/// damit actually needs to do its job.
///
/// macOS doesn't expose a "request all permissions" API. each permission
/// fires the first time you touch the underlying resource. Worse, **Full
/// Disk Access can't be requested via a runtime prompt at all**: it's a
/// deliberate Apple-enforced manual step in System Settings.
///
/// Given that, the best UX is:
///  1. Detect current status without triggering a prompt.
///  2. Tell the user exactly what's missing, in one onboarding screen.
///  3. Open the right System Settings pane for them to flip the toggle.
///  4. Re-check when the user returns to damit.
///
/// This module provides (1), (3), and (4). The UI layer owns (2).
public enum PermissionsStore {

    // MARK: - Permission

    public enum Permission: String, Sendable, Hashable, Identifiable, CaseIterable {
        /// Full Disk Access. Required to scan `~/Library/Application
        /// Support/*` for the AI-tool and credential-file scanners (Cursor
        /// configs, Arc/Chrome/Firefox profiles, Charles keystores, etc.).
        /// Without FDA, those paths return permission-denied silently.
        case fullDiskAccess
        /// Apple Events → Notes. Required only if the user opted into the
        /// Apple Notes module.
        case appleNotesAutomation

        public var id: String { rawValue }

        public var displayTitle: String {
            switch self {
            case .fullDiskAccess:        return "Full Disk Access"
            case .appleNotesAutomation:  return "Apple Notes"
            }
        }

        public var displaySummary: String {
            switch self {
            case .fullDiskAccess:
                return "Lets damit scan every folder under your home directory in one pass. Without this you'd get a separate macOS prompt per folder during every scan."
            case .appleNotesAutomation:
                return "Lets damit read your unlocked Apple Notes to detect pasted API keys, wallet phrases, and passwords. Locked notes are never touched."
            }
        }

        /// Whether the permission is required for damit to be useful, or
        /// only needed when the user opts into a specific module. FDA is
        /// strongly recommended but not strictly required; Notes is only
        /// relevant when the Notes module is on.
        public var isRequiredBaseline: Bool {
            self == .fullDiskAccess
        }
    }

    // MARK: - Status

    public enum Status: String, Sendable, Hashable {
        case granted
        case denied
        /// The user hasn't answered yet. either they've never triggered
        /// the prompt, or the underlying permission has no "denied" state
        /// that damit can observe without prompting.
        case notDetermined
    }

    // MARK: - Query

    public static func status(for permission: Permission) -> Status {
        switch permission {
        case .fullDiskAccess:        return fullDiskAccessStatus()
        case .appleNotesAutomation:  return notesAutomationStatus()
        }
    }

    // MARK: - System Settings Deep Links

    /// URL for opening the relevant System Settings pane so the user
    /// can flip the permission toggle. Safe to call on both Ventura+
    /// ("System Settings") and older macOS ("System Preferences"). the
    /// x-apple.systempreferences scheme is stable across both.
    public static func settingsURL(for permission: Permission) -> URL? {
        switch permission {
        case .fullDiskAccess:
            return URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles")
                ?? URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
        case .appleNotesAutomation:
            return URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Automation")
                ?? URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Automation")
        }
    }

    // MARK: - FDA Detection

    /// Full Disk Access is detected by attempting to read a file that is
    /// only accessible under FDA. We use `~/Library/Application
    /// Support/com.apple.TCC/TCC.db` because:
    ///  - It exists on every Mac (TCC itself depends on it).
    ///  - Reading it requires FDA regardless of app signature.
    ///  - The read attempt does not produce a TCC prompt. it silently
    ///    fails with EPERM when FDA isn't granted, which is exactly what
    ///    we want for non-intrusive status polling.
    private static func fullDiskAccessStatus() -> Status {
        let home = NSHomeDirectory()
        // Probe a menu of FDA-gated paths. macOS gates reads to any of
        // these behind Full Disk Access, so a single successful open
        // is proof the permission is granted. Using multiple probes
        // avoids false negatives when one specific file happens to be
        // missing on this Mac (Safari uninstalled, Mail never run).
        let probes = [
            "\(home)/Library/Application Support/com.apple.TCC/TCC.db",
            "\(home)/Library/Safari/Bookmarks.plist",
            "\(home)/Library/Messages/chat.db",
            "\(home)/Library/Mail",
        ]
        for path in probes {
            let fd = open(path, O_RDONLY)
            if fd >= 0 {
                close(fd)
                return .granted
            }
            // ENOENT just means this Mac doesn't have that file (no
            // Safari bookmarks yet, for example). Keep looking.
            // EPERM / EACCES = TCC denied; also keep looking in case
            // another probe is reachable.
        }
        return .denied
    }

    // MARK: - Notes Automation Detection

    /// Notes Automation status is trickier. macOS doesn't expose an
    /// API to query it without potentially triggering a prompt. Best
    /// reliable option: run a minimal JXA probe and translate the
    /// `JXAResult` back into our ``Status``.
    ///
    /// If the user has never been prompted, this call *will* surface the
    /// prompt. That's acceptable because the onboarding UI invokes this
    /// lazily in response to a user action ("Grant Apple Notes").
    private static func notesAutomationStatus() -> Status {
        switch AppleNotesScanner.runJXA(script: "Application('Notes').notes().length;") {
        case .success:          return .granted
        case .permissionDenied: return .denied
        case .failure:          return .notDetermined
        }
    }
}
