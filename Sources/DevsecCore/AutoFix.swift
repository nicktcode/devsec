import Foundation

// MARK: - AutoFix

/// Actions damit can perform on the user's behalf to remediate a
/// specific finding. Kept intentionally narrow. every auto-fix is a
/// well-understood, reversible filesystem change. We never touch
/// network state, never shell-exec arbitrary strings, never delete
/// data; the only built-in fix today is `chmod 600` on an SSH private
/// key with overly broad permissions.
///
/// Callers should first check ``canAutoFix(_:)`` to decide whether to
/// show an "Apply fix" button, then call ``apply(_:)`` when the user
/// clicks it. The return value indicates success or a human-readable
/// failure reason that the UI can surface in an alert.
public enum AutoFix {

    // MARK: - Result

    public enum Result: Sendable {
        case applied(description: String)
        case unsupported
        case failed(String)
    }

    // MARK: - Capability Check

    /// Returns true when the finding has an associated auto-fix. UI
    /// should only surface the "Apply fix" affordance when this is
    /// true. everything else falls back to the recommendation text.
    public static func canAutoFix(_ finding: Finding) -> Bool {
        finding.id.hasPrefix("ssh:perms:") && finding.filePath != nil
    }

    // MARK: - Apply

    /// Dispatches to the correct fixer for the finding. Returns a
    /// structured Result so the UI can show success or surface failures
    /// (permission denied, file missing, etc.).
    public static func apply(_ finding: Finding) -> Result {
        if finding.id.hasPrefix("ssh:perms:"), let path = finding.filePath {
            return chmodSSHKey(path: path)
        }
        return .unsupported
    }

    // MARK: - Fixers

    /// chmod 600 on an SSH key file that currently has broader
    /// permissions. Uses POSIX chmod directly rather than shelling out
    /// to `/bin/chmod`. faster, and the error path is more legible.
    private static func chmodSSHKey(path: String) -> Result {
        guard FileManager.default.fileExists(atPath: path) else {
            return .failed("File no longer exists at \(path)")
        }
        let mode: mode_t = 0o600
        if chmod(path, mode) == 0 {
            return .applied(description: "Set \(path) to mode 0600 (owner read/write only).")
        }
        let err = String(cString: strerror(errno))
        return .failed("chmod 600 failed: \(err)")
    }
}
