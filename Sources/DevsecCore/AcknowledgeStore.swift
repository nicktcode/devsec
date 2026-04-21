import Foundation

// MARK: - AcknowledgeStore

/// Persistent set of finding IDs the user has **acknowledged**. i.e. seen,
/// accepted the local risk, and asked damit to stop counting toward the
/// menubar alert state.
///
/// Unlike ``WhitelistManager`` (which hides a finding entirely), an
/// acknowledged finding **stays visible** in the Full Report with muted
/// styling. It just doesn't contribute to the "critical / warnings / clean"
/// pill in the popover or the status color on the menubar icon.
///
/// Use case: shell history files. You can't delete `~/.zsh_history`, and
/// you know it won't get committed, but the Heroku token in there is still
/// a real local-risk finding. Acknowledge it so the menubar stops nagging
/// without losing the record of what's there.
///
/// Backed by UserDefaults (same storage strategy as ``ScanExclusions``).
public enum AcknowledgeStore {

    // MARK: - Keys

    private static let key = "damit.acknowledgedFindings"

    // MARK: - Notifications

    /// Posted whenever the acknowledged set changes, so Settings tabs
    /// displaying the list stay in sync.
    public static let didChangeNotification = Notification.Name(
        "damit.acknowledge.didChange"
    )

    // MARK: - Accessors

    /// Sorted snapshot of all acknowledged finding IDs.
    public static var ids: [String] {
        get {
            UserDefaults.standard.stringArray(forKey: key) ?? []
        }
        set {
            let unique = Array(Set(newValue)).sorted()
            UserDefaults.standard.set(unique, forKey: key)
            NotificationCenter.default.post(name: didChangeNotification, object: nil)
        }
    }

    /// Fast `Set` view for membership checks during status computation.
    public static var idSet: Set<String> {
        Set(ids)
    }

    public static func acknowledge(_ id: String) {
        var current = ids
        guard !current.contains(id) else { return }
        current.append(id)
        ids = current
    }

    public static func unacknowledge(_ id: String) {
        ids = ids.filter { $0 != id }
    }

    public static func isAcknowledged(_ id: String) -> Bool {
        idSet.contains(id)
    }
}
