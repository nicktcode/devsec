import Foundation

// MARK: - ScanExclusions

/// User-configurable path exclusions, backed by ``UserDefaults``.
///
/// Any file whose absolute path starts with one of the stored prefixes is
/// skipped by the document scanner. Prefix matching is intentionally simple:
/// it catches both a file and every file beneath it without needing regex.
///
/// Typical uses:
///  - Developers running damit on their own dev machine want to exclude their
///    own source trees (where test fixtures and pattern definitions look like
///    real secrets).
///  - Excluding large vendored directories or external drives.
public enum ScanExclusions {

    // MARK: - Keys

    private static let key = "damit.scan.excludedPaths"

    // MARK: - Notifications

    /// Posted whenever the exclusion list is mutated. The Settings UI listens
    /// for this so the Exclusions tab stays in sync when the user clicks
    /// "exclude folder" from elsewhere (e.g. the Full Report window).
    public static let didChangeNotification = Notification.Name(
        "damit.scanExclusions.didChange"
    )

    // MARK: - Accessors

    /// The current exclusion list, as absolute paths. Normalized (trimmed,
    /// trailing slash removed) so prefix matching is predictable.
    public static var paths: [String] {
        get {
            (UserDefaults.standard.array(forKey: key) as? [String] ?? [])
                .map(normalize)
                .filter { !$0.isEmpty }
        }
        set {
            let normalized = Array(Set(newValue.map(normalize).filter { !$0.isEmpty })).sorted()
            UserDefaults.standard.set(normalized, forKey: key)
            NotificationCenter.default.post(name: didChangeNotification, object: nil)
        }
    }

    /// Adds an exclusion. No-op if already present.
    public static func add(_ path: String) {
        let p = normalize(path)
        guard !p.isEmpty else { return }
        var current = paths
        guard !current.contains(p) else { return }
        current.append(p)
        paths = current
    }

    /// Removes an exclusion. No-op if not present.
    public static func remove(_ path: String) {
        let p = normalize(path)
        paths = paths.filter { $0 != p }
    }

    /// Returns true if `filePath` lies under any excluded path.
    public static func isExcluded(_ filePath: String) -> Bool {
        let p = normalize(filePath)
        for prefix in paths {
            if p == prefix { return true }
            if p.hasPrefix(prefix + "/") { return true }
        }
        return false
    }

    // MARK: - Private

    private static func normalize(_ path: String) -> String {
        var p = path.trimmingCharacters(in: .whitespacesAndNewlines)
        // Expand a leading "~" so users can type "~/Repos/damit".
        if p.hasPrefix("~") {
            let home = NSHomeDirectory()
            p = home + String(p.dropFirst())
        }
        // Drop trailing slashes so "~/foo/" and "~/foo" compare equal.
        while p.count > 1 && p.hasSuffix("/") {
            p.removeLast()
        }
        return p
    }
}
