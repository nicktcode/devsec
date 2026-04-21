import Foundation

// MARK: - ScanLimits

/// User-configurable limits for file scanning, backed by ``UserDefaults``.
///
/// ``SafeFileReader`` consults these at runtime so settings changes take effect
/// on the next scan without requiring a restart. Defaults match the original
/// hardcoded values (25 MB / 50 KB) and are chosen to comfortably fit real
/// credential-bearing files (password exports, SQL dumps, large bash history)
/// while still bounding worst-case scan time.
public enum ScanLimits {

    // MARK: - Keys

    private static let maxFileSizeKey = "damit.scan.maxFileSizeMB"
    private static let maxLineLengthKey = "damit.scan.maxLineLengthKB"

    // MARK: - Defaults

    public static let defaultMaxFileSizeMB: Int = 25
    public static let defaultMaxLineLengthKB: Int = 50

    // MARK: - Bounds

    /// Allowed range for the per-file size cap (MB). Upper bound prevents
    /// accidentally scanning multi-GB archives.
    public static let fileSizeRangeMB: ClosedRange<Int> = 1...500

    /// Allowed range for the per-line length cap (KB). Lower bound keeps real
    /// secret patterns scannable; upper bound keeps regex backtracking bounded.
    public static let lineLengthRangeKB: ClosedRange<Int> = 4...1024

    // MARK: - Accessors

    public static var maxFileSizeMB: Int {
        get {
            let raw = UserDefaults.standard.integer(forKey: maxFileSizeKey)
            return raw == 0 ? defaultMaxFileSizeMB : clamp(raw, fileSizeRangeMB)
        }
        set {
            UserDefaults.standard.set(clamp(newValue, fileSizeRangeMB), forKey: maxFileSizeKey)
        }
    }

    public static var maxLineLengthKB: Int {
        get {
            let raw = UserDefaults.standard.integer(forKey: maxLineLengthKey)
            return raw == 0 ? defaultMaxLineLengthKB : clamp(raw, lineLengthRangeKB)
        }
        set {
            UserDefaults.standard.set(clamp(newValue, lineLengthRangeKB), forKey: maxLineLengthKey)
        }
    }

    /// Byte values derived from the MB/KB-oriented user-facing settings.
    public static var maxFileSizeBytes: Int { maxFileSizeMB * 1024 * 1024 }
    public static var maxLineLengthBytes: Int { maxLineLengthKB * 1024 }

    // MARK: - Private

    private static func clamp(_ value: Int, _ range: ClosedRange<Int>) -> Int {
        min(max(value, range.lowerBound), range.upperBound)
    }
}
