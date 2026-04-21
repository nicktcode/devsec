import Foundation

// MARK: - SafeFileReader

/// Reads files safely for scanning.
///
/// All file-reading scanners should go through this utility instead of calling
/// `String(contentsOfFile:)` directly. It provides:
///
/// - **iCloud-aware reads.** Files that are iCloud Drive placeholders (uploaded but
///   not materialized locally) are detected and skipped *without* triggering a
///   download. This prevents damit from consuming bandwidth, re-hydrating files
///   the user explicitly evicted, or stalling on unreachable networks.
/// - **Per-file size cap.** Files larger than `maxFileSize` are skipped. This
///   protects against scanning multi-GB logs, SQL dumps, or data exports where the
///   cost exceeds the benefit. Real secret-bearing files comfortably fit in 25 MB.
/// - **Per-line length cap.** Individual lines longer than `maxLineLength` are
///   skipped. This is the primary defense against regex catastrophic backtracking
///   on minified JS/CSS bundles, base64 blobs, and other pathological single-line
///   content. All current secret patterns match within a single line, so skipping
///   oversized lines does not hide any real findings.
/// - **Binary detection.** Files whose first 4 KB contains NUL bytes are treated
///   as binary and skipped. images, archives, compiled objects, etc.
///
/// Callers use `forEachLine(at:body:)` and inspect the returned `ReadSummary` to
/// learn whether (and why) a file was skipped. iCloud placeholder skips are the
/// interesting case: the caller can record the path so the UI can tell the user
/// "N files in iCloud were not scanned", and a future scheduled scan will pick
/// them up automatically once macOS materializes them.
public enum SafeFileReader {

    // MARK: - Limits

    /// Maximum size (bytes) of a file we are willing to read. Files beyond this
    /// are skipped entirely. Chosen generously so password-manager exports, large
    /// `.bash_history`, SQL dumps, and Jupyter notebooks with embedded keys all
    /// fit. Configurable via ``ScanLimits``; default 25 MB.
    public static var maxFileSize: Int { ScanLimits.maxFileSizeBytes }

    /// Maximum length (bytes) of a single line we are willing to scan. Lines
    /// longer than this are skipped. 50 KB is an order of magnitude larger than
    /// any legitimate secret assignment and well below the multi-megabyte single
    /// lines typical of minified bundles. Configurable via ``ScanLimits``.
    public static var maxLineLength: Int { ScanLimits.maxLineLengthBytes }

    // MARK: - Outcome Types

    /// Why a file (or line) was skipped rather than scanned.
    public enum SkipReason: Sendable, Equatable {
        /// The file could not be opened (permissions, missing, encoding unreadable).
        case unreadable
        /// The file exceeded ``SafeFileReader/maxFileSize``.
        case tooLarge(size: Int)
        /// The file appears to be binary (NUL bytes in the first 4 KB).
        case binary
        /// The file is an iCloud Drive item that is not currently downloaded.
        /// Reading would trigger a network download. skipped by design.
        case cloudPlaceholder
    }

    /// Result of a call to ``forEachLine(at:body:)``.
    public struct ReadSummary: Sendable {
        /// `nil` when the file was read successfully (possibly with individual
        /// lines skipped because they exceeded ``SafeFileReader/maxLineLength``).
        /// Otherwise, the reason the file was not processed.
        public let skipped: SkipReason?

        /// Number of lines skipped because they exceeded ``SafeFileReader/maxLineLength``.
        /// Non-zero values indicate the file contained minified content or huge blobs.
        public let oversizedLinesSkipped: Int

        public init(skipped: SkipReason?, oversizedLinesSkipped: Int = 0) {
            self.skipped = skipped
            self.oversizedLinesSkipped = oversizedLinesSkipped
        }
    }

    // MARK: - iCloud Detection

    /// Returns `true` if `path` is an iCloud Drive item whose contents are not
    /// currently materialized locally. Returns `false` for non-iCloud files and
    /// for iCloud items that are already downloaded.
    ///
    /// This check uses `URLResourceKey` and does not trigger a download.
    public static func isCloudPlaceholder(path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        let keys: Set<URLResourceKey> = [
            .isUbiquitousItemKey,
            .ubiquitousItemDownloadingStatusKey,
        ]
        guard let values = try? url.resourceValues(forKeys: keys) else { return false }
        guard values.isUbiquitousItem == true else { return false }
        // Only ".notDownloaded" counts as a placeholder. ".current" and
        // ".downloaded" are both locally readable.
        return values.ubiquitousItemDownloadingStatus == .notDownloaded
    }

    // MARK: - Public API

    /// Invokes `body` for each line of the file, applying all safety guards.
    ///
    /// - Parameters:
    ///   - path: Absolute path to the file.
    ///   - body: Called for each line that passes the per-line size check, with
    ///     the line contents (terminator stripped) and a 1-based line number.
    /// - Returns: A ``ReadSummary`` describing whether the file was processed,
    ///   skipped (and why), and how many individual lines were skipped due to
    ///   length.
    @discardableResult
    public static func forEachLine(
        at path: String,
        _ body: (_ line: String, _ lineNumber: Int) -> Void
    ) -> ReadSummary {

        // 1. iCloud placeholder. don't touch it, don't download it.
        if isCloudPlaceholder(path: path) {
            return ReadSummary(skipped: .cloudPlaceholder)
        }

        // 2. Size cap via stat-equivalent attrs (does not materialize placeholders).
        if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
           let size = (attrs[.size] as? NSNumber)?.intValue,
           size > maxFileSize {
            return ReadSummary(skipped: .tooLarge(size: size))
        }

        // 3. Open handle, sniff for binary content.
        guard let handle = try? FileHandle(forReadingFrom: URL(fileURLWithPath: path)) else {
            return ReadSummary(skipped: .unreadable)
        }
        defer { try? handle.close() }

        let sniff = (try? handle.read(upToCount: 4096)) ?? Data()
        if sniff.contains(0) {
            return ReadSummary(skipped: .binary)
        }

        // 4. Read rest, decode (utf8 with latin1 fallback for legacy shell history etc).
        let rest = (try? handle.readToEnd()) ?? Data()
        let full = sniff + rest
        let text: String
        if let decoded = String(data: full, encoding: .utf8) {
            text = decoded
        } else if let decoded = String(data: full, encoding: .isoLatin1) {
            text = decoded
        } else {
            return ReadSummary(skipped: .unreadable)
        }

        // 5. Enumerate lines with per-line cap. Manual split (rather than
        // `String.enumerateLines`) because the latter takes an escaping closure,
        // which would force `body` to escape unnecessarily.
        var oversized = 0
        var lineNumber = 0
        for line in text.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" }) {
            lineNumber += 1
            if line.utf8.count > maxLineLength {
                oversized += 1
                continue
            }
            body(String(line), lineNumber)
        }

        return ReadSummary(skipped: nil, oversizedLinesSkipped: oversized)
    }

    /// Convenience wrapper that returns the entire file as a single string under
    /// the same safety guards. Oversized lines are dropped from the result.
    ///
    /// Prefer ``forEachLine(at:body:)`` when the caller already works line-by-line;
    /// this is provided for scanners that want whole-file access.
    public static func readAll(
        at path: String
    ) -> (text: String?, summary: ReadSummary) {
        var chunks: [String] = []
        chunks.reserveCapacity(64)
        let summary = forEachLine(at: path) { line, _ in
            chunks.append(line)
        }
        if summary.skipped != nil { return (nil, summary) }
        return (chunks.joined(separator: "\n"), summary)
    }
}
