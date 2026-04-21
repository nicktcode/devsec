import Foundation

// MARK: - HistoryScanner

/// Scans shell history files for hardcoded secrets in commands.
///
/// Shell history files can contain API keys, tokens, and passwords passed as
/// command-line arguments. These are stored in plaintext and are accessible to
/// any process with read access to the home directory.
public struct HistoryScanner: Scanner {

    public init() {}

    // MARK: - Scanner Protocol

    public var module: ScanModule { .history }

    public func scan(onProgress: ScanProgressHandler? = nil) async throws -> ScanResult {
        let start = Date()
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // Known history file locations
        let knownPaths = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.sh_history",
        ]

        // Discover additional history files via Spotlight glob
        onProgress?("Discovering history files")
        let discovered = await SpotlightEngine.findFiles(matchingGlob: "*_history", searchPath: home)

        // Deduplicate
        var seen = Set<String>()
        var allPaths: [String] = []
        for path in knownPaths + discovered {
            if seen.insert(path).inserted {
                allPaths.append(path)
            }
        }

        // Only include files that actually exist
        let fm = FileManager.default
        let existingPaths = allPaths.filter { fm.fileExists(atPath: $0) }

        onProgress?("Found \(existingPaths.count) history files")

        var allFindings: [Finding] = []
        var offloadedPaths: [String] = []
        for (i, path) in existingPaths.enumerated() {
            let filename = (path as NSString).lastPathComponent
            let dir = ((path as NSString).deletingLastPathComponent as NSString).lastPathComponent
            onProgress?("[\(i+1)/\(existingPaths.count)] \(dir)/\(filename)")
            let outcome = HistoryScanner.scanFileDetailed(at: path)
            allFindings.append(contentsOf: outcome.findings)
            if outcome.skipped == .cloudPlaceholder {
                offloadedPaths.append(path)
            }
        }

        let duration = Date().timeIntervalSince(start)
        return ScanResult(
            module: .history,
            findings: allFindings,
            duration: duration,
            offloadedPaths: offloadedPaths
        )
    }

    // MARK: - Static File Scanner

    public struct FileScanOutcome: Sendable {
        public let findings: [Finding]
        public let skipped: SafeFileReader.SkipReason?
    }

    /// Back-compat wrapper. Prefer ``scanFileDetailed(at:)``.
    public static func scanFile(at path: String) -> [Finding] {
        scanFileDetailed(at: path).findings
    }

    /// Maximum detailed findings per (history file, pattern) pair. Without
    /// this, a shell history full of the same kind of token (e.g. twenty
    /// `heroku auth:token XXXX` invocations) produces twenty separate cards
    /// that drown out everything else. Extra occurrences roll up into a
    /// single summary card.
    private static let perPatternCapPerFile: Int = 3

    /// Reads a history file via ``SafeFileReader`` (latin1 fallback handled there),
    /// strips zsh timestamps, and scans each line for secrets.
    public static func scanFileDetailed(at path: String) -> FileScanOutcome {
        var findings: [Finding] = []
        var countsByPattern: [String: Int] = [:]
        var firstLineByPattern: [String: Int] = [:]
        let filename = (path as NSString).lastPathComponent

        let summary = SafeFileReader.forEachLine(at: path) { rawLine, lineNumber in
            let command = stripZshTimestamp(rawLine)
            guard !command.isEmpty else { return }

            let matches = PatternDatabase.findSecrets(in: command)
            guard !matches.isEmpty else { return }

            for match in matches {
                let count = (countsByPattern[match.patternName] ?? 0) + 1
                countsByPattern[match.patternName] = count
                if firstLineByPattern[match.patternName] == nil {
                    firstLineByPattern[match.patternName] = lineNumber
                }

                // Keep counting past the cap so the rollup card is accurate,
                // but stop emitting detailed cards.
                guard count <= HistoryScanner.perPatternCapPerFile else { continue }

                // Include preview8 in the ID so two truly distinct tokens
                // on adjacent lines still end up as distinct findings.
                let preview8 = String(match.matchedText.prefix(8))
                let findingId = "history:\(path):\(match.patternName):\(preview8):\(lineNumber)"

                let finding = Finding(
                    id: findingId,
                    module: .history,
                    severity: .high,
                    gitRisk: .none,
                    localRisk: .high,
                    filePath: path,
                    lineNumber: lineNumber,
                    description: "\(match.patternName) found in shell history",
                    secretPreview: PatternDatabase.maskSecret(match.matchedText),
                    recommendation: "Remove this secret from your shell history. Run: sed -i '' '\(lineNumber)d' \(path)",
                    isNew: true
                )

                findings.append(finding)
            }
        }

        // Emit one rollup card per pattern that exceeded the cap.
        for (pattern, total) in countsByPattern
        where total > HistoryScanner.perPatternCapPerFile {
            let extra = total - HistoryScanner.perPatternCapPerFile
            let firstLine = firstLineByPattern[pattern] ?? 0
            findings.append(Finding(
                id: "history:\(path):\(pattern):rollup",
                module: .history,
                severity: .high,
                gitRisk: .none,
                localRisk: .high,
                filePath: path,
                lineNumber: firstLine,
                description: "+\(extra) more \(pattern) matches in \(filename)",
                secretPreview: "",
                recommendation: "This history file has \(total) \(pattern) hits. Clear them in bulk: grep -vE 'pattern' \(path) > \(path).cleaned && mv \(path).cleaned \(path).",
                isNew: true
            ))
        }

        return FileScanOutcome(findings: findings, skipped: summary.skipped)
    }

    // MARK: - Private Helpers

    /// Strips the zsh extended history timestamp prefix.
    /// Zsh stores entries as ": <timestamp>:<elapsed>;<command>" when EXTENDED_HISTORY is set.
    /// This function strips the prefix and returns the bare command.
    static func stripZshTimestamp(_ line: String) -> String {
        // Pattern: ": <digits>:<digits>;<rest>"
        let pattern = #"^:\s*\d+:\d+;"#
        if let range = line.range(of: pattern, options: .regularExpression) {
            return String(line[range.upperBound...])
        }
        return line
    }
}
