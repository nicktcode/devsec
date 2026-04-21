import Foundation

// MARK: - EnvFileScanner

/// Scans .env files discovered via Spotlight for hardcoded secrets.
///
/// Just being in .gitignore does not make a secret safe. local compromise risk
/// remains high. EnvFileScanner surfaces both git and local risk for each finding.
public struct EnvFileScanner: Scanner {

    public init() {}

    // MARK: - Scanner Protocol

    public var module: ScanModule { .env }

    public func scan(onProgress: ScanProgressHandler? = nil) async throws -> ScanResult {
        let start = Date()

        onProgress?("Discovering .env files")
        async let exactMatches = SpotlightEngine.findFiles(named: ".env")
        async let globMatches = SpotlightEngine.findFiles(matchingGlob: ".env.*")

        let (exact, glob) = await (exactMatches, globMatches)

        var seen = Set<String>()
        var paths: [String] = []
        for path in exact + glob {
            if seen.insert(path).inserted {
                paths.append(path)
            }
        }

        onProgress?("Found \(paths.count) env files")

        var allFindings: [Finding] = []
        var offloadedPaths: [String] = []
        for (i, path) in paths.enumerated() {
            let filename = (path as NSString).lastPathComponent
            let dir = ((path as NSString).deletingLastPathComponent as NSString).lastPathComponent
            onProgress?("[\(i+1)/\(paths.count)] \(dir)/\(filename)")
            let outcome = EnvFileScanner.scanFileDetailed(at: path)
            allFindings.append(contentsOf: outcome.findings)
            if outcome.skipped == .cloudPlaceholder {
                offloadedPaths.append(path)
            }
        }

        let duration = Date().timeIntervalSince(start)
        return ScanResult(
            module: .env,
            findings: allFindings,
            duration: duration,
            offloadedPaths: offloadedPaths
        )
    }

    // MARK: - Static File Scanner

    /// Outcome of scanning a single file: findings plus optional skip reason.
    public struct FileScanOutcome: Sendable {
        public let findings: [Finding]
        public let skipped: SafeFileReader.SkipReason?
    }

    /// Parses a single .env file and returns findings for any secrets detected.
    /// Back-compat wrapper around ``scanFileDetailed(at:)``.
    public static func scanFile(at path: String) -> [Finding] {
        scanFileDetailed(at: path).findings
    }

    /// Parses a single .env file and returns findings plus a skip reason if the
    /// file was not processed. Goes through ``SafeFileReader`` so iCloud
    /// placeholders are skipped without triggering downloads.
    public static func scanFileDetailed(at path: String) -> FileScanOutcome {
        let isIgnored = checkGitignore(filePath: path)
        var findings: [Finding] = []

        let summary = SafeFileReader.forEachLine(at: path) { rawLine, lineNumber in
            let line = rawLine.trimmingCharacters(in: .whitespaces)

            // Skip empty lines
            guard !line.isEmpty else { return }

            // Skip comment lines
            guard !line.hasPrefix("#") else { return }

            // Skip lines that use 1Password op:// references
            guard !line.contains("op://") else { return }

            // Parse KEY=VALUE format
            let (_, value) = parseLine(line)

            // Build the text to scan: run patterns against the full line so
            // inline patterns (e.g. connection strings) are also caught, but
            // strip quotes from the value portion first so quoted secrets match.
            let scanLine: String
            if let strippedValue = value {
                let stripped = stripQuotes(strippedValue)
                // Reconstruct the line with the stripped value for pattern matching
                if let eqRange = line.range(of: "=") {
                    let key = String(line[line.startIndex..<eqRange.lowerBound])
                    scanLine = key + "=" + stripped
                } else {
                    scanLine = stripped
                }
            } else {
                scanLine = line
            }

            let matches = PatternDatabase.findSecrets(in: scanLine)
            guard !matches.isEmpty else { return }

            for match in matches {
                let assessment = RiskClassifier.classify(
                    secretValue: match.matchedText,
                    filePath: path,
                    isInGitignore: isIgnored
                )

                let findingId = "env:\(path):\(lineNumber):\(match.patternName)"

                let finding = Finding(
                    id: findingId,
                    module: .env,
                    severity: assessment.severity,
                    gitRisk: assessment.gitRisk,
                    localRisk: assessment.localRisk,
                    filePath: path,
                    lineNumber: lineNumber,
                    description: "\(match.patternName) found in \(URL(fileURLWithPath: path).lastPathComponent)",
                    secretPreview: PatternDatabase.maskSecret(match.matchedText),
                    recommendation: assessment.recommendation,
                    isNew: true
                )

                findings.append(finding)
            }
        }

        return FileScanOutcome(findings: findings, skipped: summary.skipped)
    }

    // MARK: - Private Helpers

    /// Parses a KEY=VALUE line and returns the key and value (both optional).
    private static func parseLine(_ line: String) -> (key: String?, value: String?) {
        guard let eqRange = line.range(of: "=") else {
            return (nil, nil)
        }
        let key = String(line[line.startIndex..<eqRange.lowerBound])
        let value = String(line[eqRange.upperBound...])
        return (key, value)
    }

    /// Removes surrounding single or double quotes from a string.
    private static func stripQuotes(_ value: String) -> String {
        let v = value.trimmingCharacters(in: .whitespaces)
        if v.count >= 2 {
            if (v.hasPrefix("\"") && v.hasSuffix("\"")) ||
               (v.hasPrefix("'") && v.hasSuffix("'")) {
                return String(v.dropFirst().dropLast())
            }
        }
        return v
    }

    /// Checks whether a file is tracked by .gitignore.
    /// Walks up directories from the file to find a .git folder, then runs
    /// `git check-ignore -q` against the file. Returns true if ignored.
    private static func checkGitignore(filePath: String) -> Bool {
        let fileURL = URL(fileURLWithPath: filePath)
        var dir = fileURL.deletingLastPathComponent()

        // Walk upward to find .git directory (max 20 levels to avoid runaway)
        var gitRoot: URL?
        for _ in 0..<20 {
            let gitDir = dir.appendingPathComponent(".git")
            if FileManager.default.fileExists(atPath: gitDir.path) {
                gitRoot = dir
                break
            }
            let parent = dir.deletingLastPathComponent()
            guard parent.path != dir.path else { break }
            dir = parent
        }

        guard gitRoot != nil else {
            // No git repository found; treat as not ignored
            return false
        }

        let result = SpotlightEngine.runProcess(
            "/usr/bin/git",
            arguments: ["check-ignore", "-q", filePath]
        )
        // Exit code 0 means the file is ignored
        return result.exitCode == 0
    }

}
