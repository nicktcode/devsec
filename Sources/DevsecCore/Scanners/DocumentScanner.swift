import Foundation

// MARK: - DocumentScanner

/// Scans document and text files for hardcoded secrets.
///
/// Uses Spotlight content queries from PatternDatabase plus keyword searches
/// to discover files that may contain credentials. Files handled by other
/// scanners (env files, history files, known config files) are filtered out.
public struct DocumentScanner: Scanner {

    public init() {}

    // MARK: - Scanner Protocol

    public var module: ScanModule { .documents }

    public func scan(onProgress: ScanProgressHandler? = nil) async throws -> ScanResult {
        let start = Date()
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // Spotlight content queries - specific API key prefixes only
        // (broad keywords like "password" match thousands of files and are too slow)
        let queries = PatternDatabase.spotlightContentQueries

        // Run all queries concurrently instead of sequentially. Each
        // NSMetadataQuery is largely I/O-bound and non-CPU-heavy, so
        // running them in parallel is ~N× faster for N queries. Progress
        // is reported by completed-query count rather than per-query
        // name, which would flicker unusefully at concurrency N.
        onProgress?("Searching [0/\(queries.count)]")
        var completed = 0
        let allPaths: [String] = await withTaskGroup(of: [String].self) { group in
            for query in queries {
                group.addTask {
                    await SpotlightEngine.findFiles(containingText: query, searchPath: home)
                }
            }
            var acc: [String] = []
            for await paths in group {
                completed += 1
                onProgress?("Searching [\(completed)/\(queries.count)]")
                acc.append(contentsOf: paths)
            }
            return acc
        }

        // Deduplicate
        var seen = Set<String>()
        var uniquePaths: [String] = []
        for path in allPaths {
            if seen.insert(path).inserted {
                uniquePaths.append(path)
            }
        }

        // Filter out files handled by other scanners
        let filteredPaths = uniquePaths.filter { !shouldSkip($0) }

        onProgress?("Found \(filteredPaths.count) files")

        // Scan files concurrently with bounded parallelism. Each scanFile is CPU-bound
        // (regex matching) plus a single disk read, so we cap at the core count to
        // avoid thrashing IO and the thread pool.
        let total = filteredPaths.count
        let concurrency = max(2, min(ProcessInfo.processInfo.activeProcessorCount, 8))

        var allFindings: [Finding] = []
        var offloadedPaths: [String] = []
        await withTaskGroup(of: (String, FileScanOutcome).self) { group in
            var iterator = filteredPaths.makeIterator()

            // Seed the group with `concurrency` in-flight tasks.
            for _ in 0..<concurrency {
                guard let path = iterator.next() else { break }
                group.addTask { (path, DocumentScanner.scanFileDetailed(at: path)) }
            }

            var completed = 0
            while let (path, outcome) = await group.next() {
                completed += 1
                allFindings.append(contentsOf: outcome.findings)
                if outcome.skipped == .cloudPlaceholder {
                    offloadedPaths.append(path)
                }

                let filename = (path as NSString).lastPathComponent
                let dir = ((path as NSString).deletingLastPathComponent as NSString).lastPathComponent
                onProgress?("[\(completed)/\(total)] \(dir)/\(filename)")

                if let next = iterator.next() {
                    group.addTask { (next, DocumentScanner.scanFileDetailed(at: next)) }
                }
            }
        }

        let duration = Date().timeIntervalSince(start)
        return ScanResult(
            module: .documents,
            findings: allFindings,
            duration: duration,
            offloadedPaths: offloadedPaths
        )
    }

    // MARK: - Static File Scanner

    /// Outcome of scanning a single file: any findings, plus the reason the file
    /// was skipped if it was not fully processed.
    public struct FileScanOutcome: Sendable {
        public let findings: [Finding]
        public let skipped: SafeFileReader.SkipReason?
    }

    /// Reads a document/text file and returns findings for any secrets detected.
    /// Back-compat wrapper around ``scanFileDetailed(at:)``.
    public static func scanFile(at path: String) -> [Finding] {
        scanFileDetailed(at: path).findings
    }

    /// Reads a document/text file and returns findings plus a skip reason if the
    /// file wasn't processed. Uses ``SafeFileReader`` for all IO, so it will
    /// transparently skip iCloud placeholders, oversized files, and binaries.
    /// Maximum individual findings per (file, pattern) pair. Files like SSH
    /// library test fixtures can contain hundreds of copies of the same
    /// pattern; emitting a card for each drowns out real findings elsewhere.
    /// Extra occurrences are rolled up into a single summary finding.
    private static let perPatternCapPerFile: Int = 3

    public static func scanFileDetailed(at path: String) -> FileScanOutcome {
        var findings: [Finding] = []
        var countsByPattern: [String: Int] = [:]
        var firstLineByPattern: [String: Int] = [:]
        var assessmentByPattern: [String: RiskClassifier.RiskAssessment] = [:]
        let filename = URL(fileURLWithPath: path).lastPathComponent

        let summary = SafeFileReader.forEachLine(at: path) { line, lineNumber in
            let matches = PatternDatabase.findSecrets(in: line)
            guard !matches.isEmpty else { return }

            for match in matches {
                let count = (countsByPattern[match.patternName] ?? 0) + 1
                countsByPattern[match.patternName] = count
                if firstLineByPattern[match.patternName] == nil {
                    firstLineByPattern[match.patternName] = lineNumber
                }

                // Only emit detailed cards up to the cap. Beyond that, we just
                // keep counting so we can produce one summary card at the end.
                guard count <= DocumentScanner.perPatternCapPerFile else { continue }

                let assessment = RiskClassifier.classify(
                    secretValue: match.matchedText,
                    filePath: path,
                    isInGitignore: false
                )
                assessmentByPattern[match.patternName] = assessment

                let preview8 = String(match.matchedText.prefix(8))
                let findingId = "doc:\(path):\(match.patternName):\(preview8)"

                let finding = Finding(
                    id: findingId,
                    module: .documents,
                    severity: assessment.severity,
                    gitRisk: assessment.gitRisk,
                    localRisk: assessment.localRisk,
                    filePath: path,
                    lineNumber: lineNumber,
                    description: "\(match.patternName) found in \(filename)",
                    secretPreview: PatternDatabase.maskSecret(match.matchedText),
                    recommendation: assessment.recommendation,
                    isNew: true
                )

                findings.append(finding)
            }
        }

        // Emit rollup cards for patterns that exceeded the per-file cap.
        for (pattern, total) in countsByPattern
        where total > DocumentScanner.perPatternCapPerFile {
            let extra = total - DocumentScanner.perPatternCapPerFile
            let firstLine = firstLineByPattern[pattern] ?? 0
            let assessment = assessmentByPattern[pattern]
            findings.append(Finding(
                id: "doc:\(path):\(pattern):rollup",
                module: .documents,
                severity: assessment?.severity ?? .medium,
                gitRisk: assessment?.gitRisk ?? .medium,
                localRisk: assessment?.localRisk ?? .medium,
                filePath: path,
                lineNumber: firstLine,
                description: "+\(extra) more \(pattern) matches in \(filename)",
                secretPreview: "",
                recommendation: "This file contains \(total) matches of \(pattern). It may be a test fixture or library file; if so, add its folder to exclusions.",
                isNew: true
            ))
        }

        return FileScanOutcome(findings: findings, skipped: summary.skipped)
    }

    // MARK: - Private Helpers

    /// Returns true if the file should be skipped because another scanner handles it,
    /// or because it lives in a build/cache directory, or because it is a known
    /// minified bundle that causes catastrophic regex backtracking.
    private func shouldSkip(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        let filename = url.lastPathComponent.lowercased()
        let ext = url.pathExtension.lowercased()

        // User-defined exclusions (Settings → Exclusions).
        if ScanExclusions.isExcluded(path) { return true }

        // Canonical built-in exclusions (node_modules, .venv, ZxcvbnData, …).
        // Centralized in BuiltInScanExclusions so the Settings UI can display
        // the same list that the scanner applies.
        if BuiltInScanExclusions.isExcluded(path) { return true }

        // Skip minified bundles and source maps. they trigger regex blowups and
        // essentially never contain real secrets worth flagging.
        if filename.hasSuffix(".min.js") || filename.hasSuffix(".min.css") { return true }
        if filename.hasSuffix(".bundle.js") { return true }
        if filename.hasPrefix("chunk-") && ext == "js" { return true }
        if ext == "map" { return true }

        // Skip env files (handled by EnvFileScanner)
        if filename == ".env" || filename.hasPrefix(".env.") { return true }
        if filename.hasSuffix(".env") { return true }

        // Skip history files (handled by HistoryScanner)
        if filename.hasSuffix("_history") { return true }

        // Skip SSH keys (handled by SSHScanner)
        if ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"].contains(filename) { return true }
        if ext == "pem" { return true }

        // Skip known config files that other scanners handle
        let knownConfigs = [".netrc", ".htpasswd", "wp-config.php"]
        if knownConfigs.contains(filename) { return true }

        // Skip binary/compiled files
        let binaryExtensions = ["o", "a", "dylib", "so", "class", "jar",
                                "zip", "tar", "gz", "bz2", "xz",
                                "png", "jpg", "jpeg", "gif", "ico", "svg",
                                "mp3", "mp4", "mov", "avi",
                                "app", "framework", "bundle"]
        if binaryExtensions.contains(ext) { return true }

        return false
    }
}
