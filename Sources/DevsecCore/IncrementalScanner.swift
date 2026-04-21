import Foundation

// MARK: - IncrementalScanner

/// Routes individual file paths to the right per-file scanner so that
/// FSEvents-triggered scans don't need to re-walk the whole home
/// directory. Each `onChange` callback from ``FileSystemWatcher``
/// delivers a deduplicated list of paths; we scan just those, which
/// typically takes 20-100ms instead of the 2-5 seconds a full scan
/// costs.
///
/// Routing rules, in order of specificity:
///  1. Anything under `~/.ssh/` goes to ``SSHScanner``.
///  2. Shell history filenames (`_history` suffix) go to ``HistoryScanner``.
///  3. `.env*` filenames go to ``EnvFileScanner``.
///  4. Files that ``CredentialFileScanner`` claims (by filename or
///     extension) go to it.
///  5. Files inside known AI-tool config directories go to
///     ``AIToolScanner``.
///  6. Everything else falls through to ``DocumentScanner``.
///
/// Paths matched by ``BuiltInScanExclusions`` or ``ScanExclusions`` are
/// rejected before routing. same filtering the full scan applies.
public enum IncrementalScanner {

    // MARK: - Public API

    /// Scans `paths` using the appropriate per-file scanner for each.
    /// Returns the union of findings across all paths. Excluded paths
    /// produce zero findings rather than an error.
    public static func scanPaths(_ paths: [String]) -> [Finding] {
        var findings: [Finding] = []
        for path in paths {
            findings.append(contentsOf: scanOne(path))
        }
        return findings
    }

    /// Quick check: does damit have any scanner that would ever pick
    /// this path up? Used by the watcher to short-circuit events for
    /// paths we'd immediately drop anyway (e.g. a binary cache file).
    public static func isScanCandidate(_ path: String) -> Bool {
        if BuiltInScanExclusions.isExcluded(path) { return false }
        if ScanExclusions.isExcluded(path) { return false }
        return true
    }

    // MARK: - Routing

    private static func scanOne(_ path: String) -> [Finding] {
        // Exclusions first. same filter the full scan applies so the
        // incremental path doesn't create findings the full scan would
        // immediately drop on the next scheduled pass.
        guard FileManager.default.fileExists(atPath: path) else { return [] }
        if BuiltInScanExclusions.isExcluded(path) { return [] }
        if ScanExclusions.isExcluded(path) { return [] }

        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let filename = (path as NSString).lastPathComponent.lowercased()

        // 1. ~/.ssh/ → SSHScanner
        if path.hasPrefix(home + "/.ssh/") {
            return SSHScanner.scanKeyFileDetailed(at: path).findings
        }

        // 2. Shell history
        if filename.hasSuffix("_history")
            || filename == ".zsh_history"
            || filename == ".bash_history"
            || filename == ".sh_history" {
            return HistoryScanner.scanFileDetailed(at: path).findings
        }

        // 3. .env files
        if filename == ".env" || filename.hasPrefix(".env.") || filename.hasSuffix(".env") {
            return EnvFileScanner.scanFileDetailed(at: path).findings
        }

        // 4. Credential files. the scanner's own `scanFile` returns
        //    empty for anything that doesn't match its filename/ext
        //    rules, so we can call it unconditionally on non-routed
        //    paths as a cheap pre-filter.
        let credFindings = CredentialFileScanner.scanFile(at: path)
        if !credFindings.isEmpty {
            return credFindings
        }

        // 5. AI-tool configs. route paths inside known tool
        //    directories. Naming convention matches AIToolScanner's
        //    own discovery heuristics.
        if let aiFindings = maybeScanAsAITool(path: path, filename: filename, home: home) {
            return aiFindings
        }

        // 6. Fall through → DocumentScanner handles everything else.
        //    Its own shouldSkip() rejects build outputs, binaries, and
        //    anything too large.
        return DocumentScanner.scanFileDetailed(at: path).findings
    }

    /// AI-tool routing. Matches paths inside the canonical locations
    /// for Cursor, Continue, Claude Code, Aider, and Codeium.
    private static func maybeScanAsAITool(path: String, filename: String, home: String) -> [Finding]? {
        struct Tool {
            let name: String
            let pathFragments: [String]
            let filenames: [String]
        }
        let tools: [Tool] = [
            Tool(name: "Cursor",
                 pathFragments: ["/Application Support/Cursor/"],
                 filenames: ["mcp.json", "settings.json"]),
            Tool(name: "Continue",
                 pathFragments: ["/.continue/"],
                 filenames: ["config.json", "config.yaml"]),
            Tool(name: "Claude Code",
                 pathFragments: ["/.claude/"],
                 filenames: ["claude.json", "settings.json", "CLAUDE.md"]),
            Tool(name: "Aider",
                 pathFragments: ["/.config/aider/", "/.aider/"],
                 filenames: [".aider.conf.yml", "config.yml"]),
            Tool(name: "Codeium",
                 pathFragments: ["/.codeium/"],
                 filenames: ["config.json"]),
        ]
        for tool in tools {
            let pathHit = tool.pathFragments.contains { path.contains($0) }
            let nameHit = tool.filenames.contains { filename == $0.lowercased() }
            if pathHit || nameHit {
                return AIToolScanner.scanConfigFile(at: path, toolName: tool.name)
            }
        }
        return nil
    }
}
