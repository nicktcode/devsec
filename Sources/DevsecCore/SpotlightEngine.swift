import Foundation

// MARK: - SpotlightEngine

/// Discovery layer for damit. Wraps macOS Spotlight (mdfind) for full-disk search
/// and falls back to find + grep when Spotlight is unavailable.
public enum SpotlightEngine: Sendable {

    // MARK: - Supporting Types

    public struct SpotlightHealth: Sendable {
        public let checked: Bool
        public let available: Bool
        public let message: String

        public init(checked: Bool, available: Bool, message: String) {
            self.checked = checked
            self.available = available
            self.message = message
        }
    }

    // ProcessResult is used internally only and never crosses isolation boundaries.
    struct ProcessResult {
        let stdout: String
        let stderr: String
        let exitCode: Int32
    }

    // MARK: - Health Check

    // Spotlight availability rarely changes during a process's lifetime.
    // Cache the mdutil probe so scanners making 15-30 Spotlight calls
    // don't spawn an mdutil subprocess for each one. that's what made
    // the Documents scan appear to hang for seconds at a time.
    private static let healthCache = HealthCache()

    private final class HealthCache: @unchecked Sendable {
        private let lock = NSLock()
        private var cached: SpotlightHealth?
        func get() -> SpotlightHealth? { lock.lock(); defer { lock.unlock() }; return cached }
        func set(_ h: SpotlightHealth) { lock.lock(); cached = h; lock.unlock() }
    }

    /// Checks whether Spotlight indexing is enabled on the root volume.
    /// Result is cached for the life of the process. Spotlight state is
    /// a system-wide setting that effectively never changes mid-run.
    public static func checkHealth() async -> SpotlightHealth {
        if let cached = healthCache.get() { return cached }
        let result = runProcess("/usr/bin/mdutil", arguments: ["-s", "/"])
        let output = result.stdout + result.stderr
        let available = output.contains("Indexing enabled")
        let message = output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "mdutil returned no output"
            : output.trimmingCharacters(in: .whitespacesAndNewlines)
        let health = SpotlightHealth(checked: true, available: available, message: message)
        healthCache.set(health)
        return health
    }

    // MARK: - Public Search API

    /// Finds files by exact filename. Uses in-process ``NSMetadataQuery``
    /// when Spotlight is available (no subprocess overhead), falls back
    /// to `find` otherwise.
    public static func findFiles(named name: String, searchPath: String? = nil) async -> [String] {
        let health = await checkHealth()
        if health.available {
            return await runMetadataQuery(
                predicateFormat: "kMDItemFSName == %@",
                predicateArg: name,
                searchPath: searchPath
            )
        }
        return await fallbackFindFiles(named: name, searchPath: searchPath)
    }

    /// Finds files matching a glob pattern. Uses in-process
    /// ``NSMetadataQuery`` when Spotlight is available, falls back to
    /// `find` otherwise. Predicate `LIKE` supports `*` and `?` wildcards
    /// the same way the Spotlight query language does.
    public static func findFiles(matchingGlob glob: String, searchPath: String? = nil) async -> [String] {
        let health = await checkHealth()
        if health.available {
            return await runMetadataQuery(
                predicateFormat: "kMDItemFSName LIKE %@",
                predicateArg: glob,
                searchPath: searchPath
            )
        }
        return await fallbackFindFiles(matchingGlob: glob, searchPath: searchPath)
    }

    /// Finds files whose content contains the given text. Uses in-process
    /// ``NSMetadataQuery`` when Spotlight is available, falls back to
    /// `grep` otherwise.
    public static func findFiles(containingText text: String, searchPath: String? = nil) async -> [String] {
        let health = await checkHealth()
        if health.available {
            return await runMetadataQuery(
                predicateFormat: "kMDItemTextContent == %@",
                predicateArg: text,
                searchPath: searchPath
            )
        }
        return await fallbackFindFiles(containingText: text, searchPath: searchPath)
    }

    // MARK: - Fallback Methods

    /// Fallback: uses `find` to locate files by exact filename.
    public static func fallbackFindFiles(named name: String, searchPath: String?) async -> [String] {
        let path = searchPath ?? defaultSearchPath()
        var args = [path, "-maxdepth", "10",
                    "-not", "-path", "*/.Trash/*",
                    "-not", "-path", "*/Library/Caches/*",
                    "-name", name]
        // Silence permission errors
        args += ["-prune", "-o", "-name", name, "-print"]
        // Simpler: just use -name directly; permission errors go to stderr (ignored)
        let simpleArgs = [path, "-maxdepth", "10",
                          "-not", "-path", "*/.Trash/*",
                          "-not", "-path", "*/Library/Caches/*",
                          "-name", name, "-print"]
        let result = runProcess("/usr/bin/find", arguments: simpleArgs)
        return parseLines(result.stdout)
    }

    /// Fallback: uses `find` to locate files matching a glob pattern.
    public static func fallbackFindFiles(matchingGlob glob: String, searchPath: String?) async -> [String] {
        let path = searchPath ?? defaultSearchPath()
        let args = [path, "-maxdepth", "10",
                    "-not", "-path", "*/.Trash/*",
                    "-not", "-path", "*/Library/Caches/*",
                    "-name", glob, "-print"]
        let result = runProcess("/usr/bin/find", arguments: args)
        return parseLines(result.stdout)
    }

    /// Fallback: uses `grep` to locate files containing the given text.
    public static func fallbackFindFiles(containingText text: String, searchPath: String?) async -> [String] {
        let path = searchPath ?? defaultSearchPath()
        // -rl: recursive, list filenames only
        // Include common text-based file extensions
        let extensions = ["txt", "env", "json", "yaml", "yml", "toml", "sh",
                          "bash", "zsh", "py", "rb", "js", "ts", "swift",
                          "go", "rs", "java", "kt", "xml", "plist", "cfg",
                          "conf", "ini", "properties", "md", "log"]
        let includeArgs = extensions.flatMap { ["--include=*.\($0)"] }
        var args = ["-rl", text, path] + includeArgs
        // Exclude trash and caches
        args += ["--exclude-dir=.Trash", "--exclude-dir=Caches"]
        let result = runProcess("/usr/bin/grep", arguments: args)
        return parseLines(result.stdout)
    }

    // MARK: - Private: NSMetadataQuery Runner

    /// In-process Spotlight query via ``NSMetadataQuery``. Replaces the
    /// previous `/usr/bin/mdfind` subprocess path, which cost ~20-50ms
    /// per call in fork+exec+pipe overhead. The Spotlight index lookup
    /// itself takes ~5-10ms, so skipping the subprocess shaves roughly
    /// 4× off every query. a substantial win across the 15+ queries
    /// per full scan.
    ///
    /// The query runs on the main actor because NSMetadataQuery requires
    /// a run loop for its notification delivery. The Spotlight daemon
    /// does the actual work off-thread, so firing 15 concurrent queries
    /// from a TaskGroup is safe. the main actor only schedules the
    /// queries and receives their completion notifications.
    /// Runs an in-process Spotlight query. Takes Sendable primitives
    /// (format + single string argument) rather than an ``NSPredicate``
    /// so the call can hop to the main actor without tripping Swift 6
    /// data-race diagnostics. ``NSPredicate`` isn't Sendable.
    static func runMetadataQuery(
        predicateFormat: String,
        predicateArg: String,
        searchPath: String?
    ) async -> [String] {
        await withCheckedContinuation { (cont: CheckedContinuation<[String], Never>) in
            Task { @MainActor in
                let predicate = NSPredicate(format: predicateFormat, predicateArg)
                let runner = MetadataQueryRunner(predicate: predicate, searchPath: searchPath)
                let paths = await runner.run()
                cont.resume(returning: paths)
            }
        }
    }

    @MainActor
    fileprivate final class MetadataQueryRunner {
        private let query = NSMetadataQuery()
        private var continuation: CheckedContinuation<[String], Never>?
        private var observer: NSObjectProtocol?

        init(predicate: NSPredicate, searchPath: String?) {
            query.predicate = predicate
            if let searchPath {
                query.searchScopes = [URL(fileURLWithPath: searchPath)]
            }
            // Notifications deliver on .main so the capture closure and
            // continuation resume are both on the main actor.
            query.operationQueue = .main
        }

        func run() async -> [String] {
            await withCheckedContinuation { (cont: CheckedContinuation<[String], Never>) in
                self.continuation = cont
                // The observer closure is declared @Sendable by
                // NotificationCenter, so route through a main-actor Task
                // to call our isolated ``finish()``. We've already set
                // `operationQueue = .main`, so the Task hop is cheap.
                self.observer = NotificationCenter.default.addObserver(
                    forName: .NSMetadataQueryDidFinishGathering,
                    object: query,
                    queue: .main
                ) { [weak self] _ in
                    Task { @MainActor [weak self] in
                        self?.finish()
                    }
                }
                query.start()
            }
        }

        /// Called from the main actor when Spotlight signals the initial
        /// gather is complete. Extracts result paths, tears down the
        /// observer, and resumes the awaiting continuation. Guarded so a
        /// rogue extra notification can't double-resume.
        private func finish() {
            guard let cont = continuation else { return }
            continuation = nil
            query.disableUpdates()
            query.stop()

            var paths: [String] = []
            paths.reserveCapacity(query.resultCount)
            for i in 0..<query.resultCount {
                guard let item = query.result(at: i) as? NSMetadataItem,
                      let path = item.value(forAttribute: NSMetadataItemPathKey) as? String else {
                    continue
                }
                paths.append(path)
            }

            if let obs = observer {
                NotificationCenter.default.removeObserver(obs)
                observer = nil
            }
            cont.resume(returning: paths)
        }
    }

    // MARK: - Private: Process Helpers

    /// Runs an external process and returns its stdout, stderr, and exit code.
    static func runProcess(_ executable: String, arguments: [String]) -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return ProcessResult(stdout: "", stderr: error.localizedDescription, exitCode: -1)
        }

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""

        return ProcessResult(stdout: stdout, stderr: stderr, exitCode: process.terminationStatus)
    }

    /// Splits a newline-delimited string into non-empty lines.
    static func parseLines(_ output: String) -> [String] {
        output.components(separatedBy: "\n").filter { !$0.isEmpty }
    }

    // MARK: - Private: Defaults

    private static func defaultSearchPath() -> String {
        FileManager.default.homeDirectoryForCurrentUser.path
    }
}
