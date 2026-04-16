import Foundation

// MARK: - SpotlightEngine

/// Discovery layer for devsec. Wraps macOS Spotlight (mdfind) for full-disk search
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

    /// Checks whether Spotlight indexing is enabled on the root volume.
    public static func checkHealth() async -> SpotlightHealth {
        let result = runProcess("/usr/bin/mdutil", arguments: ["-s", "/"])
        let output = result.stdout + result.stderr
        let available = output.contains("Indexing enabled")
        let message = output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "mdutil returned no output"
            : output.trimmingCharacters(in: .whitespacesAndNewlines)
        return SpotlightHealth(checked: true, available: available, message: message)
    }

    // MARK: - Public Search API

    /// Finds files by exact filename. Uses mdfind when Spotlight is available,
    /// falls back to `find` otherwise.
    public static func findFiles(named name: String, searchPath: String? = nil) async -> [String] {
        let health = await checkHealth()
        if health.available {
            return mdfindByName(name, searchPath: searchPath)
        }
        return await fallbackFindFiles(named: name, searchPath: searchPath)
    }

    /// Finds files matching a glob pattern. Uses mdfind when Spotlight is available,
    /// falls back to `find` otherwise.
    public static func findFiles(matchingGlob glob: String, searchPath: String? = nil) async -> [String] {
        let health = await checkHealth()
        if health.available {
            return mdfindByGlob(glob, searchPath: searchPath)
        }
        return await fallbackFindFiles(matchingGlob: glob, searchPath: searchPath)
    }

    /// Finds files whose content contains the given text. Uses mdfind when Spotlight
    /// is available, falls back to `grep` otherwise.
    public static func findFiles(containingText text: String, searchPath: String? = nil) async -> [String] {
        let health = await checkHealth()
        if health.available {
            return mdfindByContent(text, searchPath: searchPath)
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

    // MARK: - Private: mdfind Wrappers

    private static func mdfindByName(_ name: String, searchPath: String?) -> [String] {
        let query = "kMDItemFSName == '\(name)'"
        return runMdfind(query: query, searchPath: searchPath)
    }

    private static func mdfindByGlob(_ glob: String, searchPath: String?) -> [String] {
        let query = "kMDItemFSName == '\(glob)'"
        return runMdfind(query: query, searchPath: searchPath)
    }

    private static func mdfindByContent(_ text: String, searchPath: String?) -> [String] {
        let query = "kMDItemTextContent == '\(text)'"
        return runMdfind(query: query, searchPath: searchPath)
    }

    private static func runMdfind(query: String, searchPath: String?) -> [String] {
        var args: [String] = []
        if let path = searchPath {
            args += ["-onlyin", path]
        }
        args.append(query)
        let result = runProcess("/usr/bin/mdfind", arguments: args)
        return parseLines(result.stdout)
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
