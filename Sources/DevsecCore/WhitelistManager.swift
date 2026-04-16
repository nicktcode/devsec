import Foundation

// MARK: - WhitelistManager

public final class WhitelistManager: Sendable {

    // MARK: - WhitelistConfig

    struct WhitelistConfig: Codable {
        var files: [String]
        var dirs: [String]
        var findings: [String]
        var safePatterns: [String]
        var scanInterval: Int

        init(
            files: [String] = [],
            dirs: [String] = [],
            findings: [String] = [],
            safePatterns: [String] = [
                "sk-test-*",
                "pk_test_*",
                "AKIAIOSFODNN7EXAMPLE",
                "django-insecure-*",
                "your-api-key-here",
                "changeme",
            ],
            scanInterval: Int = 300
        ) {
            self.files = files
            self.dirs = dirs
            self.findings = findings
            self.safePatterns = safePatterns
            self.scanInterval = scanInterval
        }
    }

    // MARK: - Properties

    private let configPath: String
    private let lock = NSLock()
    nonisolated(unsafe) private var config: WhitelistConfig

    // MARK: - Init

    public init(configPath: String? = nil) {
        if let path = configPath {
            self.configPath = path
        } else {
            self.configPath = NSHomeDirectory() + "/.config/devsec/config.json"
        }
        self.config = WhitelistConfig()
    }

    // MARK: - Load / Save

    public func load() throws {
        let url = URL(fileURLWithPath: configPath)
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        let loaded = try decoder.decode(WhitelistConfig.self, from: data)
        lock.lock()
        config = loaded
        lock.unlock()
    }

    public func save() throws {
        lock.lock()
        let snapshot = config
        lock.unlock()

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(snapshot)

        let url = URL(fileURLWithPath: configPath)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
    }

    // MARK: - Add methods

    public func addFile(_ path: String) {
        lock.lock()
        defer { lock.unlock() }
        if !config.files.contains(path) {
            config.files.append(path)
        }
    }

    public func addDir(_ path: String) {
        lock.lock()
        defer { lock.unlock() }
        if !config.dirs.contains(path) {
            config.dirs.append(path)
        }
    }

    public func addFinding(_ id: String) {
        lock.lock()
        defer { lock.unlock() }
        if !config.findings.contains(id) {
            config.findings.append(id)
        }
    }

    public func addSafePattern(_ pattern: String) {
        lock.lock()
        defer { lock.unlock() }
        if !config.safePatterns.contains(pattern) {
            config.safePatterns.append(pattern)
        }
    }

    // MARK: - Remove methods

    public func removeFinding(_ id: String) {
        lock.lock()
        defer { lock.unlock() }
        config.findings.removeAll { $0 == id }
    }

    // MARK: - Query methods

    public func isFileWhitelisted(_ path: String) -> Bool {
        let expanded = expandTilde(path)
        lock.lock()
        defer { lock.unlock() }
        return config.files.contains { expandTilde($0) == expanded }
    }

    public func isDirWhitelisted(_ path: String) -> Bool {
        let expanded = expandTilde(path)
        lock.lock()
        defer { lock.unlock() }
        return config.dirs.contains { dir in
            let expandedDir = expandTilde(dir)
            let prefix = expandedDir.hasSuffix("/") ? expandedDir : expandedDir + "/"
            return expanded.hasPrefix(prefix)
        }
    }

    public func isWhitelisted(findingId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return config.findings.contains(findingId)
    }

    public func isSafePattern(_ value: String) -> Bool {
        lock.lock()
        let patterns = config.safePatterns
        lock.unlock()
        return patterns.contains { matchesGlob(value: value, pattern: $0) }
    }

    public func isWhitelistedByAnyRule(finding: Finding) -> Bool {
        // Check finding ID
        if isWhitelisted(findingId: finding.id) { return true }

        // Check file path
        if let path = finding.filePath {
            if isFileWhitelisted(path) { return true }
            if isDirWhitelisted(path) { return true }
        }

        // Check secret preview against safe patterns
        if isSafePattern(finding.secretPreview) { return true }

        return false
    }

    public func filterFindings(_ findings: [Finding]) -> [Finding] {
        findings.filter { !isWhitelistedByAnyRule(finding: $0) }
    }

    // MARK: - Computed properties

    public var allFindings: [String] {
        lock.lock()
        defer { lock.unlock() }
        return config.findings
    }

    public var scanInterval: Int {
        lock.lock()
        defer { lock.unlock() }
        return config.scanInterval
    }

    // MARK: - Private helpers

    private func expandTilde(_ path: String) -> String {
        if path.hasPrefix("~/") {
            return NSHomeDirectory() + "/" + path.dropFirst(2)
        }
        return path
    }

    private func matchesGlob(value: String, pattern: String) -> Bool {
        if pattern.hasSuffix("*") {
            let prefix = String(pattern.dropLast())
            return value.hasPrefix(prefix)
        } else if pattern.hasPrefix("*") {
            let suffix = String(pattern.dropFirst())
            return value.hasSuffix(suffix)
        } else {
            return value == pattern
        }
    }
}
