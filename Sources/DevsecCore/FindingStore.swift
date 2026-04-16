import Foundation

// FindingStore persists finding IDs so the CLI can highlight which findings
// are new since the last scan vs previously seen.
public final class FindingStore: Sendable {

    // MARK: - Private state

    private let storePath: String
    private let lock = NSLock()

    // Wrapped in a class so we can mutate inside a Sendable final class.
    private final class State: @unchecked Sendable {
        var knownIds: Set<String> = []
    }

    private let state = State()

    // MARK: - Init

    public init(storePath: String? = nil) {
        if let path = storePath {
            self.storePath = path
        } else {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            self.storePath = "\(home)/.config/devsec/findings.json"
        }

        // Auto-load on init; ignore errors (file may not exist yet).
        try? loadInternal()
    }

    // MARK: - Load / Save

    public func load() throws {
        try loadInternal()
    }

    private func loadInternal() throws {
        let url = URL(fileURLWithPath: storePath)
        let data = try Data(contentsOf: url)
        let ids = try JSONDecoder().decode(Set<String>.self, from: data)
        lock.lock()
        state.knownIds = ids
        lock.unlock()
    }

    public func save() throws {
        lock.lock()
        let ids = state.knownIds
        lock.unlock()

        let data = try JSONEncoder().encode(ids)

        let url = URL(fileURLWithPath: storePath)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: nil
        )
        try data.write(to: url, options: .atomic)
    }

    // MARK: - Recording findings

    public func recordFindings(_ findings: [Finding]) {
        let ids = findings.map { $0.id }
        lock.lock()
        for id in ids {
            state.knownIds.insert(id)
        }
        lock.unlock()
    }

    // MARK: - Marking new vs known

    /// Returns new Finding instances with isNew=true for findings whose IDs are
    /// not in knownIds, and isNew=false for those that are already known.
    public func markNewVsKnown(_ findings: [Finding]) -> [Finding] {
        lock.lock()
        let snapshot = state.knownIds
        lock.unlock()

        return findings.map { finding in
            let alreadyKnown = snapshot.contains(finding.id)
            return Finding(
                id: finding.id,
                module: finding.module,
                severity: finding.severity,
                gitRisk: finding.gitRisk,
                localRisk: finding.localRisk,
                filePath: finding.filePath,
                lineNumber: finding.lineNumber,
                description: finding.description,
                secretPreview: finding.secretPreview,
                recommendation: finding.recommendation,
                isNew: !alreadyKnown
            )
        }
    }
}
