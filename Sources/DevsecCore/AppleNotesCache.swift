import Foundation

// MARK: - AppleNotesCache

/// Per-note scan cache for Apple Notes. Keyed by Apple's opaque note ID.
///
/// The Apple Notes library can easily contain thousands of notes. Re-parsing
/// every note's HTML body on every scheduled scan would be wasteful. most
/// notes don't change between runs. This cache records each note's last-seen
/// `modificationDate` along with the findings produced from it. On subsequent
/// scans:
///
/// - If the note is gone, its cache entry is dropped.
/// - If the note's modification date is unchanged, the cached findings are
///   replayed without re-scanning the body.
/// - If the note is new or its modification date has advanced, the body is
///   re-scanned and the cache entry is rewritten.
///
/// Persisted to `~/.config/damit/apple-notes-cache.json`.
public final class AppleNotesCache: @unchecked Sendable {

    // MARK: - Entry

    public struct Entry: Codable, Sendable {
        public let modificationDate: Date
        public let findings: [Finding]

        public init(modificationDate: Date, findings: [Finding]) {
            self.modificationDate = modificationDate
            self.findings = findings
        }
    }

    private struct Store: Codable {
        var entries: [String: Entry]
    }

    // MARK: - State

    private let storePath: String
    private let lock = NSLock()
    private var entries: [String: Entry]

    // MARK: - Init

    public init(storePath: String? = nil) {
        self.storePath = storePath ?? (NSHomeDirectory() + "/.config/damit/apple-notes-cache.json")
        self.entries = [:]
        try? load()
    }

    // MARK: - Persistence

    public func load() throws {
        guard FileManager.default.fileExists(atPath: storePath) else { return }
        let data = try Data(contentsOf: URL(fileURLWithPath: storePath))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let loaded = try decoder.decode(Store.self, from: data)
        lock.lock()
        entries = loaded.entries
        lock.unlock()
    }

    public func save() throws {
        lock.lock()
        let snapshot = Store(entries: entries)
        lock.unlock()

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(snapshot)

        let url = URL(fileURLWithPath: storePath)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
    }

    // MARK: - Mutations

    public func entry(for noteId: String) -> Entry? {
        lock.lock()
        defer { lock.unlock() }
        return entries[noteId]
    }

    public func setEntry(_ entry: Entry, for noteId: String) {
        lock.lock()
        entries[noteId] = entry
        lock.unlock()
    }

    /// Removes cache entries for notes that are no longer present in `presentIds`.
    /// Returns the number of entries dropped.
    @discardableResult
    public func pruneToIds(_ presentIds: Set<String>) -> Int {
        lock.lock()
        defer { lock.unlock() }
        let stale = entries.keys.filter { !presentIds.contains($0) }
        for id in stale {
            entries.removeValue(forKey: id)
        }
        return stale.count
    }

    public func clear() {
        lock.lock()
        entries.removeAll()
        lock.unlock()
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.count
    }
}
