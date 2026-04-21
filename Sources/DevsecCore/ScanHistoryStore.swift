import Foundation

// MARK: - ScanHistoryRecord

/// Summary of a single scan run, persisted across launches so the Settings UI
/// can show trends ("findings over time", "secrets fixed"). Deliberately small
///. no file paths, no finding details, just counts + timestamp. so the history
/// file stays under a few hundred KB even after months of scans.
public struct ScanHistoryRecord: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public let date: Date
    public let totalFindings: Int
    public let newFindings: Int
    public let fixedSincePrevious: Int
    public let critical: Int
    public let high: Int
    public let medium: Int
    public let low: Int
    public let durationSeconds: Double

    public init(
        id: UUID = UUID(),
        date: Date,
        totalFindings: Int,
        newFindings: Int,
        fixedSincePrevious: Int,
        critical: Int,
        high: Int,
        medium: Int,
        low: Int,
        durationSeconds: Double
    ) {
        self.id = id
        self.date = date
        self.totalFindings = totalFindings
        self.newFindings = newFindings
        self.fixedSincePrevious = fixedSincePrevious
        self.critical = critical
        self.high = high
        self.medium = medium
        self.low = low
        self.durationSeconds = durationSeconds
    }
}

// MARK: - ScanHistoryStore

/// Append-only store of ``ScanHistoryRecord`` values at
/// `~/.config/damit/history.json`. Capped at `maxRecords` to prevent unbounded
/// growth. older records are dropped when the cap is exceeded.
public final class ScanHistoryStore: @unchecked Sendable {

    // MARK: - Config

    public static let maxRecords: Int = 500

    // MARK: - Properties

    private let storePath: String
    private let lock = NSLock()
    private var records: [ScanHistoryRecord]

    // MARK: - Init

    public init(storePath: String? = nil) {
        if let path = storePath {
            self.storePath = path
        } else {
            self.storePath = NSHomeDirectory() + "/.config/damit/history.json"
        }
        self.records = []
        try? load()
    }

    // MARK: - Persistence

    public func load() throws {
        let url = URL(fileURLWithPath: storePath)
        guard FileManager.default.fileExists(atPath: storePath) else {
            return
        }
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let loaded = try decoder.decode([ScanHistoryRecord].self, from: data)
        lock.lock()
        records = loaded
        lock.unlock()
    }

    public func save() throws {
        lock.lock()
        let snapshot = records
        lock.unlock()

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(snapshot)

        let url = URL(fileURLWithPath: storePath)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
    }

    // MARK: - Mutations

    /// Appends a record and trims the oldest if the cap is exceeded.
    public func append(_ record: ScanHistoryRecord) {
        lock.lock()
        records.append(record)
        if records.count > Self.maxRecords {
            records.removeFirst(records.count - Self.maxRecords)
        }
        lock.unlock()
    }

    public func clear() {
        lock.lock()
        records.removeAll()
        lock.unlock()
    }

    // MARK: - Queries

    public var allRecords: [ScanHistoryRecord] {
        lock.lock()
        defer { lock.unlock() }
        return records
    }

    /// Total number of findings removed (fixed) across all recorded scans.
    /// Useful as the "secured X" headline for the Settings dashboard.
    public var totalFixed: Int {
        lock.lock()
        defer { lock.unlock() }
        return records.reduce(0) { $0 + $1.fixedSincePrevious }
    }

    public var latest: ScanHistoryRecord? {
        lock.lock()
        defer { lock.unlock() }
        return records.last
    }
}
