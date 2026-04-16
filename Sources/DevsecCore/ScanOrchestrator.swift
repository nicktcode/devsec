import Foundation

// MARK: - FullScanResult

public struct FullScanResult: Sendable {
    public let results: [ScanResult]
    public let findings: [Finding]
    public let totalDuration: TimeInterval
    public let newCount: Int
    public let criticalCount: Int
    public let highCount: Int
    public let mediumCount: Int
    public let lowCount: Int

    public init(
        results: [ScanResult],
        findings: [Finding],
        totalDuration: TimeInterval,
        newCount: Int,
        criticalCount: Int,
        highCount: Int,
        mediumCount: Int,
        lowCount: Int
    ) {
        self.results = results
        self.findings = findings
        self.totalDuration = totalDuration
        self.newCount = newCount
        self.criticalCount = criticalCount
        self.highCount = highCount
        self.mediumCount = mediumCount
        self.lowCount = lowCount
    }
}

// MARK: - ScanOrchestrator

public final class ScanOrchestrator: Sendable {

    // MARK: - Properties

    private let whitelistManager: WhitelistManager
    private let findingStore: FindingStore
    private let modules: Set<ScanModule>

    // MARK: - Init

    public init(
        whitelistManager: WhitelistManager,
        findingStore: FindingStore,
        modules: Set<ScanModule>? = nil
    ) {
        self.whitelistManager = whitelistManager
        self.findingStore = findingStore
        self.modules = modules ?? Set(ScanModule.allCases)
    }

    // MARK: - Scan

    public func scan() async throws -> FullScanResult {
        let start = Date()

        // Build list of scanners for selected modules
        let scanners: [any Scanner] = buildScanners()

        // Run all scanners concurrently
        var results: [ScanResult] = []
        try await withThrowingTaskGroup(of: ScanResult.self) { group in
            for scanner in scanners {
                group.addTask {
                    try await scanner.scan()
                }
            }
            for try await result in group {
                results.append(result)
            }
        }

        // Sort results by module rawValue for deterministic order
        results.sort { $0.module.rawValue < $1.module.rawValue }

        // Merge all findings
        let allFindings = results.flatMap { $0.findings }

        // Apply whitelist filter
        let filtered = whitelistManager.filterFindings(allFindings)

        // Mark new vs known
        let marked = findingStore.markNewVsKnown(filtered)

        // Record findings for future scans
        findingStore.recordFindings(marked)
        try? findingStore.save()

        // Sort by severity descending
        let sorted = marked.sorted { $0.severity > $1.severity }

        let totalDuration = Date().timeIntervalSince(start)

        // Compute counts
        let newCount = sorted.filter { $0.isNew }.count
        let criticalCount = sorted.filter { $0.severity == .critical }.count
        let highCount = sorted.filter { $0.severity == .high }.count
        let mediumCount = sorted.filter { $0.severity == .medium }.count
        let lowCount = sorted.filter { $0.severity == .low }.count

        return FullScanResult(
            results: results,
            findings: sorted,
            totalDuration: totalDuration,
            newCount: newCount,
            criticalCount: criticalCount,
            highCount: highCount,
            mediumCount: mediumCount,
            lowCount: lowCount
        )
    }

    // MARK: - Private

    private func buildScanners() -> [any Scanner] {
        var scanners: [any Scanner] = []
        if modules.contains(.env) {
            scanners.append(EnvFileScanner())
        }
        if modules.contains(.history) {
            scanners.append(HistoryScanner())
        }
        if modules.contains(.ssh) {
            scanners.append(SSHScanner())
        }
        if modules.contains(.documents) {
            scanners.append(DocumentScanner())
        }
        if modules.contains(.aiTools) {
            scanners.append(AIToolScanner())
        }
        if modules.contains(.credentialFiles) {
            scanners.append(CredentialFileScanner())
        }
        return scanners
    }
}
