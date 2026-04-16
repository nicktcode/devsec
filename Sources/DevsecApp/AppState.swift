import Foundation
import SwiftUI
import DevsecCore

// MARK: - ScanStatus

public enum ScanStatus {
    case idle
    case scanning
    case clean
    case warnings
    case critical
}

// MARK: - AppState

@MainActor
public final class AppState: ObservableObject {

    // MARK: - Published Properties

    @Published public var overallStatus: ScanStatus = .idle
    @Published public var lastScanResult: FullScanResult?
    @Published public var lastScanTime: Date?
    @Published public var isScanning: Bool = false
    @Published public var errorMessage: String?
    @Published public var scanInterval: TimeInterval = 300
    @Published public var enabledModules: Set<ScanModule> = Set(ScanModule.allCases)
    @Published public var notificationsEnabled: Bool = true

    // MARK: - Private Services

    private let whitelist: WhitelistManager
    private let findingStore: FindingStore
    private let notificationService: NotificationService
    private lazy var scheduler: ScanScheduler = ScanScheduler(appState: self)

    // MARK: - Init

    public init() {
        self.whitelist = WhitelistManager()
        self.findingStore = FindingStore()
        self.notificationService = NotificationService()

        // Request notification permission on launch
        notificationService.requestPermission()

        // Start scheduled scanning after a short delay to let the UI settle
        Task {
            try? await Task.sleep(for: .seconds(2))
            self.startScheduledScanning()
        }
    }

    // MARK: - Scheduling

    public func startScheduledScanning() {
        scheduler.start()
    }

    public func stopScheduledScanning() {
        scheduler.stop()
    }

    // MARK: - Scan

    public func runScan() async {
        guard !isScanning else { return }

        isScanning = true
        overallStatus = .scanning
        errorMessage = nil

        defer {
            isScanning = false
        }

        do {
            let orchestrator = ScanOrchestrator(
                whitelistManager: whitelist,
                findingStore: findingStore,
                modules: enabledModules.isEmpty ? nil : enabledModules
            )

            let result = try await orchestrator.scan()

            lastScanResult = result
            lastScanTime = Date()

            // Determine overall status from finding counts
            if result.criticalCount > 0 {
                overallStatus = .critical
            } else if result.highCount > 0 || result.mediumCount > 0 {
                overallStatus = .warnings
            } else {
                overallStatus = .clean
            }

            // Send notification if there are new findings
            if notificationsEnabled && result.newCount > 0 {
                notificationService.sendNewFindingsNotification(
                    count: result.newCount,
                    critical: result.criticalCount
                )
            }
        } catch {
            errorMessage = error.localizedDescription
            overallStatus = .idle
        }
    }

    // MARK: - Whitelist

    public func whitelistFinding(_ finding: Finding) {
        whitelist.addFinding(finding.id)
        try? whitelist.save()

        // Re-filter current results to update UI immediately
        guard let current = lastScanResult else { return }

        let filtered = whitelist.filterFindings(current.findings)

        let criticalCount = filtered.filter { $0.severity == .critical }.count
        let highCount = filtered.filter { $0.severity == .high }.count
        let mediumCount = filtered.filter { $0.severity == .medium }.count
        let lowCount = filtered.filter { $0.severity == .low }.count
        let newCount = filtered.filter { $0.isNew }.count

        lastScanResult = FullScanResult(
            results: current.results,
            findings: filtered,
            totalDuration: current.totalDuration,
            newCount: newCount,
            criticalCount: criticalCount,
            highCount: highCount,
            mediumCount: mediumCount,
            lowCount: lowCount
        )

        // Update status after re-filtering
        if criticalCount > 0 {
            overallStatus = .critical
        } else if highCount > 0 || mediumCount > 0 {
            overallStatus = .warnings
        } else if lastScanResult != nil {
            overallStatus = .clean
        }
    }

    // MARK: - Computed Properties

    public var nextScanTime: Date? {
        guard let last = lastScanTime else { return nil }
        return last.addingTimeInterval(scanInterval)
    }

    public var timeUntilNextScan: String {
        guard let next = nextScanTime else { return "Not scheduled" }
        let remaining = next.timeIntervalSinceNow
        if remaining <= 0 { return "Scanning soon..." }
        let minutes = Int(remaining / 60)
        let seconds = Int(remaining) % 60
        if minutes > 0 {
            return "Next scan in \(minutes)m \(seconds)s"
        } else {
            return "Next scan in \(seconds)s"
        }
    }
}
