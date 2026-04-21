import Foundation
import SwiftUI
import DevsecCore

// MARK: - SettingsTab

/// Identifier for the tabs in ``SettingsView``. Exposed so callers from
/// elsewhere in the app (e.g. the popover banner) can request a specific
/// tab be preselected the next time the Settings window opens.
public enum SettingsTab: String, Sendable, Hashable {
    case general, modules, limits, whitelist, exclusions, permissions, diagnostics, history
}

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
    @Published public var scanProgress: String = ""
    @Published public var scanDetail: String = ""
    @Published public var completedModules: Int = 0
    @Published public var totalModules: Int = 0
    @Published public var errorMessage: String?
    /// Key under which the user's preferred scan interval is persisted
    /// in `UserDefaults`. Kept public only so test harnesses can clear
    /// it; production code should never touch it directly.
    public static let scanIntervalDefaultsKey = "damit.scanInterval"

    @Published public var scanInterval: TimeInterval = {
        // Load previously-saved interval on launch. 0 is not a valid
        // interval; UserDefaults returns 0 when the key is missing,
        // which we treat as "use the 5-minute default".
        let saved = UserDefaults.standard.double(forKey: scanIntervalDefaultsKey)
        return saved > 0 ? saved : 300
    }() {
        didSet {
            guard oldValue != scanInterval else { return }
            // Persist so the 1-hour (or whatever) choice survives
            // restarts. Previously the Settings picker would change
            // the live value but silently revert to 300s on next
            // launch.
            UserDefaults.standard.set(scanInterval, forKey: Self.scanIntervalDefaultsKey)
            // Reschedule the timer so the new cadence takes effect
            // immediately instead of waiting until next app launch.
            scheduler.reschedule()
        }
    }
    @Published public var enabledModules: Set<ScanModule> = [
        .env, .history, .ssh, .documents, .aiTools, .credentialFiles
    ]
    @Published public var notificationsEnabled: Bool = true
    /// Set to `true` to request that the onboarding window be opened.
    /// A bridging view on the MenuBarExtra scene watches this flag (which
    /// has access to SwiftUI's `openWindow` environment) and flips it
    /// back to `false` after opening. Used for first-launch auto-open and
    /// re-opens from Settings → Permissions.
    @Published public var shouldPresentOnboarding: Bool = false
    /// Tab to preselect the next time the Settings window is opened.
    /// Consumed by ``SettingsView`` on appear, then reset to `nil`.
    /// Lets the popover banner deep-link into the Permissions tab
    /// without us having to parse scene paths.
    @Published public var pendingSettingsTab: SettingsTab? = nil
    /// What caused the most recent scan to start. Used by the popover to
    /// distinguish scheduled runs from FSEvents-triggered ones so the
    /// countdown doesn't look like it lied when an unscheduled scan
    /// fires. Cleared when the scan completes.
    @Published public var lastScanTrigger: ScanTrigger = .scheduled
    /// Ring buffer of the most recent file-change triggers. Lets the
    /// user see **what** actually caused a scan to fire, so
    /// "file change detected" in the UI is inspectable rather than
    /// mysterious. Bounded at 50 entries; older events fall off.
    @Published public var recentFileChanges: [FileChangeEvent] = []

    public enum ScanTrigger: Sendable, Equatable {
        case scheduled
        case manual
        case fileChange(count: Int)

        public var displayText: String? {
            switch self {
            case .scheduled:            return nil
            case .manual:               return "Manual scan"
            case .fileChange(let n):    return "File change detected (\(n))"
            }
        }
    }

    public struct FileChangeEvent: Sendable, Identifiable, Equatable {
        public let id: UUID
        public let timestamp: Date
        /// How many paths the watcher reported in this burst.
        public let totalPaths: Int
        /// Up to 5 sample paths from the burst for display. We don't
        /// store the full list. at 50 events × thousands of paths each
        /// the memory footprint balloons.
        public let samplePaths: [String]

        public init(timestamp: Date, totalPaths: Int, samplePaths: [String]) {
            self.id = UUID()
            self.timestamp = timestamp
            self.totalPaths = totalPaths
            self.samplePaths = samplePaths
        }
    }

    // MARK: - Private Services

    public let whitelist: WhitelistManager
    private let findingStore: FindingStore
    public let historyStore: ScanHistoryStore
    private let notificationService: NotificationService
    private lazy var scheduler: ScanScheduler = ScanScheduler(appState: self)
    private lazy var watcher: FileSystemWatcher = FileSystemWatcher()

    /// IDs of findings covered by the most recent user-facing
    /// notification. A new notification only fires when the "isNew" set
    /// actually introduces IDs we haven't already told the user about,
    /// so rapid FSEvents bursts don't spam the Notification Center with
    /// the same "1 new finding" toast repeatedly. Persisted across
    /// restarts so a rebuild doesn't re-notify about findings the user
    /// has already seen in a previous session.
    private var lastNotifiedNewIds: Set<String> {
        get {
            Set(UserDefaults.standard.stringArray(forKey: Self.lastNotifiedIdsKey) ?? [])
        }
        set {
            UserDefaults.standard.set(Array(newValue), forKey: Self.lastNotifiedIdsKey)
        }
    }
    private static let lastNotifiedIdsKey = "damit.lastNotifiedNewIds"
    /// Timestamp of the last new-findings toast. Combined with
    /// ``notificationCooldown`` this rate-limits toasts even when
    /// legitimately-new findings keep arriving. Active development
    /// can introduce a trickle of new secrets; the first one warns
    /// the user, the rest can wait for the next scheduled summary.
    private var lastNotificationAt: Date? {
        get {
            let epoch = UserDefaults.standard.double(forKey: Self.lastNotificationAtKey)
            return epoch > 0 ? Date(timeIntervalSince1970: epoch) : nil
        }
        set {
            if let newValue {
                UserDefaults.standard.set(
                    newValue.timeIntervalSince1970,
                    forKey: Self.lastNotificationAtKey
                )
            } else {
                UserDefaults.standard.removeObject(forKey: Self.lastNotificationAtKey)
            }
        }
    }

    /// UserDefaults key backing ``lastNotificationAt``. Persisting
    /// the last-notified timestamp across app restarts is critical:
    /// without it, every rebuild / relaunch wipes the cooldown and
    /// the user gets a fresh toast the moment the next scan finds
    /// anything.
    private static let lastNotificationAtKey = "damit.lastNotificationAt"

    /// Minimum gap between user-facing new-findings toasts. 15
    /// minutes is long enough to survive a normal dev loop (edits,
    /// rebuilds, git pulls, test runs) without spamming; short enough
    /// that a genuinely-new secret surfaces within a reasonable
    /// window. Tune via the UserDefault key below if it's wrong for
    /// your workflow.
    private static let notificationCooldown: TimeInterval = 900

    /// Serialization guard for ``runIncrementalScan(paths:)``. Without
    /// it, a rapid sequence of FSEvents bursts can spawn multiple
    /// incremental Tasks that race on the main actor and pile up
    /// findings reads. Setting this to `true` makes the watcher drop
    /// new bursts instead of stacking them up. the dropped paths will
    /// be caught by the next scheduled full scan, which is exactly
    /// what the safety net is for.
    private var isIncrementalScanning: Bool = false

    // MARK: - Init

    public init() {
        self.whitelist = WhitelistManager()
        self.findingStore = FindingStore()
        self.historyStore = ScanHistoryStore()
        self.notificationService = NotificationService()

        // Request notification permission on launch
        notificationService.requestPermission()

        // Start scheduled scanning after a short delay to let the UI settle
        Task {
            try? await Task.sleep(for: .seconds(2))
            self.startScheduledScanning()
            self.startFileSystemWatcher()
        }

        // First-launch onboarding. A view with the SwiftUI `openWindow`
        // environment watches `shouldPresentOnboarding` and opens the
        // scene when it flips to true. We set it here so the view can
        // bridge SwiftUI's scene lookup for us.
        if !OnboardingState.isCompleted {
            Task { @MainActor [weak self] in
                try? await Task.sleep(for: .seconds(1))
                self?.shouldPresentOnboarding = true
            }
        }
    }

    // MARK: - Scheduling

    public func startScheduledScanning() {
        scheduler.start()
    }

    public func stopScheduledScanning() {
        scheduler.stop()
    }

    // MARK: - File System Watcher

    /// Starts FSEvents monitoring. When new / modified files appear in
    /// `$HOME`, we schedule a background scan within the debounce
    /// window. Rapid bursts (IDE save-all, yarn install) coalesce into
    /// a single scan. This is what makes damit "always on". catching
    /// a secret on disk within seconds of it appearing, not 5 minutes
    /// later on the next scheduled scan.
    public func startFileSystemWatcher() {
        watcher.onChange = { [weak self] changedPaths in
            guard let self else { return }
            // Log every trigger to the ring buffer, even ones that
            // don't kick off a scan (because one is already running).
            // This is the signal users need to debug "why is damit
            // triggering so often?". they can see the actual paths.
            let event = FileChangeEvent(
                timestamp: Date(),
                totalPaths: changedPaths.count,
                samplePaths: Array(changedPaths.prefix(5))
            )
            self.recentFileChanges.insert(event, at: 0)
            if self.recentFileChanges.count > 50 {
                self.recentFileChanges = Array(self.recentFileChanges.prefix(50))
            }

            // If any scan (full or incremental) is already in flight,
            // drop this burst. A pile-up of overlapping scans makes
            // the app lag without catching anything the next scheduled
            // scan wouldn't cover anyway.
            guard !self.isScanning, !self.isIncrementalScanning else { return }
            // Record the trigger reason so the popover can show "File
            // change detected, scanning…" instead of making the user
            // wonder why a scan started when the countdown said 59m.
            self.lastScanTrigger = .fileChange(count: changedPaths.count)

            // Safety cap: a single debounce window with more than a few
            // hundred paths is a git-checkout or bulk-copy event. Full
            // scans use Spotlight and are consistently faster than
            // per-file routing above this threshold.
            if changedPaths.count > 300 {
                Task { await self.runScan() }
                return
            }

            // Incremental path: scan only the changed files and merge
            // results into the existing report. Typical burst is 1-5
            // files and completes in ~50-200ms.
            Task { await self.runIncrementalScan(paths: changedPaths) }
        }
        watcher.start()
    }

    public func stopFileSystemWatcher() {
        watcher.stop()
    }

    // MARK: - Notification Dedup

    /// Sends a "new findings" macOS notification only when the set of
    /// currently-new findings introduces IDs that haven't already been
    /// notified. Call this after each scan (full or incremental); the
    /// function is a no-op when nothing qualifies.
    ///
    /// `findings` must already have ``Finding.isNew`` updated by
    /// ``FindingStore/markNewVsKnown(_:)`` - the helper trusts the
    /// flags. Passing raw scanner output here causes every scan to
    /// look like it produced new findings, which is exactly the bug
    /// the dedup exists to prevent.
    private func notifyIfNewFindings(in findings: [Finding]) {
        guard notificationsEnabled else { return }
        let newOnes = findings.filter(\.isNew)
        guard !newOnes.isEmpty else { return }

        let newIds = Set(newOnes.map(\.id))
        let notYetNotified = newIds.subtracting(lastNotifiedNewIds)
        guard !notYetNotified.isEmpty else { return }

        // Cooldown gate: even if there are genuinely-new IDs, don't
        // fire a toast if we already bugged the user recently. The
        // IDs we skip here get absorbed into lastNotifiedNewIds so
        // the next toast after the cooldown will reflect any
        // accumulated changes up to that point.
        if let lastAt = lastNotificationAt,
           Date().timeIntervalSince(lastAt) < Self.notificationCooldown {
            lastNotifiedNewIds = newIds
            return
        }

        let trulyNew = newOnes.filter { notYetNotified.contains($0.id) }
        let criticalCount = trulyNew.filter { $0.severity == .critical }.count
        notificationService.sendNewFindingsNotification(
            count: trulyNew.count,
            critical: criticalCount
        )
        lastNotifiedNewIds = newIds
        lastNotificationAt = Date()
    }

    // MARK: - Incremental Scan

    /// Scans a small set of changed paths and merges the results with
    /// the existing ``lastScanResult`` instead of re-running the full
    /// scanner pipeline. Typical trigger: FSEvents reports "these 3
    /// files changed in the last 2 seconds".
    ///
    /// Merge semantics:
    ///  - Findings from ``lastScanResult`` whose filePath is in the
    ///    scanned set are dropped. If the file still contains a secret,
    ///    the new scan re-emits it with an updated id/isNew flag.
    ///  - Findings from files *outside* the scanned set are kept as-is.
    ///  - Whitelist + acknowledge filtering applies to new findings.
    ///  - ``lastScanTime`` is *not* updated, so the scheduled full-scan
    ///    timer continues on its original cadence.
    public func runIncrementalScan(paths: [String]) async {
        guard !isScanning else { return }
        // Drop overlapping incremental scans. A new FSEvents burst
        // while the previous scan is still processing would double the
        // CPU load for no gain. the next scheduled scan catches the
        // paths we skipped anyway.
        guard !isIncrementalScanning else { return }
        isIncrementalScanning = true
        defer { isIncrementalScanning = false }

        // First-run safety: no baseline to merge into. Fall back to the
        // full scan so the user gets a complete initial report.
        guard let baseline = lastScanResult else {
            await runScan()
            return
        }

        // Route each path to its per-file scanner.
        //
        // Critical: run this OFF the main actor. scanPaths is CPU-bound
        // (regex matching) and does synchronous file I/O. If we call it
        // from this @MainActor context directly, the menubar popover
        // freezes for the duration, the shield icon shows a spinner on
        // hover, and SwiftUI can't flush state updates. Detach to a
        // utility-priority Task so main stays responsive.
        let pathsCopy = paths
        let rawFindings: [Finding] = await Task.detached(priority: .utility) {
            IncrementalScanner.scanPaths(pathsCopy)
        }.value
        let filtered = whitelist.filterFindings(rawFindings)

        // Drop baseline findings for the paths we just re-scanned;
        // their state is replaced by the new findings (or cleared if
        // the secret was removed).
        let scannedSet = Set(paths)
        let surviving = baseline.findings.filter { finding in
            guard let fp = finding.filePath else { return true }
            return !scannedSet.contains(fp)
        }

        // Mark new-vs-known and persist. The findingStore keeps a
        // running set of seen ids so genuinely-new findings get the
        // blue "new" dot.
        var merged = surviving + filtered
        merged = findingStore.markNewVsKnown(merged)
        findingStore.recordFindings(merged)
        try? findingStore.save()
        merged.sort { $0.severity > $1.severity }

        // Rebuild the per-module ScanResults from the merged findings so
        // the MODULES list in the popover matches the top-level count.
        // Keeping `baseline.results` untouched caused "24 findings"
        // total but module rows still summing to the last full scan's
        // 98. Preserve each module's duration/offloadedPaths metadata
        // from the baseline, but update `findings` to the current
        // merged state for that module.
        let findingsByModule = Dictionary(grouping: merged, by: \.module)
        let rebuiltResults: [ScanResult] = baseline.results.map { baselineResult in
            let moduleFindings = findingsByModule[baselineResult.module] ?? []
            return ScanResult(
                module: baselineResult.module,
                findings: moduleFindings,
                duration: baselineResult.duration,
                offloadedPaths: baselineResult.offloadedPaths
            )
        }

        let result = FullScanResult(
            results: rebuiltResults,
            findings: merged,
            totalDuration: baseline.totalDuration,
            newCount: merged.filter(\.isNew).count,
            criticalCount: merged.filter { $0.severity == .critical }.count,
            highCount: merged.filter { $0.severity == .high }.count,
            mediumCount: merged.filter { $0.severity == .medium }.count,
            lowCount: merged.filter { $0.severity == .low }.count
        )

        lastScanResult = result
        overallStatus = Self.computeStatus(for: merged)
        lastScanTrigger = .scheduled // reset trigger after incremental completes

        // Trust `merged`'s isNew flags (set by markNewVsKnown). The
        // helper dedups against already-notified IDs so rapid FSEvents
        // bursts can't spam the user with the same finding.
        notifyIfNewFindings(in: merged)
    }

    // MARK: - Scan

    public func runScan() async {
        guard !isScanning else { return }

        isScanning = true
        overallStatus = .scanning
        errorMessage = nil
        completedModules = 0

        let moduleNames: [ScanModule: String] = [
            .env: "Env Files", .history: "History", .ssh: "SSH Keys",
            .documents: "Documents", .aiTools: "AI Tools", .credentialFiles: "Credentials",
            .appleNotes: "Apple Notes"
        ]
        let activeModules = enabledModules.isEmpty ? Set(ScanModule.allCases) : enabledModules
        totalModules = activeModules.count
        scanProgress = "Starting scan"

        defer {
            isScanning = false
            scanProgress = ""
            // Reset trigger so the next scan starts from the scheduled
            // baseline unless a different caller explicitly sets it.
            lastScanTrigger = .scheduled
            scanDetail = ""
        }

        do {
            let allScanners: [(ScanModule, any DevsecCore.Scanner)] = [
                (ScanModule.env, EnvFileScanner()),
                (ScanModule.history, HistoryScanner()),
                (ScanModule.ssh, SSHScanner()),
                (ScanModule.documents, DocumentScanner()),
                (ScanModule.aiTools, AIToolScanner()),
                (ScanModule.credentialFiles, CredentialFileScanner()),
                (ScanModule.appleNotes, AppleNotesScanner()),
            ]
            let scanners = allScanners.filter { activeModules.contains($0.0) }

            var results: [ScanResult] = []
            var foundSoFar = 0
            for (module, scanner) in scanners {
                let name = moduleNames[module] ?? module.rawValue
                scanProgress = "Scanning \(name)"
                scanDetail = "Discovering files"
                let scanResult = try await scanner.scan { [weak self] detail in
                    Task { @MainActor [weak self] in
                        self?.scanDetail = detail
                    }
                }
                results.append(scanResult)
                completedModules += 1
                foundSoFar += scanResult.findings.count
                scanDetail = "\(scanResult.findings.count) found in \(name)"
                try? await Task.sleep(for: .milliseconds(300))
            }
            scanDetail = "Finalizing \(foundSoFar) findings"

            var allFindings = results.flatMap(\.findings)
            allFindings = whitelist.filterFindings(allFindings)
            allFindings = findingStore.markNewVsKnown(allFindings)
            findingStore.recordFindings(allFindings)
            try? findingStore.save()
            allFindings.sort { $0.severity > $1.severity }

            let result = FullScanResult(
                results: results,
                findings: allFindings,
                totalDuration: results.reduce(0) { $0 + $1.duration },
                newCount: allFindings.filter(\.isNew).count,
                criticalCount: allFindings.filter { $0.severity == .critical }.count,
                highCount: allFindings.filter { $0.severity == .high }.count,
                mediumCount: allFindings.filter { $0.severity == .medium }.count,
                lowCount: allFindings.filter { $0.severity == .low }.count
            )

            // Compute "fixed since previous scan" by diffing ID sets before we
            // overwrite lastScanResult. This does not use FindingStore because
            // its known-ID set is append-only and never shrinks.
            let previousIds = Set(lastScanResult?.findings.map(\.id) ?? [])
            let currentIds = Set(result.findings.map(\.id))
            let fixed = previousIds.subtracting(currentIds).count

            let historyRecord = ScanHistoryRecord(
                date: Date(),
                totalFindings: result.findings.count,
                newFindings: result.newCount,
                fixedSincePrevious: fixed,
                critical: result.criticalCount,
                high: result.highCount,
                medium: result.mediumCount,
                low: result.lowCount,
                durationSeconds: result.totalDuration
            )
            historyStore.append(historyRecord)
            try? historyStore.save()

            lastScanResult = result
            lastScanTime = Date()

            // Determine overall status from the subset of findings the user
            // has *not* acknowledged. Acknowledged findings stay visible in
            // the Full Report but don't drive the menubar icon color. this
            // is how users silence unfixable-but-not-commit-risky findings
            // like shell-history hits.
            overallStatus = Self.computeStatus(for: result.findings)

            // Shared dedup so a scheduled scan and an immediately
            // following incremental scan don't both notify about the
            // same set of new findings.
            notifyIfNewFindings(in: result.findings)
        } catch {
            errorMessage = error.localizedDescription
            overallStatus = .idle
        }
    }

    // MARK: - Status Computation

    /// Collapses a list of findings into a single ``ScanStatus`` for the
    /// menubar icon and popover pill. Acknowledged findings are filtered
    /// out before counting so the user can quiet known-and-accepted
    /// findings without losing the record of them.
    static func computeStatus(for findings: [Finding]) -> ScanStatus {
        let acknowledged = AcknowledgeStore.idSet
        let active = findings.filter { !acknowledged.contains($0.id) }
        let critical = active.contains { $0.severity == .critical }
        if critical { return .critical }
        let warn = active.contains { $0.severity == .high || $0.severity == .medium }
        if warn { return .warnings }
        return .clean
    }

    // MARK: - Acknowledge

    /// Marks a finding as acknowledged (keeps it visible, stops it counting
    /// toward the menubar alert). Symmetric with ``whitelistFinding`` but
    /// less destructive.
    public func acknowledgeFinding(_ finding: Finding) {
        AcknowledgeStore.acknowledge(finding.id)
        refreshStatus()
    }

    /// Reverse of ``acknowledgeFinding``.
    public func unacknowledgeFinding(_ finding: Finding) {
        AcknowledgeStore.unacknowledge(finding.id)
        refreshStatus()
    }

    /// Re-compute the overall status from the current `lastScanResult`,
    /// typically after the acknowledged set changes.
    public func refreshStatus() {
        guard let result = lastScanResult else { return }
        overallStatus = Self.computeStatus(for: result.findings)
    }

    // MARK: - Menubar Badge

    /// Number shown in the menubar badge. Matches the popover's
    /// top-level count (minus acknowledged findings) so the two
    /// displays never disagree. Severity is already conveyed by the
    /// badge pill color (red / orange / gray), so the number itself
    /// is just "how many things."
    public var alertCount: Int {
        guard let result = lastScanResult else { return 0 }
        let acknowledged = AcknowledgeStore.idSet
        return result.findings.filter { !acknowledged.contains($0.id) }.count
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

    // MARK: - Exclusions

    /// Adds the parent folder of `filePath` to ``ScanExclusions`` and removes
    /// any current findings that fall under it so the UI updates immediately.
    /// A follow-up scan will also skip these paths.
    public func excludeFolder(for filePath: String) {
        let folder = (filePath as NSString).deletingLastPathComponent
        guard !folder.isEmpty else { return }
        ScanExclusions.add(folder)

        guard let current = lastScanResult else { return }

        let remaining = current.findings.filter { finding in
            guard let p = finding.filePath else { return true }
            return !ScanExclusions.isExcluded(p)
        }

        let criticalCount = remaining.filter { $0.severity == .critical }.count
        let highCount = remaining.filter { $0.severity == .high }.count
        let mediumCount = remaining.filter { $0.severity == .medium }.count
        let lowCount = remaining.filter { $0.severity == .low }.count
        let newCount = remaining.filter { $0.isNew }.count

        lastScanResult = FullScanResult(
            results: current.results,
            findings: remaining,
            totalDuration: current.totalDuration,
            newCount: newCount,
            criticalCount: criticalCount,
            highCount: highCount,
            mediumCount: mediumCount,
            lowCount: lowCount
        )

        if criticalCount > 0 {
            overallStatus = .critical
        } else if highCount > 0 || mediumCount > 0 {
            overallStatus = .warnings
        } else {
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
        if remaining <= 0 { return "Scanning soon" }
        let minutes = Int(remaining / 60)
        let seconds = Int(remaining) % 60
        // "Scheduled" is explicit so users don't think this is the only
        // trigger. File-system changes also kick off scans via FSEvents,
        // which is why a scan may start long before this countdown ends.
        if minutes > 0 {
            return "Next scheduled in \(minutes)m \(seconds)s"
        } else {
            return "Next scheduled in \(seconds)s"
        }
    }
}
