import Foundation

// MARK: - ScanResult

public struct ScanResult: Sendable {
    public let module: ScanModule
    public let findings: [Finding]
    public let duration: TimeInterval

    /// Paths that were discovered but not scanned because the file is an iCloud
    /// placeholder (uploaded, not locally materialized). Tracked so the UI can
    /// tell the user about coverage gaps and a later scan can pick these up
    /// once macOS has downloaded them.
    public let offloadedPaths: [String]

    public init(
        module: ScanModule,
        findings: [Finding],
        duration: TimeInterval,
        offloadedPaths: [String] = []
    ) {
        self.module = module
        self.findings = findings
        self.duration = duration
        self.offloadedPaths = offloadedPaths
    }
}

// MARK: - Progress Handler

public typealias ScanProgressHandler = @Sendable (String) -> Void

// MARK: - Scanner

public protocol Scanner: Sendable {
    var module: ScanModule { get }
    func scan(onProgress: ScanProgressHandler?) async throws -> ScanResult
}

extension Scanner {
    public func scan() async throws -> ScanResult {
        try await scan(onProgress: nil)
    }
}
