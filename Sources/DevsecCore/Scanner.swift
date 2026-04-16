import Foundation

// MARK: - ScanResult

public struct ScanResult: Sendable {
    public let module: ScanModule
    public let findings: [Finding]
    public let duration: TimeInterval

    public init(module: ScanModule, findings: [Finding], duration: TimeInterval) {
        self.module = module
        self.findings = findings
        self.duration = duration
    }
}

// MARK: - Scanner

public protocol Scanner: Sendable {
    var module: ScanModule { get }
    func scan() async throws -> ScanResult
}
