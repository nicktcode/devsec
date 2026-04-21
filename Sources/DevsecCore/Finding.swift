import Foundation

// MARK: - Severity

public enum Severity: String, Codable, Comparable, Sendable, CaseIterable {
    case critical
    case high
    case medium
    case low
    case info

    private var sortOrder: Int {
        switch self {
        case .critical: return 4
        case .high:     return 3
        case .medium:   return 2
        case .low:      return 1
        case .info:     return 0
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.sortOrder < rhs.sortOrder
    }
}

// MARK: - RiskLevel

public enum RiskLevel: String, Codable, Sendable, CaseIterable {
    case none
    case low
    case medium
    case high
    case critical
}

// MARK: - ScanModule

public enum ScanModule: String, Codable, Sendable, CaseIterable {
    case env               = "env"
    case history           = "history"
    case ssh               = "ssh"
    case documents         = "documents"
    case aiTools           = "ai-tools"
    case credentialFiles   = "credential-files"
    case appleNotes        = "apple-notes"
    case git               = "git"
    case ports             = "ports"
    case clipboard         = "clipboard"
    case permissions       = "permissions"
}

// MARK: - Finding

public struct Finding: Codable, Sendable, Identifiable {
    public let id: String
    public let module: ScanModule
    public let severity: Severity
    public let gitRisk: RiskLevel
    public let localRisk: RiskLevel
    public let filePath: String?
    public let lineNumber: Int?
    public let description: String
    public let secretPreview: String
    public let recommendation: String
    public let isNew: Bool

    public init(
        id: String,
        module: ScanModule,
        severity: Severity,
        gitRisk: RiskLevel,
        localRisk: RiskLevel,
        filePath: String? = nil,
        lineNumber: Int? = nil,
        description: String,
        secretPreview: String,
        recommendation: String,
        isNew: Bool = true
    ) {
        self.id = id
        self.module = module
        self.severity = severity
        self.gitRisk = gitRisk
        self.localRisk = localRisk
        self.filePath = filePath
        self.lineNumber = lineNumber
        self.description = description
        self.secretPreview = secretPreview
        self.recommendation = recommendation
        self.isNew = isNew
    }
}
