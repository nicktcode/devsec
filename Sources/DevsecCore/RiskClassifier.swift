import Foundation

// MARK: - RiskClassifier

public enum RiskClassifier {

    // MARK: - RiskAssessment

    public struct RiskAssessment: Sendable {
        public let severity: Severity
        public let gitRisk: RiskLevel
        public let localRisk: RiskLevel
        public let recommendation: String

        public init(severity: Severity, gitRisk: RiskLevel, localRisk: RiskLevel, recommendation: String) {
            self.severity = severity
            self.gitRisk = gitRisk
            self.localRisk = localRisk
            self.recommendation = recommendation
        }
    }

    // MARK: - Private Helpers

    private static let localDevIndicators: [String] = [
        "localhost", "127.0.0.1", "0.0.0.0", "::1", ".local", ".test", ".example"
    ]

    private static let placeholderIndicators: [String] = [
        "changeme", "your-api-key", "xxx", "todo", "replace-me",
        "django-insecure-", "dev-", "test-", "dummy", "fake",
        "EXAMPLE", "sample"
    ]

    private static let unsafeLocations: [String] = [
        "/Desktop/", "/Downloads/", "/Public/", "/Shared/"
    ]

    private static let documentExtensions: [String] = [
        ".pdf", ".docx", ".doc", ".xlsx", ".xls",
        ".pages", ".numbers", ".key", ".pptx", ".ppt", ".rtf"
    ]

    private static func isLocalDev(_ value: String) -> Bool {
        let lower = value.lowercased()
        return localDevIndicators.contains { lower.contains($0) }
    }

    private static func isPlaceholder(_ value: String) -> Bool {
        let lower = value.lowercased()
        return placeholderIndicators.contains { lower.contains($0.lowercased()) }
    }

    private static func isUnsafeLocation(_ filePath: String) -> Bool {
        unsafeLocations.contains { filePath.contains($0) }
    }

    private static func isDocument(_ filePath: String) -> Bool {
        let lower = filePath.lowercased()
        return documentExtensions.contains { lower.hasSuffix($0) }
    }

    private static func severityFrom(gitRisk: RiskLevel, localRisk: RiskLevel) -> Severity {
        let higher = max(riskLevelInt(gitRisk), riskLevelInt(localRisk))
        switch higher {
        case 4: return .critical
        case 3: return .high
        case 2: return .medium
        case 1: return .low
        default: return .info
        }
    }

    private static func riskLevelInt(_ level: RiskLevel) -> Int {
        switch level {
        case .none:     return 0
        case .low:      return 1
        case .medium:   return 2
        case .high:     return 3
        case .critical: return 4
        }
    }

    // MARK: - Public API

    /// Classify a secret value found at a given file path.
    public static func classify(
        secretValue: String,
        filePath: String,
        isInGitignore: Bool
    ) -> RiskAssessment {
        // 1Password references are properly managed
        if secretValue.contains("op://") {
            return RiskAssessment(
                severity: .info,
                gitRisk: .none,
                localRisk: .none,
                recommendation: "Secret is properly managed via 1Password (op://). No action needed."
            )
        }

        let doc = isDocument(filePath)
        let unsafe = isUnsafeLocation(filePath)
        let placeholder = isPlaceholder(secretValue)
        let localDev = isLocalDev(secretValue)

        // Git risk
        let gitRisk: RiskLevel
        if doc {
            gitRisk = .none
        } else if placeholder {
            gitRisk = .low
        } else if isInGitignore {
            gitRisk = .low
        } else {
            gitRisk = .critical
        }

        // Local risk
        let localRisk: RiskLevel
        if doc && !placeholder && !localDev {
            localRisk = .critical
        } else if unsafe && !placeholder && !localDev {
            localRisk = .critical
        } else if placeholder {
            localRisk = .low
        } else if localDev {
            localRisk = .medium
        } else {
            localRisk = .high
        }

        let severity = severityFrom(gitRisk: gitRisk, localRisk: localRisk)

        // Recommendation
        let recommendation: String
        if doc {
            recommendation = "Remove this secret from the document. Store it in 1Password and reference via op:// in your config files."
        } else if unsafe {
            recommendation = "Move this file to a secure location. Migrate the secret to 1Password and reference via op://."
        } else if !isInGitignore {
            recommendation = "Add this file to .gitignore immediately, then migrate the secret to 1Password (op://vault/item/field)."
        } else {
            recommendation = "Migrate this secret to 1Password and reference it via op://vault/item/field."
        }

        return RiskAssessment(
            severity: severity,
            gitRisk: gitRisk,
            localRisk: localRisk,
            recommendation: recommendation
        )
    }

    /// Classify a password export or credential file.
    ///
    /// - Parameters:
    ///   - filePath: Absolute path to the file.
    ///   - inspection: Format sniff from ``CredentialFileInspector``. When the
    ///     file is detected as an encrypted container (PKCS#12, Java
    ///     keystore, Firefox NSS-encrypted `logins.json`, …) we downgrade
    ///     the local severity and change the recommendation accordingly.
    ///     Encrypted-at-rest files are *not* harmless. losing one to a
    ///     public repo still exposes passphrase-protected key material, 
    ///     so the git risk stays high.
    public static func classifyCredentialFile(
        filePath: String,
        inspection: CredentialFileInspector.Inspection
    ) -> RiskAssessment {
        if inspection.isEncrypted {
            return RiskAssessment(
                severity: .medium,
                gitRisk: .high,
                localRisk: .low,
                recommendation: "\(inspection.format). Encrypted at rest, so a local copy is low risk by itself. but treat the passphrase as a secret and make sure the file is not committed to a public repo."
            )
        }

        let lower = filePath.lowercased()
        let isPasswordExport = lower.contains("password") ||
                               lower.contains("logins") ||
                               lower.contains("1password-export") ||
                               lower.contains("bitwarden-export")

        let recommendation: String
        if isPasswordExport {
            recommendation = "Delete this password export immediately. It contains all your credentials in plaintext. Password exports should never be stored on disk."
        } else {
            recommendation = "Move this credential file to a secure secret manager such as 1Password. Delete the local copy once migrated."
        }

        return RiskAssessment(
            severity: .critical,
            gitRisk: .critical,
            localRisk: .critical,
            recommendation: recommendation
        )
    }

    /// Back-compat shim: classifies as if the file were plaintext. New code
    /// should pass an ``CredentialFileInspector/Inspection``.
    public static func classifyCredentialFile(filePath: String) -> RiskAssessment {
        classifyCredentialFile(
            filePath: filePath,
            inspection: CredentialFileInspector.Inspection(isEncrypted: false, format: "plaintext")
        )
    }
}
