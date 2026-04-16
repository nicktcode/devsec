import Testing
@testable import DevsecCore

@Suite("RiskClassifier")
struct RiskClassifierTests {

    // MARK: - 1Password op:// References

    @Test("op:// reference returns info severity with no risks")
    func opReferenceReturnsInfoSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "op://vault/item/field",
            filePath: "/Users/user/.env",
            isInGitignore: false
        )
        #expect(result.severity == .info)
        #expect(result.gitRisk == .none)
        #expect(result.localRisk == .none)
    }

    @Test("op:// embedded in value returns info severity")
    func opReferenceEmbeddedReturnsInfoSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "prefix-op://vault/item/field",
            filePath: "/Users/user/.env",
            isInGitignore: false
        )
        #expect(result.severity == .info)
        #expect(result.gitRisk == .none)
        #expect(result.localRisk == .none)
    }

    // MARK: - Git Risk Based on Gitignore

    @Test("Plaintext in gitignore returns high severity, low git risk, high local risk")
    func plaintextInGitignoreReturnsHighSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "sk_test_abcdefghijklmnopqrstuvwxyz",
            filePath: "/Users/user/project/.env",
            isInGitignore: true
        )
        #expect(result.severity == .high)
        #expect(result.gitRisk == .low)
        #expect(result.localRisk == .high)
    }

    @Test("Plaintext NOT in gitignore returns critical severity and critical git risk")
    func plaintextNotInGitignoreReturnsCriticalSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "sk_test_abcdefghijklmnopqrstuvwxyz",
            filePath: "/Users/user/project/.env",
            isInGitignore: false
        )
        #expect(result.severity == .critical)
        #expect(result.gitRisk == .critical)
        #expect(result.localRisk == .high)
    }

    // MARK: - Local Dev Values

    @Test("localhost value returns medium local risk and medium severity")
    func localhostValueReturnsMediumSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "postgres://user:pass@localhost:5432/db",
            filePath: "/Users/user/project/.env",
            isInGitignore: true
        )
        #expect(result.severity == .medium)
        #expect(result.localRisk == .medium)
    }

    @Test("127.0.0.1 value returns medium local risk")
    func loopbackValueReturnsMediumLocalRisk() {
        let result = RiskClassifier.classify(
            secretValue: "redis://127.0.0.1:6379",
            filePath: "/Users/user/project/.env",
            isInGitignore: true
        )
        #expect(result.localRisk == .medium)
    }

    // MARK: - Unsafe File Locations

    @Test("Desktop location raises severity to critical")
    func desktopLocationRaisesToCritical() {
        let result = RiskClassifier.classify(
            secretValue: "sk_test_abcdefghijklmnopqrstuvwxyz",
            filePath: "/Users/user/Desktop/.env",
            isInGitignore: false
        )
        #expect(result.severity == .critical)
        #expect(result.localRisk == .critical)
    }

    @Test("Downloads location raises severity to critical")
    func downloadsLocationRaisesToCritical() {
        let result = RiskClassifier.classify(
            secretValue: "sk_test_abcdefghijklmnopqrstuvwxyz",
            filePath: "/Users/user/Downloads/secrets.txt",
            isInGitignore: false
        )
        #expect(result.severity == .critical)
        #expect(result.localRisk == .critical)
    }

    // MARK: - Credential Files

    @Test("Password export file returns critical severity")
    func passwordExportFileReturnsCritical() {
        let result = RiskClassifier.classifyCredentialFile(
            filePath: "/Users/user/Downloads/1password-export.csv"
        )
        #expect(result.severity == .critical)
        #expect(result.localRisk == .critical)
    }

    @Test("Generic credential file returns critical severity")
    func credentialFileReturnsCritical() {
        let result = RiskClassifier.classifyCredentialFile(
            filePath: "/Users/user/Desktop/credentials.json"
        )
        #expect(result.severity == .critical)
        #expect(result.localRisk == .critical)
    }

    @Test("Password export recommendation mentions deletion")
    func passwordExportRecommendationMentionsDeletion() {
        let result = RiskClassifier.classifyCredentialFile(
            filePath: "/Users/user/Downloads/bitwarden-export.json"
        )
        let rec = result.recommendation.lowercased()
        #expect(rec.contains("delete") || rec.contains("remove"))
    }

    // MARK: - Document Files

    @Test("Document with secret returns critical severity")
    func documentWithSecretReturnsCritical() {
        let result = RiskClassifier.classify(
            secretValue: "sk_test_abcdefghijklmnopqrstuvwxyz",
            filePath: "/Users/user/Documents/setup.docx",
            isInGitignore: false
        )
        #expect(result.severity == .critical)
        #expect(result.localRisk == .critical)
    }

    @Test("PDF with secret returns critical severity")
    func pdfWithSecretReturnsCritical() {
        let result = RiskClassifier.classify(
            secretValue: "sk_test_abcdefghijklmnopqrstuvwxyz",
            filePath: "/Users/user/Documents/guide.pdf",
            isInGitignore: false
        )
        #expect(result.severity == .critical)
        #expect(result.localRisk == .critical)
    }

    // MARK: - Placeholder Values

    @Test("Dev placeholder returns low or medium severity (<=medium)")
    func devPlaceholderReturnsLowerSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "changeme",
            filePath: "/Users/user/project/.env",
            isInGitignore: false
        )
        #expect(result.severity <= .medium)
    }

    @Test("your-api-key placeholder returns low severity")
    func yourApiKeyPlaceholderReturnsLowSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "your-api-key",
            filePath: "/Users/user/project/.env",
            isInGitignore: false
        )
        #expect(result.severity <= .medium)
        #expect(result.localRisk == .low)
    }

    @Test("xxx placeholder returns low severity")
    func xxxPlaceholderReturnsLowSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "xxx",
            filePath: "/Users/user/project/.env",
            isInGitignore: false
        )
        #expect(result.severity <= .medium)
    }

    // MARK: - Recommendations

    @Test("Recommendation for plaintext not in gitignore suggests migration to op://")
    func recommendationForPlaintextSuggestsMigration() {
        let result = RiskClassifier.classify(
            secretValue: "sk_test_abcdefghijklmnopqrstuvwxyz",
            filePath: "/Users/user/project/.env",
            isInGitignore: false
        )
        let rec = result.recommendation
        #expect(rec.contains("op://") || rec.contains("1Password"))
    }

    @Test("Recommendation for document mentions removing from doc")
    func recommendationForDocumentMentionsRemoval() {
        let result = RiskClassifier.classify(
            secretValue: "sk_test_abcdefghijklmnopqrstuvwxyz",
            filePath: "/Users/user/Documents/guide.pdf",
            isInGitignore: false
        )
        let rec = result.recommendation.lowercased()
        #expect(rec.contains("document") || rec.contains("remove") || rec.contains("delete"))
    }

    @Test("Recommendation for unsafe location mentions moving the file")
    func recommendationForUnsafeLocationMentionsMoving() {
        let result = RiskClassifier.classify(
            secretValue: "sk_test_abcdefghijklmnopqrstuvwxyz",
            filePath: "/Users/user/Desktop/secrets.env",
            isInGitignore: false
        )
        let rec = result.recommendation.lowercased()
        #expect(rec.contains("move") || rec.contains("relocate") || rec.contains("op://") || rec.contains("1password"))
    }

    // MARK: - Gitignore recommendation

    @Test("Plaintext in gitignore but not migrated still suggests op:// migration")
    func plaintextInGitignoreSuggestsMigration() {
        let result = RiskClassifier.classify(
            secretValue: "sk_test_abcdefghijklmnopqrstuvwxyz",
            filePath: "/Users/user/project/.env",
            isInGitignore: true
        )
        let rec = result.recommendation
        #expect(rec.contains("op://") || rec.contains("1Password"))
    }
}
