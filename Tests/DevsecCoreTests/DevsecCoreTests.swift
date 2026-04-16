import Testing
@testable import DevsecCore

@Suite("DevsecCore")
struct DevsecCoreTests {
    @Test("Finding can be created")
    func findingCreation() {
        let finding = Finding(
            id: "test-finding-1",
            module: .env,
            severity: .high,
            gitRisk: .high,
            localRisk: .medium,
            description: "Test finding",
            secretPreview: "****",
            recommendation: "Remove it"
        )
        #expect(finding.module == .env)
        #expect(finding.severity == .high)
        #expect(finding.isNew == true)
    }

    @Test("Severity is Comparable")
    func severityComparable() {
        #expect(Severity.low < Severity.high)
        #expect(Severity.critical > Severity.medium)
        #expect(Severity.info < Severity.critical)
    }
}
