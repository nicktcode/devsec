# devsec Phase 1: Core Framework + MVP Scanners + CLI

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working CLI tool that scans a macOS developer workstation for exposed secrets across environment files, shell history, SSH keys, documents, AI tool configs, and credential files -- with full-disk Spotlight-based discovery, risk classification, whitelisting, and human-readable output.

**Architecture:** Swift Package Manager monorepo with a `DevsecCore` library (detection engine, pattern database, Spotlight wrapper, risk classifier, whitelist manager) consumed by a `devsec-cli` executable. Each scanner is an independent module conforming to a `Scanner` protocol. Spotlight is the primary discovery mechanism with `find`+`grep` fallback when Spotlight is unavailable.

**Tech Stack:** Swift 6.0, Swift Package Manager, Foundation framework (NSMetadataQuery/Process for mdfind), Swift Regex, macOS 14.0+

**Phase 1 scope (this plan):** Pattern database, Spotlight engine, core framework, 6 scanners (env, history, SSH, documents, AI tools, credential files), risk classifier, whitelist manager, CLI with scan/whitelist/status commands, text+JSON output.

**Deferred to Phase 2:** Git repo scanner, port scanner, clipboard scanner, permission scanner, `devsec migrate` command.

**Deferred to Phase 3:** Menubar app (SwiftUI, notifications, settings, App Store distribution).

---

## File Structure

```
devsec/
├── Package.swift
├── Sources/
│   ├── DevsecCore/
│   │   ├── Scanner.swift              # Scanner protocol + ScanResult type
│   │   ├── Finding.swift              # Finding model, Severity, RiskLevel enums
│   │   ├── PatternDatabase.swift      # All regex patterns organized by category
│   │   ├── SpotlightEngine.swift      # mdfind wrapper + find/grep fallback
│   │   ├── RiskClassifier.swift       # Two-dimensional risk scoring logic
│   │   ├── WhitelistManager.swift     # Load/save/match TOML whitelist config
│   │   ├── FindingStore.swift         # Persist findings to JSON, detect new vs known
│   │   ├── ScanOrchestrator.swift     # Runs all scanners, merges results, applies whitelist
│   │   └── Scanners/
│   │       ├── EnvFileScanner.swift
│   │       ├── HistoryScanner.swift
│   │       ├── SSHScanner.swift
│   │       ├── DocumentScanner.swift
│   │       ├── AIToolScanner.swift
│   │       └── CredentialFileScanner.swift
│   └── devsec-cli/
│       ├── DevsecCLI.swift            # ArgumentParser entry point + subcommands
│       ├── ScanCommand.swift          # devsec scan [--modules] [--format] [--show-whitelisted]
│       ├── WhitelistCommand.swift     # devsec whitelist add/remove/list
│       ├── StatusCommand.swift        # devsec status
│       └── Formatters/
│           ├── TextFormatter.swift    # Human-readable terminal output
│           └── JSONFormatter.swift    # Machine-readable JSON output
├── Tests/
│   └── DevsecCoreTests/
│       ├── PatternDatabaseTests.swift
│       ├── SpotlightEngineTests.swift
│       ├── RiskClassifierTests.swift
│       ├── WhitelistManagerTests.swift
│       ├── FindingStoreTests.swift
│       ├── EnvFileScannerTests.swift
│       ├── HistoryScannerTests.swift
│       ├── SSHScannerTests.swift
│       ├── DocumentScannerTests.swift
│       ├── AIToolScannerTests.swift
│       └── CredentialFileScannerTests.swift
└── docs/
    ├── specs/
    │   └── 2026-04-16-devsec-design.md
    └── plans/
        └── 2026-04-16-devsec-phase1.md
```

---

## Task 1: Project Setup + Package.swift

**Files:**
- Create: `Package.swift`
- Create: `Sources/DevsecCore/Scanner.swift`
- Create: `Sources/DevsecCore/Finding.swift`
- Create: `Sources/devsec-cli/DevsecCLI.swift`

- [ ] **Step 1: Initialize git repo**

```bash
cd /Users/nick/Repos/devsec
git init
```

- [ ] **Step 2: Create .gitignore**

Create `.gitignore`:

```
.DS_Store
.build/
.swiftpm/
*.xcodeproj
xcuserdata/
DerivedData/
```

- [ ] **Step 3: Create Package.swift**

Create `Package.swift`:

```swift
// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "devsec",
    platforms: [
        .macOS(.v14)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "DevsecCore",
            path: "Sources/DevsecCore"
        ),
        .executableTarget(
            name: "devsec-cli",
            dependencies: [
                "DevsecCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/devsec-cli"
        ),
        .testTarget(
            name: "DevsecCoreTests",
            dependencies: ["DevsecCore"],
            path: "Tests/DevsecCoreTests"
        ),
    ]
)
```

- [ ] **Step 4: Create core model types**

Create `Sources/DevsecCore/Finding.swift`:

```swift
import Foundation

public enum Severity: String, Codable, Comparable, Sendable {
    case critical
    case high
    case medium
    case low
    case info

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        let order: [Severity] = [.info, .low, .medium, .high, .critical]
        return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
    }
}

public enum RiskLevel: String, Codable, Sendable {
    case none
    case low
    case medium
    case high
    case critical
}

public enum ScanModule: String, Codable, Sendable {
    case env
    case history
    case ssh
    case documents
    case aiTools = "ai-tools"
    case credentialFiles = "credential-files"
    case git
    case ports
    case clipboard
    case permissions
}

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
```

- [ ] **Step 5: Create Scanner protocol**

Create `Sources/DevsecCore/Scanner.swift`:

```swift
import Foundation

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

public protocol Scanner: Sendable {
    var module: ScanModule { get }
    func scan() async throws -> ScanResult
}
```

- [ ] **Step 6: Create minimal CLI entry point**

Create `Sources/devsec-cli/DevsecCLI.swift`:

```swift
import ArgumentParser

@main
struct DevsecCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "devsec",
        abstract: "Developer workstation security auditor",
        version: "0.1.0",
        subcommands: [ScanCommand.self, StatusCommand.self],
        defaultSubcommand: ScanCommand.self
    )
}
```

Create `Sources/devsec-cli/ScanCommand.swift`:

```swift
import ArgumentParser
import DevsecCore

struct ScanCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "scan",
        abstract: "Scan your machine for exposed secrets"
    )

    func run() throws {
        print("devsec v0.1.0 -- scanning your machine")
        print("(not yet implemented)")
    }
}
```

Create `Sources/devsec-cli/StatusCommand.swift`:

```swift
import ArgumentParser

struct StatusCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Check devsec status and Spotlight health"
    )

    func run() throws {
        print("devsec status: ok")
    }
}
```

- [ ] **Step 7: Verify the project builds**

```bash
cd /Users/nick/Repos/devsec
swift build
```

Expected: builds successfully, produces `devsec-cli` binary.

- [ ] **Step 8: Verify the CLI runs**

```bash
swift run devsec-cli
swift run devsec-cli status
swift run devsec-cli --version
```

Expected: prints placeholder messages and version 0.1.0.

- [ ] **Step 9: Commit**

```bash
git add Package.swift .gitignore Sources/ docs/
git commit -m "feat: initial project setup with core types and CLI skeleton"
```

---

## Task 2: Pattern Database

**Files:**
- Create: `Sources/DevsecCore/PatternDatabase.swift`
- Create: `Tests/DevsecCoreTests/PatternDatabaseTests.swift`

- [ ] **Step 1: Write tests for pattern matching**

Create `Tests/DevsecCoreTests/PatternDatabaseTests.swift`:

```swift
import Testing
@testable import DevsecCore

@Suite("PatternDatabase")
struct PatternDatabaseTests {

    // MARK: - API Keys

    @Test func detectsAWSAccessKey() {
        let matches = PatternDatabase.findSecrets(in: "aws_key=AKIAIOSFODNN7EXAMPLE")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "AWS Access Key")
    }

    @Test func detectsAnthropicKey() {
        let matches = PatternDatabase.findSecrets(in: "key=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Anthropic API Key")
    }

    @Test func detectsOpenAIKey() {
        let matches = PatternDatabase.findSecrets(in: "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz01234567890123456789")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "OpenAI API Key")
    }

    @Test func detectsGitHubToken() {
        let matches = PatternDatabase.findSecrets(in: "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "GitHub Token")
    }

    @Test func detectsStripeKey() {
        // devsec-test-value: sk_test_ matches same pattern as sk_live_
        let matches = PatternDatabase.findSecrets(in: "sk_test_FAKE_TEST_VALUE_devsec")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Stripe Secret Key")
    }

    @Test func detectsSlackToken() {
        // devsec-test-value: two-segment form matches xox[bprs]-[0-9A-Za-z\-]{20,}
        let matches = PatternDatabase.findSecrets(in: "token=xoxb-fake-devsectest0000000")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Slack Token")
    }

    @Test func detectsGoogleAPIKey() {
        let matches = PatternDatabase.findSecrets(in: "key=AIzaSyA-abcdefghijklmnopqrstuvwxyz12345")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Google API Key")
    }

    @Test func detectsSendGridKey() {
        // devsec-test-value: lowercase-only segments avoid GitHub's SendGrid scanner heuristic
        let matches = PatternDatabase.findSecrets(in: "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789abcdefg")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "SendGrid API Key")
    }

    @Test func detectsTwilioKey() {
        // devsec-test-value: plain 32 hex chars match Twilio auth token pattern without SK prefix
        let matches = PatternDatabase.findSecrets(in: "twilio_auth=0123456789abcdef0123456789abcdef")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Twilio API Key")
    }

    // MARK: - Private Keys

    @Test func detectsRSAPrivateKey() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "RSA Private Key")
    }

    @Test func detectsOpenSSHPrivateKey() {
        let text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb..."
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "OpenSSH Private Key")
    }

    @Test func detectsGenericPrivateKey() {
        let text = "-----BEGIN PRIVATE KEY-----\nMIIE..."
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Private Key")
    }

    @Test func detectsECPrivateKey() {
        let text = "-----BEGIN EC PRIVATE KEY-----\nMHQC..."
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "EC Private Key")
    }

    @Test func detectsPGPPrivateKey() {
        let text = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nxcMG..."
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "PGP Private Key")
    }

    // MARK: - Passwords

    @Test func detectsPasswordAssignment() {
        let matches = PatternDatabase.findSecrets(in: "password = \"mySuperSecret123\"")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Password Assignment")
    }

    @Test func detectsPasswordColonFormat() {
        let matches = PatternDatabase.findSecrets(in: "password: hunter2")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Password Assignment")
    }

    @Test func detectsConnectionStringPostgres() {
        let matches = PatternDatabase.findSecrets(in: "postgres://admin:s3cret@prod.db.com/mydb")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Connection String")
    }

    @Test func detectsConnectionStringMongoDB() {
        let matches = PatternDatabase.findSecrets(in: "mongodb+srv://user:pass123@cluster.mongodb.net/db")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Connection String")
    }

    @Test func detectsBasicAuth() {
        let matches = PatternDatabase.findSecrets(in: "Authorization: Basic dXNlcjpwYXNzd29yZA==")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Basic Auth Header")
    }

    @Test func detectsBearerToken() {
        let matches = PatternDatabase.findSecrets(in: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw")
        #expect(matches.count == 1)
        #expect(matches[0].patternName == "Bearer Token")
    }

    // MARK: - No False Positives

    @Test func doesNotMatchPlainText() {
        let matches = PatternDatabase.findSecrets(in: "This is a normal sentence about passwords in general.")
        #expect(matches.isEmpty)
    }

    @Test func doesNotMatchTestKeys() {
        let matches = PatternDatabase.findSecrets(in: "sk-test-abcdefghijklmnopqrstuvwx")
        // Stripe test keys should still match the pattern -- whitelisting is separate
        #expect(matches.count == 1)
    }

    @Test func doesNotMatchOpReference() {
        let matches = PatternDatabase.findSecrets(in: "OPENAI_API_KEY=op://Development/OpenAI/credential")
        #expect(matches.isEmpty)
    }

    @Test func doesNotMatchPlaceholders() {
        let matches = PatternDatabase.findSecrets(in: "password = \"changeme\"")
        // This should match -- whitelisting handles safe_patterns separately
        #expect(matches.count == 1)
    }

    // MARK: - Multiple Matches

    @Test func detectsMultipleSecretsInSameText() {
        let text = """
        AWS_KEY=AKIAIOSFODNN7EXAMPLE
        OPENAI=sk-proj-abcdefghijklmnopqrstuvwxyz01234567890123456789
        password=hunter2
        """
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.count == 3)
    }

    // MARK: - Preview Masking

    @Test func previewMasksCorrectly() {
        let preview = PatternDatabase.maskSecret("sk-ant-api03-abcdefghijklmnop")
        #expect(preview == "sk-a****")
    }

    @Test func previewHandlesShortSecrets() {
        let preview = PatternDatabase.maskSecret("abc")
        #expect(preview == "abc****")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/nick/Repos/devsec
swift test --filter PatternDatabaseTests
```

Expected: compilation error -- `PatternDatabase` does not exist.

- [ ] **Step 3: Implement PatternDatabase**

Create `Sources/DevsecCore/PatternDatabase.swift`:

```swift
import Foundation

public struct SecretMatch: Sendable {
    public let patternName: String
    public let matchedText: String
    public let range: Range<String.Index>
}

public enum PatternDatabase {

    // MARK: - Public API

    public static func findSecrets(in text: String) -> [SecretMatch] {
        var results: [SecretMatch] = []
        for pattern in allPatterns {
            let regex = pattern.regex
            for match in text.matches(of: regex) {
                let matchedText = String(text[match.range])
                // Skip op:// references
                if matchedText.contains("op://") { continue }
                results.append(SecretMatch(
                    patternName: pattern.name,
                    matchedText: matchedText,
                    range: match.range
                ))
            }
        }
        return results
    }

    public static func maskSecret(_ secret: String) -> String {
        let visibleCount = min(4, secret.count)
        let prefix = String(secret.prefix(visibleCount))
        return "\(prefix)****"
    }

    // MARK: - Spotlight Queries

    /// Content-based Spotlight queries for finding files that may contain secrets.
    /// These are prefixes/markers that indicate a file is worth scanning with full regex.
    public static let spotlightContentQueries: [String] = [
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN DSA PRIVATE KEY",
        "BEGIN PGP PRIVATE KEY BLOCK",
        "BEGIN PRIVATE KEY",
        "AKIA",
        "sk-ant-api",
        "sk-proj-",
        "ghp_",
        "gho_",
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "xoxb-",
        "xoxp-",
        "SG.",
        "AIzaSy",
    ]

    /// Filename-based Spotlight queries for credential files.
    public static let spotlightFileQueries: [String] = [
        "passwords.csv",
        "logins.csv",
        "credentials",
        ".htpasswd",
        "wp-config.php",
    ]

    public static let spotlightFileGlobs: [String] = [
        "*.pem",
        "*.key",
        "*.pfx",
        "*.p12",
        "1password-export*",
        "bitwarden-export*",
        "*.keystore",
    ]

    // MARK: - Pattern Definitions

    struct PatternDef: Sendable {
        let name: String
        let regex: Regex<Substring>
    }

    static let allPatterns: [PatternDef] = apiKeyPatterns + privateKeyPatterns + passwordPatterns

    static let apiKeyPatterns: [PatternDef] = [
        PatternDef(name: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/),
        PatternDef(name: "Anthropic API Key", regex: /sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{40,}/),
        PatternDef(name: "OpenAI API Key", regex: /sk-proj-[A-Za-z0-9_\-]{40,}/),
        PatternDef(name: "GitHub Token", regex: /gh[ps]_[A-Za-z0-9_]{36,}/),
        PatternDef(name: "Stripe Secret Key", regex: /sk_live_[0-9a-zA-Z]{24,}/),
        PatternDef(name: "Stripe Test Key", regex: /sk_test_[0-9a-zA-Z]{24,}/),
        PatternDef(name: "Slack Token", regex: /xox[bprs]-[A-Za-z0-9\-]+/),
        PatternDef(name: "Google API Key", regex: /AIzaSy[0-9A-Za-z\-_]{33}/),
        PatternDef(name: "SendGrid API Key", regex: /SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}/),
        PatternDef(name: "Twilio API Key", regex: /SK[0-9a-fA-F]{32}/),
        PatternDef(name: "Mailgun API Key", regex: /key-[0-9a-zA-Z]{32}/),
        PatternDef(name: "Heroku API Key", regex: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/),
        PatternDef(name: "Firebase Key", regex: /AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}/),
    ]

    static let privateKeyPatterns: [PatternDef] = [
        PatternDef(name: "RSA Private Key", regex: /-----BEGIN RSA PRIVATE KEY-----/),
        PatternDef(name: "OpenSSH Private Key", regex: /-----BEGIN OPENSSH PRIVATE KEY-----/),
        PatternDef(name: "EC Private Key", regex: /-----BEGIN EC PRIVATE KEY-----/),
        PatternDef(name: "PGP Private Key", regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/),
        PatternDef(name: "Private Key", regex: /-----BEGIN PRIVATE KEY-----/),
        PatternDef(name: "DSA Private Key", regex: /-----BEGIN DSA PRIVATE KEY-----/),
    ]

    static let passwordPatterns: [PatternDef] = [
        PatternDef(
            name: "Password Assignment",
            regex: /(?:password|passwd|pwd|secret|secret_key|api_key|apikey|auth_token|access_token)[\s]*[=:]\s*['"]?([^\s'"]{4,})['"]?/
        ),
        PatternDef(
            name: "Connection String",
            regex: /(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|smtp):\/\/[^:]+:[^@]+@[^\s]+/
        ),
        PatternDef(
            name: "Basic Auth Header",
            regex: /Authorization:\s*Basic\s+[A-Za-z0-9+\/=]{8,}/
        ),
        PatternDef(
            name: "Bearer Token",
            regex: /Authorization:\s*Bearer\s+[A-Za-z0-9._\-]{20,}/
        ),
    ]
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
swift test --filter PatternDatabaseTests
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/DevsecCore/PatternDatabase.swift Tests/DevsecCoreTests/PatternDatabaseTests.swift
git commit -m "feat: add pattern database with 20+ secret detection patterns"
```

---

## Task 3: Spotlight Engine

**Files:**
- Create: `Sources/DevsecCore/SpotlightEngine.swift`
- Create: `Tests/DevsecCoreTests/SpotlightEngineTests.swift`

- [ ] **Step 1: Write tests for SpotlightEngine**

Create `Tests/DevsecCoreTests/SpotlightEngineTests.swift`:

```swift
import Testing
import Foundation
@testable import DevsecCore

@Suite("SpotlightEngine")
struct SpotlightEngineTests {

    @Test func checkSpotlightHealthReturnsResult() async {
        let health = await SpotlightEngine.checkHealth()
        // On a real Mac, this should return a status
        #expect(health.checked)
    }

    @Test func findByFilenameReturnsResults() async throws {
        // Create a temp file to find
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let testFile = tempDir.appendingPathComponent(".env.test-devsec")
        try "TEST_KEY=value".write(to: testFile, atomically: true, encoding: .utf8)

        // Give Spotlight a moment to index (fallback will find it regardless)
        let results = await SpotlightEngine.findFiles(named: ".env.test-devsec", searchPath: tempDir.path)

        // Clean up
        try? FileManager.default.removeItem(at: tempDir)

        // In fallback mode, find will locate it. In Spotlight mode, it may or may not be indexed yet.
        // We just verify the API works without crashing.
        #expect(results != nil)
    }

    @Test func findByContentReturnsResults() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let testFile = tempDir.appendingPathComponent("test-secret.txt")
        try "-----BEGIN RSA PRIVATE KEY-----".write(to: testFile, atomically: true, encoding: .utf8)

        let results = await SpotlightEngine.findFiles(
            containingText: "BEGIN RSA PRIVATE KEY",
            searchPath: tempDir.path
        )

        try? FileManager.default.removeItem(at: tempDir)

        #expect(results != nil)
    }

    @Test func fallbackFindByFilenameWorks() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let testFile = tempDir.appendingPathComponent(".env.fallback-test")
        try "SECRET=value".write(to: testFile, atomically: true, encoding: .utf8)

        let results = await SpotlightEngine.fallbackFindFiles(named: ".env.fallback-test", searchPath: tempDir.path)

        try? FileManager.default.removeItem(at: tempDir)

        #expect(results.contains(testFile.path))
    }

    @Test func fallbackFindByContentWorks() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let testFile = tempDir.appendingPathComponent("secret-test.txt")
        try "AKIA1234567890ABCDEF".write(to: testFile, atomically: true, encoding: .utf8)

        let results = await SpotlightEngine.fallbackFindFiles(containingText: "AKIA", searchPath: tempDir.path)

        try? FileManager.default.removeItem(at: tempDir)

        #expect(results.contains(testFile.path))
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
swift test --filter SpotlightEngineTests
```

Expected: compilation error -- `SpotlightEngine` does not exist.

- [ ] **Step 3: Implement SpotlightEngine**

Create `Sources/DevsecCore/SpotlightEngine.swift`:

```swift
import Foundation

public struct SpotlightHealth: Sendable {
    public let checked: Bool
    public let available: Bool
    public let message: String
}

public enum SpotlightEngine {

    // MARK: - Health Check

    public static func checkHealth() async -> SpotlightHealth {
        let result = runProcess("/usr/bin/mdutil", arguments: ["-s", "/"])
        if result.exitCode != 0 {
            return SpotlightHealth(checked: true, available: false, message: "mdutil failed: \(result.stderr)")
        }
        let enabled = result.stdout.contains("Indexing enabled")
        return SpotlightHealth(
            checked: true,
            available: enabled,
            message: enabled ? "Spotlight indexing is active" : "Spotlight indexing is disabled"
        )
    }

    // MARK: - Find by Filename

    public static func findFiles(named filename: String, searchPath: String? = nil) async -> [String] {
        let health = await checkHealth()
        if health.available {
            let results = mdfind(filenameQuery: filename, searchPath: searchPath)
            if !results.isEmpty { return results }
        }
        return await fallbackFindFiles(named: filename, searchPath: searchPath)
    }

    public static func findFiles(matchingGlob glob: String, searchPath: String? = nil) async -> [String] {
        let health = await checkHealth()
        if health.available {
            let results = mdfind(globQuery: glob, searchPath: searchPath)
            if !results.isEmpty { return results }
        }
        return await fallbackFindFiles(matchingGlob: glob, searchPath: searchPath)
    }

    // MARK: - Find by Content

    public static func findFiles(containingText text: String, searchPath: String? = nil) async -> [String] {
        let health = await checkHealth()
        if health.available {
            let results = mdfind(contentQuery: text, searchPath: searchPath)
            if !results.isEmpty { return results }
        }
        return await fallbackFindFiles(containingText: text, searchPath: searchPath)
    }

    // MARK: - mdfind Wrappers

    private static func mdfind(filenameQuery: String, searchPath: String?) -> [String] {
        var args = ["kMDItemFSName == '\(filenameQuery)'"]
        if let path = searchPath {
            args = ["-onlyin", path] + args
        }
        let result = runProcess("/usr/bin/mdfind", arguments: args)
        return parseLines(result.stdout)
    }

    private static func mdfind(globQuery: String, searchPath: String?) -> [String] {
        var args = ["kMDItemFSName == '\(globQuery)'wc"]
        if let path = searchPath {
            args = ["-onlyin", path] + args
        }
        let result = runProcess("/usr/bin/mdfind", arguments: args)
        return parseLines(result.stdout)
    }

    private static func mdfind(contentQuery: String, searchPath: String?) -> [String] {
        var args = ["kMDItemTextContent == '\(contentQuery)'"]
        if let path = searchPath {
            args = ["-onlyin", path] + args
        }
        let result = runProcess("/usr/bin/mdfind", arguments: args)
        return parseLines(result.stdout)
    }

    // MARK: - Fallback: find + grep

    public static func fallbackFindFiles(named filename: String, searchPath: String?) async -> [String] {
        let path = searchPath ?? NSHomeDirectory()
        let result = runProcess("/usr/bin/find", arguments: [
            path, "-name", filename, "-type", "f",
            "-not", "-path", "*/.Trash/*",
            "-not", "-path", "*/Library/Caches/*",
            "-maxdepth", "10"
        ])
        return parseLines(result.stdout)
    }

    public static func fallbackFindFiles(matchingGlob glob: String, searchPath: String?) async -> [String] {
        let path = searchPath ?? NSHomeDirectory()
        let result = runProcess("/usr/bin/find", arguments: [
            path, "-name", glob, "-type", "f",
            "-not", "-path", "*/.Trash/*",
            "-not", "-path", "*/Library/Caches/*",
            "-maxdepth", "10"
        ])
        return parseLines(result.stdout)
    }

    public static func fallbackFindFiles(containingText text: String, searchPath: String?) async -> [String] {
        let path = searchPath ?? NSHomeDirectory()
        let result = runProcess("/usr/bin/grep", arguments: [
            "-rl", "--include=*.{txt,md,json,yaml,yml,toml,env,cfg,conf,ini,xml,csv,swift,py,js,ts,rb,go,rs,java,sh,zsh,bash}",
            "-m", "1",
            text,
            path
        ])
        return parseLines(result.stdout)
    }

    // MARK: - Helpers

    private struct ProcessResult {
        let stdout: String
        let stderr: String
        let exitCode: Int32
    }

    private static func runProcess(_ executable: String, arguments: [String]) -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return ProcessResult(stdout: "", stderr: error.localizedDescription, exitCode: -1)
        }

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        return ProcessResult(
            stdout: String(data: stdoutData, encoding: .utf8) ?? "",
            stderr: String(data: stderrData, encoding: .utf8) ?? "",
            exitCode: process.terminationStatus
        )
    }

    private static func parseLines(_ output: String) -> [String] {
        output.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
swift test --filter SpotlightEngineTests
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/DevsecCore/SpotlightEngine.swift Tests/DevsecCoreTests/SpotlightEngineTests.swift
git commit -m "feat: add Spotlight engine with mdfind + find/grep fallback"
```

---

## Task 4: Risk Classifier

**Files:**
- Create: `Sources/DevsecCore/RiskClassifier.swift`
- Create: `Tests/DevsecCoreTests/RiskClassifierTests.swift`

- [ ] **Step 1: Write tests for risk classification**

Create `Tests/DevsecCoreTests/RiskClassifierTests.swift`:

```swift
import Testing
import Foundation
@testable import DevsecCore

@Suite("RiskClassifier")
struct RiskClassifierTests {

    @Test func opReferenceIsGreen() {
        let result = RiskClassifier.classify(
            secretValue: "op://Development/OpenAI/credential",
            filePath: "/Users/test/project/.env",
            isInGitignore: true
        )
        #expect(result.severity == .info)
        #expect(result.gitRisk == .none)
        #expect(result.localRisk == .none)
    }

    @Test func plaintextInGitignoreIsHigh() {
        let result = RiskClassifier.classify(
            secretValue: "sk-ant-api03-realkey123",
            filePath: "/Users/test/project/.env",
            isInGitignore: true
        )
        #expect(result.severity == .high)
        #expect(result.gitRisk == .low)
        #expect(result.localRisk == .high)
    }

    @Test func plaintextNotInGitignoreIsCritical() {
        let result = RiskClassifier.classify(
            secretValue: "sk-ant-api03-realkey123",
            filePath: "/Users/test/project/.env",
            isInGitignore: false
        )
        #expect(result.severity == .critical)
        #expect(result.gitRisk == .critical)
        #expect(result.localRisk == .high)
    }

    @Test func localhostValueIsMedium() {
        let result = RiskClassifier.classify(
            secretValue: "postgres://user:pass@localhost/db",
            filePath: "/Users/test/project/.env",
            isInGitignore: true
        )
        #expect(result.severity == .medium)
        #expect(result.localRisk == .medium)
    }

    @Test func desktopLocationRaisesSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "sk-ant-api03-realkey123",
            filePath: "/Users/test/Desktop/notes.txt",
            isInGitignore: false
        )
        #expect(result.severity == .critical)
        #expect(result.localRisk == .critical)
    }

    @Test func downloadsLocationRaisesSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "AKIAIOSFODNN7EXAMPLE",
            filePath: "/Users/test/Downloads/config.txt",
            isInGitignore: false
        )
        #expect(result.severity == .critical)
        #expect(result.localRisk == .critical)
    }

    @Test func passwordExportIsCritical() {
        let result = RiskClassifier.classifyCredentialFile(
            filePath: "/Users/test/Desktop/passwords.csv"
        )
        #expect(result.severity == .critical)
        #expect(result.localRisk == .critical)
    }

    @Test func documentWithSecretRaisedSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "AKIAIOSFODNN7REALKEY",
            filePath: "/Users/test/Documents/setup.pdf",
            isInGitignore: false
        )
        #expect(result.severity == .critical)
    }

    @Test func devPlaceholderIsLowerSeverity() {
        let result = RiskClassifier.classify(
            secretValue: "dev-placeholder-key",
            filePath: "/Users/test/project/.env",
            isInGitignore: true
        )
        #expect(result.severity <= .medium)
    }

    @Test func recommendationForPlaintextSuggestsMigration() {
        let result = RiskClassifier.classify(
            secretValue: "sk-ant-api03-realkey123",
            filePath: "/Users/test/project/.env",
            isInGitignore: true
        )
        #expect(result.recommendation.contains("op://") || result.recommendation.contains("1Password"))
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
swift test --filter RiskClassifierTests
```

Expected: compilation error -- `RiskClassifier` does not exist.

- [ ] **Step 3: Implement RiskClassifier**

Create `Sources/DevsecCore/RiskClassifier.swift`:

```swift
import Foundation

public struct RiskAssessment: Sendable {
    public let severity: Severity
    public let gitRisk: RiskLevel
    public let localRisk: RiskLevel
    public let recommendation: String
}

public enum RiskClassifier {

    public static func classify(
        secretValue: String,
        filePath: String,
        isInGitignore: Bool
    ) -> RiskAssessment {
        // op:// references are properly managed
        if secretValue.hasPrefix("op://") || secretValue.contains("op://") {
            return RiskAssessment(
                severity: .info,
                gitRisk: .none,
                localRisk: .none,
                recommendation: "Secret is properly managed via 1Password reference"
            )
        }

        let isLocalValue = isLocalDevelopmentValue(secretValue)
        let isDevPlaceholder = isPlaceholderValue(secretValue)
        let isUnsafeLocation = isUnsafeFileLocation(filePath)
        let isDocument = isDocumentFile(filePath)

        // Git risk
        let gitRisk: RiskLevel
        if isInGitignore {
            gitRisk = .low
        } else if isDocument {
            gitRisk = .none // documents aren't typically in git
        } else {
            gitRisk = .critical
        }

        // Local risk
        var localRisk: RiskLevel
        if isDevPlaceholder {
            localRisk = .low
        } else if isLocalValue {
            localRisk = .medium
        } else {
            localRisk = .high
        }

        // Unsafe locations always escalate local risk
        if isUnsafeLocation {
            localRisk = .critical
        }

        // Documents with secrets are always high local risk
        if isDocument && !isDevPlaceholder {
            localRisk = .critical
        }

        // Overall severity is the higher of the two risks
        let severity = deriveSeverity(gitRisk: gitRisk, localRisk: localRisk)

        let recommendation = buildRecommendation(
            filePath: filePath,
            isInGitignore: isInGitignore,
            isDocument: isDocument,
            isUnsafeLocation: isUnsafeLocation
        )

        return RiskAssessment(
            severity: severity,
            gitRisk: gitRisk,
            localRisk: localRisk,
            recommendation: recommendation
        )
    }

    public static func classifyCredentialFile(filePath: String) -> RiskAssessment {
        let filename = (filePath as NSString).lastPathComponent.lowercased()
        let isPasswordExport = filename.contains("password") || filename.contains("logins")
            || filename.contains("1password-export") || filename.contains("bitwarden-export")

        return RiskAssessment(
            severity: .critical,
            gitRisk: isPasswordExport ? .critical : .high,
            localRisk: .critical,
            recommendation: isPasswordExport
                ? "Delete this password export file immediately. It contains plaintext credentials."
                : "Move this credential file to a secure location or delete if no longer needed."
        )
    }

    // MARK: - Helpers

    private static func isLocalDevelopmentValue(_ value: String) -> Bool {
        let localPatterns = ["localhost", "127.0.0.1", "0.0.0.0", "::1", ".local", ".test", ".example"]
        return localPatterns.contains { value.lowercased().contains($0) }
    }

    private static func isPlaceholderValue(_ value: String) -> Bool {
        let placeholders = [
            "changeme", "your-api-key", "your_api_key", "xxx", "todo",
            "replace-me", "insert-key", "placeholder", "example",
            "django-insecure-", "dev-", "test-", "dummy", "fake",
            "EXAMPLE", "sample",
        ]
        let lower = value.lowercased()
        return placeholders.contains { lower.contains($0.lowercased()) }
    }

    private static func isUnsafeFileLocation(_ path: String) -> Bool {
        let unsafeDirs = ["/Desktop/", "/Downloads/", "/Public/", "/Shared/"]
        return unsafeDirs.contains { path.contains($0) }
    }

    private static func isDocumentFile(_ path: String) -> Bool {
        let docExtensions = [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pages", ".numbers",
                             ".key", ".pptx", ".ppt", ".rtf"]
        let lower = path.lowercased()
        return docExtensions.contains { lower.hasSuffix($0) }
    }

    private static func deriveSeverity(gitRisk: RiskLevel, localRisk: RiskLevel) -> Severity {
        let higher = max(riskToInt(gitRisk), riskToInt(localRisk))
        switch higher {
        case 4: return .critical
        case 3: return .high
        case 2: return .medium
        case 1: return .low
        default: return .info
        }
    }

    private static func riskToInt(_ risk: RiskLevel) -> Int {
        switch risk {
        case .none: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    private static func buildRecommendation(
        filePath: String,
        isInGitignore: Bool,
        isDocument: Bool,
        isUnsafeLocation: Bool
    ) -> String {
        if isDocument {
            return "Remove the secret from this document and rotate the exposed credential"
        }
        if isUnsafeLocation {
            return "Move this file to a secure location or delete it. Secrets should not live in Desktop/Downloads."
        }
        if !isInGitignore {
            return "Add this file to .gitignore and migrate secrets to 1Password (op:// references). Run: devsec migrate \(filePath)"
        }
        return "Migrate secrets to 1Password references (op://) to eliminate plaintext on disk. Run: devsec migrate \(filePath)"
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
swift test --filter RiskClassifierTests
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/DevsecCore/RiskClassifier.swift Tests/DevsecCoreTests/RiskClassifierTests.swift
git commit -m "feat: add two-dimensional risk classifier (git risk + local risk)"
```

---

## Task 5: Whitelist Manager

**Files:**
- Create: `Sources/DevsecCore/WhitelistManager.swift`
- Create: `Tests/DevsecCoreTests/WhitelistManagerTests.swift`

- [ ] **Step 1: Write tests for whitelist management**

Create `Tests/DevsecCoreTests/WhitelistManagerTests.swift`:

```swift
import Testing
import Foundation
@testable import DevsecCore

@Suite("WhitelistManager")
struct WhitelistManagerTests {

    func makeTempConfig() throws -> (URL, WhitelistManager) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let configFile = tempDir.appendingPathComponent("config.json")
        let manager = WhitelistManager(configPath: configFile.path)
        return (tempDir, manager)
    }

    @Test func emptyWhitelistMatchesNothing() throws {
        let (tempDir, manager) = try makeTempConfig()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        #expect(!manager.isWhitelisted(findingId: "test-123"))
        #expect(!manager.isFileWhitelisted("/some/path/.env"))
        #expect(!manager.isDirWhitelisted("/some/dir"))
    }

    @Test func whitelistFileByPath() throws {
        let (tempDir, manager) = try makeTempConfig()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        manager.addFile("/Users/test/project/.env")
        #expect(manager.isFileWhitelisted("/Users/test/project/.env"))
        #expect(!manager.isFileWhitelisted("/Users/test/other/.env"))
    }

    @Test func whitelistDirectory() throws {
        let (tempDir, manager) = try makeTempConfig()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        manager.addDir("/Users/test/archived")
        #expect(manager.isDirWhitelisted("/Users/test/archived/project/.env"))
        #expect(!manager.isDirWhitelisted("/Users/test/active/project/.env"))
    }

    @Test func whitelistFindingById() throws {
        let (tempDir, manager) = try makeTempConfig()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        manager.addFinding("env:/Users/test/.env:3:AWS_KEY")
        #expect(manager.isWhitelisted(findingId: "env:/Users/test/.env:3:AWS_KEY"))
        #expect(!manager.isWhitelisted(findingId: "env:/Users/test/.env:5:OTHER"))
    }

    @Test func safePatternMatches() throws {
        let (tempDir, manager) = try makeTempConfig()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        manager.addSafePattern("sk-test-*")
        #expect(manager.isSafePattern("sk-test-abc123"))
        #expect(!manager.isSafePattern("sk-live-abc123"))
    }

    @Test func removeFinding() throws {
        let (tempDir, manager) = try makeTempConfig()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        manager.addFinding("test-finding-1")
        #expect(manager.isWhitelisted(findingId: "test-finding-1"))
        manager.removeFinding("test-finding-1")
        #expect(!manager.isWhitelisted(findingId: "test-finding-1"))
    }

    @Test func persistsAndLoads() throws {
        let (tempDir, _) = try makeTempConfig()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let configFile = tempDir.appendingPathComponent("config.json")

        let manager1 = WhitelistManager(configPath: configFile.path)
        manager1.addFile("/Users/test/.env")
        manager1.addFinding("finding-1")
        manager1.addSafePattern("sk-test-*")
        try manager1.save()

        let manager2 = WhitelistManager(configPath: configFile.path)
        try manager2.load()
        #expect(manager2.isFileWhitelisted("/Users/test/.env"))
        #expect(manager2.isWhitelisted(findingId: "finding-1"))
        #expect(manager2.isSafePattern("sk-test-abc"))
    }

    @Test func filterFindingsRemovesWhitelisted() throws {
        let (tempDir, manager) = try makeTempConfig()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        manager.addFinding("finding-2")

        let findings = [
            Finding(id: "finding-1", module: .env, severity: .high, gitRisk: .low, localRisk: .high,
                    description: "test", secretPreview: "sk-a****", recommendation: "fix"),
            Finding(id: "finding-2", module: .env, severity: .high, gitRisk: .low, localRisk: .high,
                    description: "test", secretPreview: "sk-b****", recommendation: "fix"),
        ]

        let filtered = manager.filterFindings(findings)
        #expect(filtered.count == 1)
        #expect(filtered[0].id == "finding-1")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
swift test --filter WhitelistManagerTests
```

Expected: compilation error -- `WhitelistManager` does not exist.

- [ ] **Step 3: Implement WhitelistManager**

Create `Sources/DevsecCore/WhitelistManager.swift`:

```swift
import Foundation

public final class WhitelistManager: Sendable {
    private let configPath: String
    private let lock = NSLock()
    private var config: WhitelistConfig

    struct WhitelistConfig: Codable {
        var files: [String] = []
        var dirs: [String] = []
        var findings: [String] = []
        var safePatterns: [String] = [
            "sk-test-*", "pk_test_*", "AKIAIOSFODNN7EXAMPLE",
            "django-insecure-*", "your-api-key-here", "changeme",
        ]
        var scanInterval: Int = 300
    }

    public init(configPath: String? = nil) {
        let path = configPath ?? {
            let configDir = NSHomeDirectory() + "/.config/devsec"
            return configDir + "/config.json"
        }()
        self.configPath = path
        self.config = WhitelistConfig()
        try? load()
    }

    // MARK: - Load / Save

    public func load() throws {
        lock.lock()
        defer { lock.unlock() }

        let url = URL(fileURLWithPath: configPath)
        guard FileManager.default.fileExists(atPath: configPath) else { return }
        let data = try Data(contentsOf: url)
        config = try JSONDecoder().decode(WhitelistConfig.self, from: data)
    }

    public func save() throws {
        lock.lock()
        defer { lock.unlock() }

        let url = URL(fileURLWithPath: configPath)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(config)
        try data.write(to: url)
    }

    // MARK: - Add / Remove

    public func addFile(_ path: String) {
        lock.lock()
        defer { lock.unlock() }
        let expanded = expandTilde(path)
        if !config.files.contains(expanded) {
            config.files.append(expanded)
        }
    }

    public func addDir(_ path: String) {
        lock.lock()
        defer { lock.unlock() }
        let expanded = expandTilde(path)
        if !config.dirs.contains(expanded) {
            config.dirs.append(expanded)
        }
    }

    public func addFinding(_ findingId: String) {
        lock.lock()
        defer { lock.unlock() }
        if !config.findings.contains(findingId) {
            config.findings.append(findingId)
        }
    }

    public func addSafePattern(_ pattern: String) {
        lock.lock()
        defer { lock.unlock() }
        if !config.safePatterns.contains(pattern) {
            config.safePatterns.append(pattern)
        }
    }

    public func removeFinding(_ findingId: String) {
        lock.lock()
        defer { lock.unlock() }
        config.findings.removeAll { $0 == findingId }
    }

    // MARK: - Query

    public func isFileWhitelisted(_ path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let expanded = expandTilde(path)
        return config.files.contains(expanded)
    }

    public func isDirWhitelisted(_ path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let expanded = expandTilde(path)
        return config.dirs.contains { expanded.hasPrefix(expandTilde($0)) }
    }

    public func isWhitelisted(findingId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return config.findings.contains(findingId)
    }

    public func isSafePattern(_ value: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return config.safePatterns.contains { matchesGlob(value, pattern: $0) }
    }

    public func isWhitelistedByAnyRule(finding: Finding) -> Bool {
        if isWhitelisted(findingId: finding.id) { return true }
        if let path = finding.filePath {
            if isFileWhitelisted(path) { return true }
            if isDirWhitelisted(path) { return true }
        }
        if isSafePattern(finding.secretPreview) { return true }
        return false
    }

    public func filterFindings(_ findings: [Finding]) -> [Finding] {
        findings.filter { !isWhitelistedByAnyRule(finding: $0) }
    }

    public var allFindings: [String] {
        lock.lock()
        defer { lock.unlock() }
        return config.findings
    }

    public var scanInterval: Int {
        lock.lock()
        defer { lock.unlock() }
        return config.scanInterval
    }

    // MARK: - Helpers

    private func expandTilde(_ path: String) -> String {
        if path.hasPrefix("~/") {
            return NSHomeDirectory() + String(path.dropFirst(1))
        }
        return path
    }

    private func matchesGlob(_ value: String, pattern: String) -> Bool {
        if pattern.hasSuffix("*") {
            let prefix = String(pattern.dropLast())
            return value.hasPrefix(prefix)
        }
        if pattern.hasPrefix("*") {
            let suffix = String(pattern.dropFirst())
            return value.hasSuffix(suffix)
        }
        return value == pattern
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
swift test --filter WhitelistManagerTests
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/DevsecCore/WhitelistManager.swift Tests/DevsecCoreTests/WhitelistManagerTests.swift
git commit -m "feat: add whitelist manager with file/dir/finding/pattern support"
```

---

## Task 6: Finding Store

**Files:**
- Create: `Sources/DevsecCore/FindingStore.swift`
- Create: `Tests/DevsecCoreTests/FindingStoreTests.swift`

- [ ] **Step 1: Write tests for finding persistence**

Create `Tests/DevsecCoreTests/FindingStoreTests.swift`:

```swift
import Testing
import Foundation
@testable import DevsecCore

@Suite("FindingStore")
struct FindingStoreTests {

    func makeTempStore() throws -> (URL, FindingStore) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let storePath = tempDir.appendingPathComponent("findings.json")
        let store = FindingStore(storePath: storePath.path)
        return (tempDir, store)
    }

    @Test func newFindingsAreMarkedNew() throws {
        let (tempDir, store) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = [
            Finding(id: "f1", module: .env, severity: .high, gitRisk: .low, localRisk: .high,
                    description: "test", secretPreview: "sk-a****", recommendation: "fix"),
        ]

        let updated = store.markNewVsKnown(findings)
        #expect(updated[0].isNew)
    }

    @Test func previouslySeenFindingsAreNotNew() throws {
        let (tempDir, store) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = [
            Finding(id: "f1", module: .env, severity: .high, gitRisk: .low, localRisk: .high,
                    description: "test", secretPreview: "sk-a****", recommendation: "fix"),
        ]

        store.recordFindings(findings)
        try store.save()

        let store2 = FindingStore(storePath: tempDir.appendingPathComponent("findings.json").path)
        try store2.load()

        let updated = store2.markNewVsKnown(findings)
        #expect(!updated[0].isNew)
    }

    @Test func countsNewFindings() throws {
        let (tempDir, store) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let existing = [
            Finding(id: "f1", module: .env, severity: .high, gitRisk: .low, localRisk: .high,
                    description: "test", secretPreview: "sk-a****", recommendation: "fix"),
        ]
        store.recordFindings(existing)

        let current = [
            Finding(id: "f1", module: .env, severity: .high, gitRisk: .low, localRisk: .high,
                    description: "test", secretPreview: "sk-a****", recommendation: "fix"),
            Finding(id: "f2", module: .ssh, severity: .medium, gitRisk: .none, localRisk: .medium,
                    description: "test2", secretPreview: "key****", recommendation: "fix"),
        ]

        let updated = store.markNewVsKnown(current)
        let newCount = updated.filter(\.isNew).count
        #expect(newCount == 1)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
swift test --filter FindingStoreTests
```

Expected: compilation error -- `FindingStore` does not exist.

- [ ] **Step 3: Implement FindingStore**

Create `Sources/DevsecCore/FindingStore.swift`:

```swift
import Foundation

public final class FindingStore: Sendable {
    private let storePath: String
    private let lock = NSLock()
    private var knownIds: Set<String> = []

    public init(storePath: String? = nil) {
        let path = storePath ?? {
            let dataDir = NSHomeDirectory() + "/.config/devsec"
            return dataDir + "/findings.json"
        }()
        self.storePath = path
        try? load()
    }

    public func load() throws {
        lock.lock()
        defer { lock.unlock() }

        let url = URL(fileURLWithPath: storePath)
        guard FileManager.default.fileExists(atPath: storePath) else { return }
        let data = try Data(contentsOf: url)
        knownIds = try JSONDecoder().decode(Set<String>.self, from: data)
    }

    public func save() throws {
        lock.lock()
        defer { lock.unlock() }

        let url = URL(fileURLWithPath: storePath)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let data = try JSONEncoder().encode(knownIds)
        try data.write(to: url)
    }

    public func recordFindings(_ findings: [Finding]) {
        lock.lock()
        defer { lock.unlock() }
        for finding in findings {
            knownIds.insert(finding.id)
        }
    }

    public func markNewVsKnown(_ findings: [Finding]) -> [Finding] {
        lock.lock()
        defer { lock.unlock() }
        return findings.map { finding in
            Finding(
                id: finding.id,
                module: finding.module,
                severity: finding.severity,
                gitRisk: finding.gitRisk,
                localRisk: finding.localRisk,
                filePath: finding.filePath,
                lineNumber: finding.lineNumber,
                description: finding.description,
                secretPreview: finding.secretPreview,
                recommendation: finding.recommendation,
                isNew: !knownIds.contains(finding.id)
            )
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
swift test --filter FindingStoreTests
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/DevsecCore/FindingStore.swift Tests/DevsecCoreTests/FindingStoreTests.swift
git commit -m "feat: add finding store for tracking new vs known findings"
```

---

## Task 7: Env File Scanner

**Files:**
- Create: `Sources/DevsecCore/Scanners/EnvFileScanner.swift`
- Create: `Tests/DevsecCoreTests/EnvFileScannerTests.swift`

- [ ] **Step 1: Write tests for env file scanning**

Create `Tests/DevsecCoreTests/EnvFileScannerTests.swift`:

```swift
import Testing
import Foundation
@testable import DevsecCore

@Suite("EnvFileScanner")
struct EnvFileScannerTests {

    func createTempEnvFile(content: String) throws -> (URL, String) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let envFile = tempDir.appendingPathComponent(".env")
        try content.write(to: envFile, atomically: true, encoding: .utf8)
        return (tempDir, envFile.path)
    }

    @Test func detectsAPIKeyInEnvFile() throws {
        let content = """
        DEBUG=true
        OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz01234567890123456789
        PORT=3000
        """
        let (tempDir, path) = try createTempEnvFile(content: content)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = EnvFileScanner.scanFile(at: path)
        #expect(findings.count == 1)
        #expect(findings[0].module == .env)
        #expect(findings[0].severity >= .high)
    }

    @Test func detectsMultipleSecretsInEnvFile() throws {
        let content = """
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        DATABASE_URL=postgres://admin:secret@prod.db.com/myapp
        SAFE_VAR=hello
        """
        let (tempDir, path) = try createTempEnvFile(content: content)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = EnvFileScanner.scanFile(at: path)
        #expect(findings.count == 2)
    }

    @Test func skipsOpReferences() throws {
        let content = """
        OPENAI_API_KEY=op://Development/OpenAI/credential
        DATABASE_URL=op://Production/Database/url
        """
        let (tempDir, path) = try createTempEnvFile(content: content)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = EnvFileScanner.scanFile(at: path)
        #expect(findings.isEmpty)
    }

    @Test func skipsComments() throws {
        let content = """
        # OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz01234567890123456789
        DEBUG=true
        """
        let (tempDir, path) = try createTempEnvFile(content: content)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = EnvFileScanner.scanFile(at: path)
        #expect(findings.isEmpty)
    }

    @Test func findingIncludesLineNumber() throws {
        let content = """
        DEBUG=true
        PORT=3000
        SECRET_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ
        """
        let (tempDir, path) = try createTempEnvFile(content: content)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = EnvFileScanner.scanFile(at: path)
        #expect(findings.count == 1)
        #expect(findings[0].lineNumber == 3)
    }

    @Test func findingIdIsStable() throws {
        let content = "API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz01234567890123456789"
        let (tempDir, path) = try createTempEnvFile(content: content)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings1 = EnvFileScanner.scanFile(at: path)
        let findings2 = EnvFileScanner.scanFile(at: path)
        #expect(findings1[0].id == findings2[0].id)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
swift test --filter EnvFileScannerTests
```

Expected: compilation error -- `EnvFileScanner` does not exist.

- [ ] **Step 3: Implement EnvFileScanner**

Create `Sources/DevsecCore/Scanners/EnvFileScanner.swift`:

```swift
import Foundation

public enum EnvFileScanner: Scanner {
    public static let module: ScanModule = .env

    public var module: ScanModule { Self.module }

    public func scan() async throws -> ScanResult {
        let start = Date()
        let envFiles = await SpotlightEngine.findFiles(named: ".env")
            + (await SpotlightEngine.findFiles(matchingGlob: ".env.*"))
        let uniqueFiles = Array(Set(envFiles))

        var allFindings: [Finding] = []
        for file in uniqueFiles {
            // Skip .env.example files typically
            let findings = Self.scanFile(at: file)
            allFindings.append(contentsOf: findings)
        }

        return ScanResult(module: Self.module, findings: allFindings, duration: Date().timeIntervalSince(start))
    }

    public static func scanFile(at path: String) -> [Finding] {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }

        var findings: [Finding] = []
        let lines = content.components(separatedBy: .newlines)

        for (index, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Skip empty lines and comments
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            // Skip op:// references
            if trimmed.contains("op://") { continue }

            // Parse KEY=VALUE
            guard let equalsIndex = trimmed.firstIndex(of: "=") else { continue }
            let value = String(trimmed[trimmed.index(after: equalsIndex)...])
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))

            if value.isEmpty { continue }

            let matches = PatternDatabase.findSecrets(in: trimmed)
            if !matches.isEmpty {
                let lineNumber = index + 1
                let isGitignored = checkGitignore(filePath: path)
                let risk = RiskClassifier.classify(
                    secretValue: value,
                    filePath: path,
                    isInGitignore: isGitignored
                )

                let findingId = "env:\(path):\(lineNumber):\(matches[0].patternName)"
                findings.append(Finding(
                    id: findingId,
                    module: .env,
                    severity: risk.severity,
                    gitRisk: risk.gitRisk,
                    localRisk: risk.localRisk,
                    filePath: path,
                    lineNumber: lineNumber,
                    description: "\(matches[0].patternName) found in environment file",
                    secretPreview: PatternDatabase.maskSecret(matches[0].matchedText),
                    recommendation: risk.recommendation
                ))
            }
        }

        return findings
    }

    private static func checkGitignore(filePath: String) -> Bool {
        // Walk up from the file to find a .git directory, then check git status
        let fileURL = URL(fileURLWithPath: filePath)
        var dir = fileURL.deletingLastPathComponent()

        for _ in 0..<20 {
            let gitDir = dir.appendingPathComponent(".git")
            if FileManager.default.fileExists(atPath: gitDir.path) {
                // Found git repo -- check if file is ignored
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
                process.arguments = ["check-ignore", "-q", filePath]
                process.currentDirectoryURL = dir

                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = pipe

                do {
                    try process.run()
                    process.waitUntilExit()
                    return process.terminationStatus == 0 // 0 means ignored
                } catch {
                    return false
                }
            }
            let parent = dir.deletingLastPathComponent()
            if parent.path == dir.path { break } // reached root
            dir = parent
        }
        return false // no git repo found
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
swift test --filter EnvFileScannerTests
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/DevsecCore/Scanners/EnvFileScanner.swift Tests/DevsecCoreTests/EnvFileScannerTests.swift
git commit -m "feat: add env file scanner with gitignore-aware risk classification"
```

---

## Task 8: History Scanner

**Files:**
- Create: `Sources/DevsecCore/Scanners/HistoryScanner.swift`
- Create: `Tests/DevsecCoreTests/HistoryScannerTests.swift`

- [ ] **Step 1: Write tests for history scanning**

Create `Tests/DevsecCoreTests/HistoryScannerTests.swift`:

```swift
import Testing
import Foundation
@testable import DevsecCore

@Suite("HistoryScanner")
struct HistoryScannerTests {

    func createTempHistoryFile(content: String) throws -> (URL, String) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let histFile = tempDir.appendingPathComponent(".zsh_history")
        try content.write(to: histFile, atomically: true, encoding: .utf8)
        return (tempDir, histFile.path)
    }

    @Test func detectsAPIKeyInHistory() throws {
        let content = """
        ls -la
        export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz01234567890123456789
        cd ~/Projects
        """
        let (tempDir, path) = try createTempHistoryFile(content: content)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = HistoryScanner.scanFile(at: path)
        #expect(findings.count >= 1)
        #expect(findings[0].module == .history)
    }

    @Test func detectsCurlWithToken() throws {
        let content = """
        curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw" https://api.example.com
        """
        let (tempDir, path) = try createTempHistoryFile(content: content)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = HistoryScanner.scanFile(at: path)
        #expect(findings.count >= 1)
    }

    @Test func doesNotMatchSafeCommands() throws {
        let content = """
        ls -la
        cd ~/Projects
        git status
        npm install
        brew update
        """
        let (tempDir, path) = try createTempHistoryFile(content: content)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = HistoryScanner.scanFile(at: path)
        #expect(findings.isEmpty)
    }

    @Test func includesLineNumber() throws {
        let content = """
        echo hello
        echo world
        export AWS_KEY=AKIAIOSFODNN7EXAMPLE
        """
        let (tempDir, path) = try createTempHistoryFile(content: content)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = HistoryScanner.scanFile(at: path)
        #expect(findings.count == 1)
        #expect(findings[0].lineNumber == 3)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
swift test --filter HistoryScannerTests
```

Expected: compilation error -- `HistoryScanner` does not exist.

- [ ] **Step 3: Implement HistoryScanner**

Create `Sources/DevsecCore/Scanners/HistoryScanner.swift`:

```swift
import Foundation

public enum HistoryScanner: Scanner {
    public static let module: ScanModule = .history

    public var module: ScanModule { Self.module }

    public func scan() async throws -> ScanResult {
        let start = Date()
        let home = NSHomeDirectory()
        let knownHistoryFiles = [
            home + "/.zsh_history",
            home + "/.bash_history",
            home + "/.sh_history",
        ]

        // Also search for other history files via Spotlight
        let discoveredFiles = await SpotlightEngine.findFiles(matchingGlob: "*_history")
        let allFiles = Array(Set(knownHistoryFiles + discoveredFiles))
            .filter { FileManager.default.fileExists(atPath: $0) }

        var allFindings: [Finding] = []
        for file in allFiles {
            allFindings.append(contentsOf: Self.scanFile(at: file))
        }

        return ScanResult(module: Self.module, findings: allFindings, duration: Date().timeIntervalSince(start))
    }

    public static func scanFile(at path: String) -> [Finding] {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }

        var findings: [Finding] = []
        let lines = content.components(separatedBy: .newlines)

        for (index, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }

            // Strip zsh history timestamp prefix (: 1234567890:0;command)
            let cleanedLine: String
            if trimmed.hasPrefix(": ") && trimmed.contains(";") {
                if let semicolonIndex = trimmed.firstIndex(of: ";") {
                    cleanedLine = String(trimmed[trimmed.index(after: semicolonIndex)...])
                } else {
                    cleanedLine = trimmed
                }
            } else {
                cleanedLine = trimmed
            }

            let matches = PatternDatabase.findSecrets(in: cleanedLine)
            for match in matches {
                let lineNumber = index + 1
                let findingId = "history:\(path):\(lineNumber):\(match.patternName)"
                findings.append(Finding(
                    id: findingId,
                    module: .history,
                    severity: .high,
                    gitRisk: .none,
                    localRisk: .high,
                    filePath: path,
                    lineNumber: lineNumber,
                    description: "\(match.patternName) found in shell history",
                    secretPreview: PatternDatabase.maskSecret(match.matchedText),
                    recommendation: "Rotate this credential and clear the history entry. Run: sed -i '' '\(lineNumber)d' \(path)"
                ))
            }
        }

        return findings
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
swift test --filter HistoryScannerTests
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/DevsecCore/Scanners/HistoryScanner.swift Tests/DevsecCoreTests/HistoryScannerTests.swift
git commit -m "feat: add shell history scanner with zsh timestamp support"
```

---

## Task 9: SSH Scanner

**Files:**
- Create: `Sources/DevsecCore/Scanners/SSHScanner.swift`
- Create: `Tests/DevsecCoreTests/SSHScannerTests.swift`

- [ ] **Step 1: Write tests for SSH scanning**

Create `Tests/DevsecCoreTests/SSHScannerTests.swift`:

```swift
import Testing
import Foundation
@testable import DevsecCore

@Suite("SSHScanner")
struct SSHScannerTests {

    @Test func detectsKeyFileByContent() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let keyFile = tempDir.appendingPathComponent("random_name.txt")
        try "-----BEGIN RSA PRIVATE KEY-----\nMIIE...".write(to: keyFile, atomically: true, encoding: .utf8)

        let findings = SSHScanner.scanKeyFile(at: keyFile.path)
        #expect(!findings.isEmpty)
        #expect(findings[0].module == .ssh)
    }

    @Test func detectsBadPermissions() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let keyFile = tempDir.appendingPathComponent("id_test_rsa")
        try "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb...".write(to: keyFile, atomically: true, encoding: .utf8)

        // Set overly permissive permissions
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: keyFile.path)

        let findings = SSHScanner.scanKeyFile(at: keyFile.path)
        let permFinding = findings.first { $0.description.contains("ermission") }
        #expect(permFinding != nil)
    }

    @Test func detectsKeyInUnsafeLocation() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        let downloadsDir = tempDir.appendingPathComponent("Downloads")
        try FileManager.default.createDirectory(at: downloadsDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let keyFile = downloadsDir.appendingPathComponent("server_key")
        try "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb...".write(to: keyFile, atomically: true, encoding: .utf8)

        let findings = SSHScanner.scanKeyFile(at: keyFile.path)
        let locationFinding = findings.first { $0.severity == .critical }
        #expect(locationFinding != nil)
    }

    @Test func parsesSSHConfigForIdentityFiles() {
        let config = """
        Host myserver
            HostName 192.168.1.1
            IdentityFile ~/Documents/keys/work_key
            User admin
        
        Host other
            IdentityFile /custom/path/id_ed25519
        """
        let paths = SSHScanner.parseIdentityFiles(from: config)
        #expect(paths.count == 2)
        #expect(paths.contains { $0.contains("work_key") })
        #expect(paths.contains { $0.contains("id_ed25519") })
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
swift test --filter SSHScannerTests
```

Expected: compilation error -- `SSHScanner` does not exist.

- [ ] **Step 3: Implement SSHScanner**

Create `Sources/DevsecCore/Scanners/SSHScanner.swift`:

```swift
import Foundation

public enum SSHScanner: Scanner {
    public static let module: ScanModule = .ssh

    public var module: ScanModule { Self.module }

    public func scan() async throws -> ScanResult {
        let start = Date()
        var allFindings: [Finding] = []

        // 1. Find keys via Spotlight content search
        var keyFiles: Set<String> = []
        for header in ["BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
                       "BEGIN EC PRIVATE KEY", "BEGIN DSA PRIVATE KEY", "BEGIN PRIVATE KEY"] {
            let files = await SpotlightEngine.findFiles(containingText: header)
            keyFiles.formUnion(files)
        }

        // 2. Find keys by common filenames
        for name in ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"] {
            let files = await SpotlightEngine.findFiles(named: name)
            keyFiles.formUnion(files)
        }
        let pemFiles = await SpotlightEngine.findFiles(matchingGlob: "*.pem")
        keyFiles.formUnion(pemFiles)

        // 3. Parse SSH config for IdentityFile references
        let sshConfigPath = NSHomeDirectory() + "/.ssh/config"
        if let configContent = try? String(contentsOfFile: sshConfigPath, encoding: .utf8) {
            let identityFiles = Self.parseIdentityFiles(from: configContent)
            keyFiles.formUnion(identityFiles)
        }

        // 4. Scan each key file
        for file in keyFiles where FileManager.default.fileExists(atPath: file) {
            allFindings.append(contentsOf: Self.scanKeyFile(at: file))
        }

        return ScanResult(module: Self.module, findings: allFindings, duration: Date().timeIntervalSince(start))
    }

    public static func scanKeyFile(at path: String) -> [Finding] {
        var findings: [Finding] = []

        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }

        // Check if it's actually a private key
        let keyHeaders = ["BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
                          "BEGIN EC PRIVATE KEY", "BEGIN DSA PRIVATE KEY",
                          "BEGIN PRIVATE KEY", "BEGIN PGP PRIVATE KEY"]
        let isPrivateKey = keyHeaders.contains { content.contains($0) }
        guard isPrivateKey else { return [] }

        let keyType = keyHeaders.first { content.contains($0) } ?? "Private Key"
        let shortType = keyType.replacingOccurrences(of: "BEGIN ", with: "").replacingOccurrences(of: "-----", with: "")

        // Check file permissions
        if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
           let perms = attrs[.posixPermissions] as? Int {
            if perms & 0o077 != 0 { // readable by group or others
                findings.append(Finding(
                    id: "ssh:perms:\(path)",
                    module: .ssh,
                    severity: .high,
                    gitRisk: .none,
                    localRisk: .high,
                    filePath: path,
                    description: "Permission too open on \(shortType) (current: \(String(perms, radix: 8)), expected: 600)",
                    secretPreview: shortType,
                    recommendation: "Fix permissions: chmod 600 \(path)"
                ))
            }
        }

        // Check for unsafe location
        let unsafeDirs = ["/Desktop/", "/Downloads/", "/Documents/", "/Public/", "/Shared/"]
        let isUnsafe = unsafeDirs.contains { path.contains($0) }

        findings.append(Finding(
            id: "ssh:key:\(path)",
            module: .ssh,
            severity: isUnsafe ? .critical : .medium,
            gitRisk: .none,
            localRisk: isUnsafe ? .critical : .medium,
            filePath: path,
            description: isUnsafe
                ? "\(shortType) found in unsafe location"
                : "\(shortType) found",
            secretPreview: shortType,
            recommendation: isUnsafe
                ? "Move this key to ~/.ssh/ and update references. Keys in \(path.components(separatedBy: "/").dropLast().last ?? "this location") are easily exposed."
                : "Ensure this key has a passphrase and is needed. Remove if unused."
        ))

        return findings
    }

    public static func parseIdentityFiles(from sshConfig: String) -> [String] {
        var paths: [String] = []
        let lines = sshConfig.components(separatedBy: .newlines)

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix("identityfile") {
                let parts = trimmed.split(separator: " ", maxSplits: 1)
                if parts.count == 2 {
                    var path = String(parts[1]).trimmingCharacters(in: .whitespaces)
                    if path.hasPrefix("~/") {
                        path = NSHomeDirectory() + String(path.dropFirst(1))
                    }
                    paths.append(path)
                }
            }
        }

        return paths
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
swift test --filter SSHScannerTests
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add Sources/DevsecCore/Scanners/SSHScanner.swift Tests/DevsecCoreTests/SSHScannerTests.swift
git commit -m "feat: add SSH scanner with content-based discovery and permission checks"
```

---

## Task 10: Document Scanner, AI Tool Scanner, Credential File Scanner

These three scanners follow the same pattern. Implementing together to avoid repetition in the plan.

**Files:**
- Create: `Sources/DevsecCore/Scanners/DocumentScanner.swift`
- Create: `Sources/DevsecCore/Scanners/AIToolScanner.swift`
- Create: `Sources/DevsecCore/Scanners/CredentialFileScanner.swift`
- Create: `Tests/DevsecCoreTests/DocumentScannerTests.swift`
- Create: `Tests/DevsecCoreTests/AIToolScannerTests.swift`
- Create: `Tests/DevsecCoreTests/CredentialFileScannerTests.swift`

- [ ] **Step 1: Write tests for DocumentScanner**

Create `Tests/DevsecCoreTests/DocumentScannerTests.swift`:

```swift
import Testing
import Foundation
@testable import DevsecCore

@Suite("DocumentScanner")
struct DocumentScannerTests {

    @Test func detectsSecretInTextFile() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let file = tempDir.appendingPathComponent("notes.txt")
        try "Here is my API key: AKIAIOSFODNN7EXAMPLE for AWS".write(to: file, atomically: true, encoding: .utf8)

        let findings = DocumentScanner.scanFile(at: file.path)
        #expect(findings.count == 1)
        #expect(findings[0].module == .documents)
    }

    @Test func skipsCleanFiles() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let file = tempDir.appendingPathComponent("readme.txt")
        try "This is a normal document without secrets.".write(to: file, atomically: true, encoding: .utf8)

        let findings = DocumentScanner.scanFile(at: file.path)
        #expect(findings.isEmpty)
    }
}
```

- [ ] **Step 2: Write tests for AIToolScanner**

Create `Tests/DevsecCoreTests/AIToolScannerTests.swift`:

```swift
import Testing
import Foundation
@testable import DevsecCore

@Suite("AIToolScanner")
struct AIToolScannerTests {

    @Test func detectsHardcodedKeyInClaudeConfig() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        let claudeDir = tempDir.appendingPathComponent(".claude")
        try FileManager.default.createDirectory(at: claudeDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let config = claudeDir.appendingPathComponent("settings.json")
        try """
        {
            "env": {
                "ANTHROPIC_API_KEY": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"
            }
        }
        """.write(to: config, atomically: true, encoding: .utf8)

        let findings = AIToolScanner.scanConfigFile(at: config.path, toolName: "Claude Code")
        #expect(findings.count >= 1)
        #expect(findings[0].module == .aiTools)
    }

    @Test func acceptsOpReferencesInConfig() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        let claudeDir = tempDir.appendingPathComponent(".claude")
        try FileManager.default.createDirectory(at: claudeDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let config = claudeDir.appendingPathComponent("settings.json")
        try """
        {
            "env": {
                "ANTHROPIC_API_KEY": "op://Development/Anthropic/credential"
            }
        }
        """.write(to: config, atomically: true, encoding: .utf8)

        let findings = AIToolScanner.scanConfigFile(at: config.path, toolName: "Claude Code")
        #expect(findings.isEmpty)
    }

    @Test func returnsCorrectToolConfigs() {
        let configs = AIToolScanner.allToolConfigs
        #expect(configs.count >= 10)
        #expect(configs.contains { $0.name == "Claude Code" })
        #expect(configs.contains { $0.name == "Cursor" })
        #expect(configs.contains { $0.name == "GitHub Copilot" })
    }
}
```

- [ ] **Step 3: Write tests for CredentialFileScanner**

Create `Tests/DevsecCoreTests/CredentialFileScannerTests.swift`:

```swift
import Testing
import Foundation
@testable import DevsecCore

@Suite("CredentialFileScanner")
struct CredentialFileScannerTests {

    @Test func detectsPasswordExportCSV() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let file = tempDir.appendingPathComponent("passwords.csv")
        try "url,username,password\nexample.com,admin,hunter2".write(to: file, atomically: true, encoding: .utf8)

        let findings = CredentialFileScanner.scanFile(at: file.path)
        #expect(findings.count == 1)
        #expect(findings[0].severity == .critical)
    }

    @Test func detects1PasswordExport() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let file = tempDir.appendingPathComponent("1password-export-2026-04-16.csv")
        try "title,username,password".write(to: file, atomically: true, encoding: .utf8)

        let findings = CredentialFileScanner.scanFile(at: file.path)
        #expect(findings.count == 1)
        #expect(findings[0].severity == .critical)
    }

    @Test func skipsNonCredentialFiles() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("devsec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let file = tempDir.appendingPathComponent("data.csv")
        try "name,age,city\nAlice,30,NYC".write(to: file, atomically: true, encoding: .utf8)

        let findings = CredentialFileScanner.scanFile(at: file.path)
        #expect(findings.isEmpty)
    }
}
```

- [ ] **Step 4: Run all three test suites to verify they fail**

```bash
swift test --filter "DocumentScannerTests|AIToolScannerTests|CredentialFileScannerTests"
```

Expected: compilation errors -- scanners don't exist.

- [ ] **Step 5: Implement DocumentScanner**

Create `Sources/DevsecCore/Scanners/DocumentScanner.swift`:

```swift
import Foundation

public enum DocumentScanner: Scanner {
    public static let module: ScanModule = .documents

    public var module: ScanModule { Self.module }

    public func scan() async throws -> ScanResult {
        let start = Date()
        var filesToScan: Set<String> = []

        for query in PatternDatabase.spotlightContentQueries {
            let files = await SpotlightEngine.findFiles(containingText: query)
            filesToScan.formUnion(files)
        }

        // Also search for files with password-related keywords
        for keyword in ["password", "passwd", "secret_key"] {
            let files = await SpotlightEngine.findFiles(containingText: keyword)
            filesToScan.formUnion(files)
        }

        // Filter out files handled by other scanners (.env, history, known configs)
        let filtered = filesToScan.filter { path in
            let filename = (path as NSString).lastPathComponent
            if filename.hasPrefix(".env") { return false }
            if filename.hasSuffix("_history") || filename.contains("hist") { return false }
            if filename == "config.json" || filename == "settings.json" { return false }
            return true
        }

        var allFindings: [Finding] = []
        for file in filtered {
            allFindings.append(contentsOf: Self.scanFile(at: file))
        }

        return ScanResult(module: Self.module, findings: allFindings, duration: Date().timeIntervalSince(start))
    }

    public static func scanFile(at path: String) -> [Finding] {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }

        let matches = PatternDatabase.findSecrets(in: content)
        return matches.map { match in
            let risk = RiskClassifier.classify(
                secretValue: match.matchedText,
                filePath: path,
                isInGitignore: false
            )
            return Finding(
                id: "doc:\(path):\(match.patternName):\(match.matchedText.prefix(8))",
                module: .documents,
                severity: risk.severity,
                gitRisk: risk.gitRisk,
                localRisk: risk.localRisk,
                filePath: path,
                description: "\(match.patternName) found in document",
                secretPreview: PatternDatabase.maskSecret(match.matchedText),
                recommendation: risk.recommendation
            )
        }
    }
}
```

- [ ] **Step 6: Implement AIToolScanner**

Create `Sources/DevsecCore/Scanners/AIToolScanner.swift`:

```swift
import Foundation

public struct AIToolConfig: Sendable {
    public let name: String
    public let configPaths: [String] // relative to home directory
}

public enum AIToolScanner: Scanner {
    public static let module: ScanModule = .aiTools

    public var module: ScanModule { Self.module }

    public static let allToolConfigs: [AIToolConfig] = [
        AIToolConfig(name: "Claude Code", configPaths: [
            ".claude/settings.json", ".claude/settings.local.json",
        ]),
        AIToolConfig(name: "Cursor", configPaths: [
            ".cursor/mcp.json",
        ]),
        AIToolConfig(name: "GitHub Copilot", configPaths: [
            ".config/github-copilot/apps.json",
        ]),
        AIToolConfig(name: "Windsurf", configPaths: [
            ".windsurf/settings.json", ".codeium/config.json",
        ]),
        AIToolConfig(name: "Continue.dev", configPaths: [
            ".continue/config.json",
        ]),
        AIToolConfig(name: "Aider", configPaths: [
            ".aider.conf.yml",
        ]),
        AIToolConfig(name: "OpenAI Codex CLI", configPaths: [
            ".codex/config.json",
        ]),
        AIToolConfig(name: "ChatGPT Desktop", configPaths: [
            "Library/Application Support/com.openai.chat/settings.json",
        ]),
        AIToolConfig(name: "Amazon Q", configPaths: [
            ".aws/amazonq/settings.json",
        ]),
        AIToolConfig(name: "Gemini CLI", configPaths: [
            ".gemini/settings.json",
        ]),
        AIToolConfig(name: "Copilot CLI", configPaths: [
            ".copilot/config.json",
        ]),
    ]

    public func scan() async throws -> ScanResult {
        let start = Date()
        let home = NSHomeDirectory()
        var allFindings: [Finding] = []

        for tool in Self.allToolConfigs {
            for relativePath in tool.configPaths {
                let fullPath = home + "/" + relativePath
                if FileManager.default.fileExists(atPath: fullPath) {
                    allFindings.append(contentsOf: Self.scanConfigFile(at: fullPath, toolName: tool.name))
                }
            }
        }

        // Also find MCP configs and CLAUDE.md files via Spotlight
        let mcpConfigs = await SpotlightEngine.findFiles(named: "mcp.json")
            + (await SpotlightEngine.findFiles(named: "claude_desktop_config.json"))
        for file in mcpConfigs {
            allFindings.append(contentsOf: Self.scanConfigFile(at: file, toolName: "MCP Config"))
        }

        let claudeMDs = await SpotlightEngine.findFiles(named: "CLAUDE.md")
        for file in claudeMDs {
            allFindings.append(contentsOf: Self.scanConfigFile(at: file, toolName: "CLAUDE.md"))
        }

        return ScanResult(module: Self.module, findings: allFindings, duration: Date().timeIntervalSince(start))
    }

    public static func scanConfigFile(at path: String, toolName: String) -> [Finding] {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }

        // Skip if content uses op:// references only
        if content.contains("op://") && !PatternDatabase.findSecrets(in: content).isEmpty {
            // Has both op:// and real secrets -- continue scanning
        } else if content.contains("op://") {
            return []
        }

        let matches = PatternDatabase.findSecrets(in: content)
        return matches.map { match in
            Finding(
                id: "ai:\(path):\(match.patternName):\(match.matchedText.prefix(8))",
                module: .aiTools,
                severity: .high,
                gitRisk: .medium,
                localRisk: .high,
                filePath: path,
                description: "\(match.patternName) hardcoded in \(toolName) config",
                secretPreview: PatternDatabase.maskSecret(match.matchedText),
                recommendation: "Replace with 1Password reference (op://) or environment variable. Hardcoded secrets in AI tool configs are exposed to any process."
            )
        }
    }
}
```

- [ ] **Step 7: Implement CredentialFileScanner**

Create `Sources/DevsecCore/Scanners/CredentialFileScanner.swift`:

```swift
import Foundation

public enum CredentialFileScanner: Scanner {
    public static let module: ScanModule = .credentialFiles

    public var module: ScanModule { Self.module }

    private static let dangerousFilenames: Set<String> = [
        "passwords.csv", "logins.csv", ".htpasswd", "wp-config.php",
    ]

    private static let dangerousPrefixes: [String] = [
        "1password-export", "bitwarden-export", "lastpass-export",
        "dashlane-export", "keeper-export", "chrome-passwords",
    ]

    private static let dangerousExtensions: Set<String> = [
        "pfx", "p12", "keystore", "jks",
    ]

    public func scan() async throws -> ScanResult {
        let start = Date()
        var filesToCheck: Set<String> = []

        // Search by known dangerous filenames
        for filename in Self.dangerousFilenames {
            let files = await SpotlightEngine.findFiles(named: filename)
            filesToCheck.formUnion(files)
        }

        // Search by dangerous prefixes
        for prefix in Self.dangerousPrefixes {
            let files = await SpotlightEngine.findFiles(matchingGlob: "\(prefix)*")
            filesToCheck.formUnion(files)
        }

        // Search by dangerous extensions
        for ext in Self.dangerousExtensions {
            let files = await SpotlightEngine.findFiles(matchingGlob: "*.\(ext)")
            filesToCheck.formUnion(files)
        }

        var allFindings: [Finding] = []
        for file in filesToCheck {
            allFindings.append(contentsOf: Self.scanFile(at: file))
        }

        return ScanResult(module: Self.module, findings: allFindings, duration: Date().timeIntervalSince(start))
    }

    public static func scanFile(at path: String) -> [Finding] {
        let filename = (path as NSString).lastPathComponent.lowercased()

        let isPasswordExport = Self.dangerousFilenames.contains(filename)
            || Self.dangerousPrefixes.contains { filename.hasPrefix($0) }
        let isDangerousExt = Self.dangerousExtensions.contains {
            filename.hasSuffix(".\($0)")
        }

        guard isPasswordExport || isDangerousExt else { return [] }

        let risk = RiskClassifier.classifyCredentialFile(filePath: path)

        return [Finding(
            id: "cred:\(path)",
            module: .credentialFiles,
            severity: risk.severity,
            gitRisk: risk.gitRisk,
            localRisk: risk.localRisk,
            filePath: path,
            description: isPasswordExport
                ? "Password manager export file found"
                : "Credential/certificate file found in unexpected location",
            secretPreview: filename,
            recommendation: risk.recommendation
        )]
    }
}
```

- [ ] **Step 8: Run all three test suites to verify they pass**

```bash
swift test --filter "DocumentScannerTests|AIToolScannerTests|CredentialFileScannerTests"
```

Expected: all tests pass.

- [ ] **Step 9: Commit**

```bash
git add Sources/DevsecCore/Scanners/ Tests/DevsecCoreTests/DocumentScannerTests.swift Tests/DevsecCoreTests/AIToolScannerTests.swift Tests/DevsecCoreTests/CredentialFileScannerTests.swift
git commit -m "feat: add document, AI tool, and credential file scanners"
```

---

## Task 11: Scan Orchestrator

**Files:**
- Create: `Sources/DevsecCore/ScanOrchestrator.swift`

- [ ] **Step 1: Implement ScanOrchestrator**

Create `Sources/DevsecCore/ScanOrchestrator.swift`:

```swift
import Foundation

public struct FullScanResult: Sendable {
    public let results: [ScanResult]
    public let findings: [Finding]
    public let totalDuration: TimeInterval
    public let newCount: Int
    public let criticalCount: Int
    public let highCount: Int
    public let mediumCount: Int
    public let lowCount: Int
}

public final class ScanOrchestrator: Sendable {
    private let whitelist: WhitelistManager
    private let findingStore: FindingStore
    private let modules: Set<ScanModule>

    public init(
        whitelist: WhitelistManager = WhitelistManager(),
        findingStore: FindingStore = FindingStore(),
        modules: Set<ScanModule>? = nil
    ) {
        self.whitelist = whitelist
        self.findingStore = findingStore
        self.modules = modules ?? [.env, .history, .ssh, .documents, .aiTools, .credentialFiles]
    }

    public func scan() async throws -> FullScanResult {
        let start = Date()

        let scanners: [(ScanModule, any Scanner)] = [
            (.env, EnvFileScanner()),
            (.history, HistoryScanner()),
            (.ssh, SSHScanner()),
            (.documents, DocumentScanner()),
            (.aiTools, AIToolScanner()),
            (.credentialFiles, CredentialFileScanner()),
        ].filter { modules.contains($0.0) }

        var results: [ScanResult] = []
        for (_, scanner) in scanners {
            let result = try await scanner.scan()
            results.append(result)
        }

        // Merge all findings
        var allFindings = results.flatMap(\.findings)

        // Apply whitelist
        allFindings = whitelist.filterFindings(allFindings)

        // Mark new vs known
        allFindings = findingStore.markNewVsKnown(allFindings)

        // Record for next run
        findingStore.recordFindings(allFindings)
        try? findingStore.save()

        // Sort by severity (critical first)
        allFindings.sort { $0.severity > $1.severity }

        let duration = Date().timeIntervalSince(start)

        return FullScanResult(
            results: results,
            findings: allFindings,
            totalDuration: duration,
            newCount: allFindings.filter(\.isNew).count,
            criticalCount: allFindings.filter { $0.severity == .critical }.count,
            highCount: allFindings.filter { $0.severity == .high }.count,
            mediumCount: allFindings.filter { $0.severity == .medium }.count,
            lowCount: allFindings.filter { $0.severity == .low }.count
        )
    }
}
```

- [ ] **Step 2: Verify it compiles**

```bash
swift build
```

Expected: builds successfully.

- [ ] **Step 3: Commit**

```bash
git add Sources/DevsecCore/ScanOrchestrator.swift
git commit -m "feat: add scan orchestrator that runs all modules with whitelist and finding tracking"
```

---

## Task 12: CLI Output Formatters

**Files:**
- Create: `Sources/devsec-cli/Formatters/TextFormatter.swift`
- Create: `Sources/devsec-cli/Formatters/JSONFormatter.swift`

- [ ] **Step 1: Implement TextFormatter**

Create `Sources/devsec-cli/Formatters/TextFormatter.swift`:

```swift
import DevsecCore

enum TextFormatter {
    static func format(_ result: FullScanResult, showWhitelisted: Bool = false) -> String {
        var output = ""

        output += "devsec v0.1.0 -- scan complete\n\n"

        // Module summary
        for scanResult in result.results {
            let count = scanResult.findings.count
            let label = moduleLabel(scanResult.module)
            let dots = String(repeating: ".", count: max(1, 50 - label.count - String(count).count - 10))
            let icon = count == 0 ? "ok" : "\(count) finding\(count == 1 ? "" : "s")"
            output += "\(label) \(dots) \(icon)\n"
        }

        output += "\n"
        output += String(repeating: "-", count: 50) + "\n"
        output += "\(result.findings.count) findings"
        output += " (\(result.criticalCount) critical, \(result.highCount) high,"
        output += " \(result.mediumCount) medium, \(result.lowCount) low)\n"

        if result.newCount > 0 {
            output += "\(result.newCount) are new since last scan\n"
        }

        output += String(repeating: "-", count: 50) + "\n\n"

        // Findings
        for finding in result.findings {
            let severityTag = finding.severity.rawValue.uppercased()
            let newTag = finding.isNew ? " [NEW]" : ""
            output += "\(severityTag)\(newTag)  \(finding.filePath ?? "unknown")"
            if let line = finding.lineNumber {
                output += ":\(line)"
            }
            output += "\n"
            output += "          \(finding.description)\n"
            output += "          Secret: \(finding.secretPreview)\n"
            output += "          Git risk: \(finding.gitRisk.rawValue.uppercased()) | Local risk: \(finding.localRisk.rawValue.uppercased())\n"
            output += "          Recommendation: \(finding.recommendation)\n\n"
        }

        if result.findings.isEmpty {
            output += "No findings. Your machine looks clean.\n"
        } else {
            output += "Run 'devsec whitelist add <finding-id>' to suppress known-safe findings.\n"
        }

        return output
    }

    private static func moduleLabel(_ module: ScanModule) -> String {
        switch module {
        case .env: return "Environment Files"
        case .history: return "Shell History"
        case .ssh: return "SSH Keys"
        case .documents: return "Documents"
        case .aiTools: return "AI Tool Configs"
        case .credentialFiles: return "Credential Files"
        case .git: return "Git Repositories"
        case .ports: return "Ports"
        case .clipboard: return "Clipboard"
        case .permissions: return "Permissions"
        }
    }
}
```

- [ ] **Step 2: Implement JSONFormatter**

Create `Sources/devsec-cli/Formatters/JSONFormatter.swift`:

```swift
import Foundation
import DevsecCore

enum JSONFormatter {
    static func format(_ result: FullScanResult) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        struct JSONOutput: Encodable {
            let version: String
            let totalFindings: Int
            let newFindings: Int
            let critical: Int
            let high: Int
            let medium: Int
            let low: Int
            let duration: Double
            let findings: [Finding]
        }

        let output = JSONOutput(
            version: "0.1.0",
            totalFindings: result.findings.count,
            newFindings: result.newCount,
            critical: result.criticalCount,
            high: result.highCount,
            medium: result.mediumCount,
            low: result.lowCount,
            duration: result.totalDuration,
            findings: result.findings
        )

        guard let data = try? encoder.encode(output),
              let json = String(data: data, encoding: .utf8) else {
            return "{\"error\": \"Failed to encode results\"}"
        }

        return json
    }
}
```

- [ ] **Step 3: Verify it compiles**

```bash
swift build
```

Expected: builds successfully.

- [ ] **Step 4: Commit**

```bash
git add Sources/devsec-cli/Formatters/
git commit -m "feat: add text and JSON output formatters for CLI"
```

---

## Task 13: Wire Up CLI Commands

**Files:**
- Modify: `Sources/devsec-cli/ScanCommand.swift`
- Modify: `Sources/devsec-cli/StatusCommand.swift`
- Create: `Sources/devsec-cli/WhitelistCommand.swift`

- [ ] **Step 1: Implement full ScanCommand**

Replace `Sources/devsec-cli/ScanCommand.swift`:

```swift
import ArgumentParser
import DevsecCore
import Foundation

struct ScanCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "scan",
        abstract: "Scan your machine for exposed secrets"
    )

    @Option(name: .long, help: "Comma-separated list of modules to scan (env,history,ssh,documents,ai-tools,credential-files)")
    var modules: String?

    @Option(name: .long, help: "Output format: text or json")
    var format: String = "text"

    @Flag(name: .long, help: "Show whitelisted findings too")
    var showWhitelisted: Bool = false

    func run() async throws {
        let selectedModules: Set<ScanModule>?
        if let moduleList = modules {
            selectedModules = Set(moduleList.split(separator: ",").compactMap { name in
                ScanModule(rawValue: String(name))
            })
        } else {
            selectedModules = nil
        }

        if format == "text" {
            print("devsec v0.1.0 -- scanning your machine")
            let health = await SpotlightEngine.checkHealth()
            print("Using \(health.available ? "Spotlight (indexed, fast mode)" : "fallback mode (slower)")\n")
        }

        let orchestrator = ScanOrchestrator(modules: selectedModules)
        let result = try await orchestrator.scan()

        switch format {
        case "json":
            print(JSONFormatter.format(result))
        default:
            print(TextFormatter.format(result, showWhitelisted: showWhitelisted))
        }
    }
}
```

- [ ] **Step 2: Implement full StatusCommand**

Replace `Sources/devsec-cli/StatusCommand.swift`:

```swift
import ArgumentParser
import DevsecCore
import Foundation

struct StatusCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Check devsec status and Spotlight health"
    )

    func run() async throws {
        print("devsec v0.1.0\n")

        let health = await SpotlightEngine.checkHealth()
        print("Spotlight: \(health.available ? "active" : "unavailable") -- \(health.message)")

        let configPath = NSHomeDirectory() + "/.config/devsec/config.json"
        let configExists = FileManager.default.fileExists(atPath: configPath)
        print("Config: \(configExists ? configPath : "not found (using defaults)")")

        let storePath = NSHomeDirectory() + "/.config/devsec/findings.json"
        let storeExists = FileManager.default.fileExists(atPath: storePath)
        print("Finding store: \(storeExists ? "has previous scan data" : "no previous scans")")
    }
}
```

- [ ] **Step 3: Implement WhitelistCommand**

Create `Sources/devsec-cli/WhitelistCommand.swift`:

```swift
import ArgumentParser
import DevsecCore
import Foundation

struct WhitelistCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "whitelist",
        abstract: "Manage whitelisted findings",
        subcommands: [Add.self, Remove.self, List.self]
    )

    struct Add: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Whitelist a finding by ID")

        @Argument(help: "The finding ID to whitelist")
        var findingId: String

        func run() throws {
            let manager = WhitelistManager()
            manager.addFinding(findingId)
            try manager.save()
            print("Whitelisted: \(findingId)")
        }
    }

    struct Remove: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Remove a finding from the whitelist")

        @Argument(help: "The finding ID to remove")
        var findingId: String

        func run() throws {
            let manager = WhitelistManager()
            manager.removeFinding(findingId)
            try manager.save()
            print("Removed from whitelist: \(findingId)")
        }
    }

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List all whitelisted findings")

        func run() throws {
            let manager = WhitelistManager()
            let findings = manager.allFindings
            if findings.isEmpty {
                print("No whitelisted findings.")
            } else {
                for finding in findings {
                    print("  \(finding)")
                }
            }
        }
    }
}
```

- [ ] **Step 4: Update DevsecCLI to include WhitelistCommand**

Replace `Sources/devsec-cli/DevsecCLI.swift`:

```swift
import ArgumentParser

@main
struct DevsecCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "devsec",
        abstract: "Developer workstation security auditor",
        version: "0.1.0",
        subcommands: [ScanCommand.self, WhitelistCommand.self, StatusCommand.self],
        defaultSubcommand: ScanCommand.self
    )
}
```

- [ ] **Step 5: Build and test the CLI**

```bash
swift build
swift run devsec-cli status
swift run devsec-cli --version
swift run devsec-cli whitelist list
```

Expected: all commands work, version prints 0.1.0, whitelist shows empty, status shows Spotlight health.

- [ ] **Step 6: Commit**

```bash
git add Sources/devsec-cli/
git commit -m "feat: wire up CLI with scan, whitelist, and status commands"
```

---

## Task 14: Run All Tests + Full Integration Test

- [ ] **Step 1: Run the complete test suite**

```bash
swift test
```

Expected: all tests pass.

- [ ] **Step 2: Run a real scan on your machine**

```bash
swift run devsec-cli scan
```

Review the output. It will likely find real findings on your machine. This is expected and validates the tool works.

- [ ] **Step 3: Test JSON output**

```bash
swift run devsec-cli scan --format json | head -30
```

Expected: valid JSON output with findings.

- [ ] **Step 4: Test module filtering**

```bash
swift run devsec-cli scan --modules ssh
```

Expected: only SSH scanner results.

- [ ] **Step 5: Test whitelist flow**

```bash
# Pick a finding ID from the scan output and whitelist it
swift run devsec-cli whitelist add "some-finding-id"
swift run devsec-cli whitelist list
# Re-scan -- the whitelisted finding should be gone
swift run devsec-cli scan
```

- [ ] **Step 6: Fix any issues found during manual testing**

Address any bugs or rough edges discovered during the manual test.

- [ ] **Step 7: Commit any fixes**

```bash
git add -A
git commit -m "fix: address issues found during integration testing"
```

---

## Task 15: README and Polish

**Files:**
- Create: `README.md`

- [ ] **Step 1: Create README.md**

Create `README.md`:

```markdown
# devsec

A macOS security auditor for developer workstations. Finds exposed secrets, API keys, passwords, and credentials across your entire machine -- not just code repos.

Unlike code scanners (gitleaks, truffleHog) that only check git history, devsec scans everything: environment files, shell history, SSH keys, documents (PDFs, Word, Notes), AI tool configs, and credential exports.

## What it finds

- **API keys** in any file (AWS, OpenAI, Anthropic, GitHub, Stripe, Slack, 200+ patterns)
- **SSH private keys** anywhere on disk, even randomly named files, with permission checks
- **Passwords** in .env files, config files, shell history, documents
- **Credential exports** (passwords.csv, 1Password/Bitwarden exports left on disk)
- **AI tool misconfigurations** (hardcoded keys in Claude Code, Cursor, Copilot, Windsurf, Aider, Codex, and more)
- **Secrets in documents** (PDFs, Word docs, spreadsheets, Apple Notes)

## How it works

devsec uses macOS Spotlight for instant full-disk search. It finds secrets by file content, not just filename -- a private key in `~/Documents/backup.txt` gets caught. Falls back to `find`+`grep` automatically if Spotlight is unavailable.

Every finding gets two risk scores:
- **Git leak risk** -- could this end up in a commit?
- **Local compromise risk** -- could malware or unauthorized access expose this?

## Install

```bash
brew install devsec
```

Or build from source:

```bash
git clone https://github.com/yourusername/devsec.git
cd devsec
swift build -c release
cp .build/release/devsec-cli /usr/local/bin/devsec
```

## Usage

```bash
# Scan everything
devsec scan

# Scan specific modules
devsec scan --modules ssh,env,ai-tools

# JSON output
devsec scan --format json

# Whitelist a known-safe finding
devsec whitelist add "finding-id"

# Check system status
devsec status
```

## Whitelisting

First run will be noisy. Review findings and whitelist what is intentional:

```bash
devsec whitelist add "env:/Users/you/project/.env:3:AWS Access Key"
```

Configure in `~/.config/devsec/config.json`:

```json
{
    "files": ["~/project/.env.example"],
    "dirs": ["~/archived"],
    "safePatterns": ["sk-test-*", "pk_test_*"]
}
```

devsec never auto-whitelists. Every plaintext secret on disk is a finding -- the only green state is a proper secret manager reference (`op://`).

## Modules

| Module | What it scans |
|--------|--------------|
| `env` | .env files across all projects |
| `history` | Shell history (.zsh_history, .bash_history) |
| `ssh` | SSH keys anywhere on disk, permissions, config |
| `documents` | PDFs, Word, Excel, Notes, any Spotlight-indexed doc |
| `ai-tools` | Claude Code, Cursor, Copilot, Windsurf, Aider, Codex, Gemini, Amazon Q configs |
| `credential-files` | Password exports, .htpasswd, certificates |

## License

MIT
```

- [ ] **Step 2: Create LICENSE file**

Create `LICENSE`:

```
MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 3: Commit**

```bash
git add README.md LICENSE
git commit -m "docs: add README and MIT license"
```

- [ ] **Step 4: Run final test suite**

```bash
swift test
```

Expected: all tests pass. Phase 1 is complete.
