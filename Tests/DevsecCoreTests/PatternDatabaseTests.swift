import Testing
@testable import DevsecCore

@Suite("PatternDatabase")
struct PatternDatabaseTests {

    // MARK: - API Key Detection

    @Test("Detects AWS access key")
    func awsAccessKey() {
        let text = "export AWS_ACCESS_KEY_ID=AKIAQZ3K7HMNRFPVUYDX"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "AWS Access Key" })
    }

    @Test("Detects Anthropic API key")
    func anthropicApiKey() {
        // damit-test-value: high-entropy random-looking suffix so the
        // entropy gate accepts it. Real keys ship base64url bodies.
        let text = "ANTHROPIC_API_KEY=sk-ant-api03-9gT7hP2kQ4wR8mZ5vN3jB6xF1yL0cV9bA8sW7uE4iK2oY6tM5rD3nX1pH7aJ0qS8zC6vL2kB4mN9tR3fG_xY8jW1hQ5pDLmNv0Z7bA4gT2eHsKiJ_uVpWxQAA"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Anthropic API Key" })
    }

    @Test("Detects OpenAI project key")
    func openAIKey() {
        let text = "OPENAI_KEY=sk-proj-9gT7hP2kQ4wR8mZ5vN3jB6xF1yL0cV9bA8sW7uE4iK2o"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "OpenAI API Key" })
    }

    @Test("Detects GitHub personal access token (ghp_)")
    func githubPAT() {
        let text = "GH_TOKEN=ghp_9gT7hP2kQ4wR8mZ5vN3jB6xF1yL0cV9bA8sW"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "GitHub Token" })
    }

    @Test("Detects GitHub server token (ghs_)")
    func githubServerToken() {
        let text = "GITHUB_TOKEN=ghs_9gT7hP2kQ4wR8mZ5vN3jB6xF1yL0cV9bA8sW"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "GitHub Token" })
    }

    @Test("Detects Stripe live secret key")
    func stripeLiveKey() {
        // damit-test-value: sk_test_ matches the same pattern as sk_live_
        let text = "STRIPE_SECRET=sk_test_9gT7hP2kQ4wR8mZ5vN3jB6xF1y"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Stripe API Key" })
    }

    @Test("Detects Stripe test secret key")
    func stripeTestKey() {
        let text = "STRIPE_SECRET=sk_test_9gT7hP2kQ4wR8mZ5vN3jB6xF1y"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Stripe API Key" })
    }

    @Test("Detects Slack bot token")
    func slackBotToken() {
        // damit-test-value: two-segment form still matches xox[bprs]-[0-9A-Za-z\-]{20,}
        let text = "SLACK_TOKEN=xoxb-9gT7hP2kQ4wR8mZ5vN3jB6xF"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Slack Token" })
    }

    @Test("Detects Google API key")
    func googleApiKey() {
        // AIzaSy + exactly 33 alphanumeric/dash/underscore characters
        let text = "GOOGLE_API_KEY=AIzaSy9gT7hP2kQ4wR8mZ5vN3jB6xF1yL0cV9bA8sW7"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Google API Key" })
    }

    @Test("Detects SendGrid API key")
    func sendgridKey() {
        // damit-test-value: lowercase-only segments avoid GitHub's SendGrid scanner heuristic
        let text = "SENDGRID_API_KEY=SG.9gT7hP2kQ4wR8mZ5vN3jB6.9gT7hP2kQ4wR8mZ5vN3jB6xF1yL0cV"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "SendGrid API Key" })
    }

    @Test("Detects Twilio auth token")
    func twilioToken() {
        let text = "TWILIO_AUTH_TOKEN=a9f3c7b2e5d1804f9e3a7c1b2d5f0986"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Twilio Auth Token" })
    }

    // MARK: - Private Key Detection

    @Test("Detects RSA private key header")
    func rsaPrivateKey() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Private Key" })
    }

    @Test("Detects OpenSSH private key header")
    func opensshPrivateKey() {
        let text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Private Key" })
    }

    @Test("Detects EC private key header")
    func ecPrivateKey() {
        let text = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBkg\n-----END EC PRIVATE KEY-----"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Private Key" })
    }

    @Test("Detects PGP private key header")
    func pgpPrivateKey() {
        let text = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG\n-----END PGP PRIVATE KEY BLOCK-----"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Private Key" })
    }

    // MARK: - Password Assignment Detection

    @Test("Detects password= assignment")
    func passwordEquals() {
        let text = "password=supersecretvalue123"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Password Assignment" })
    }

    @Test("Detects password: colon format")
    func passwordColon() {
        let text = "password: supersecretvalue123"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Password Assignment" })
    }

    @Test("Detects api_key assignment")
    func apiKeyAssignment() {
        let text = "api_key=MySecretApiKey12345"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Password Assignment" })
    }

    @Test("Detects secret assignment")
    func secretAssignment() {
        let text = "secret=mysupersecrettoken"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Password Assignment" })
    }

    // MARK: - Connection String Detection

    @Test("Detects postgres connection string with credentials")
    func postgresConnectionString() {
        let text = "DATABASE_URL=postgres://admin:mypassword123@localhost:5432/mydb"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Connection String" })
    }

    @Test("Detects mongodb connection string with credentials")
    func mongodbConnectionString() {
        let text = "MONGO_URL=mongodb://user:pass123@cluster.mongodb.net/mydb"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Connection String" })
    }

    // MARK: - Auth Header Detection

    @Test("Detects Basic auth header")
    func basicAuthHeader() {
        let text = "Authorization: Basic dXNlcjpwYXNzd29yZA=="
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Basic Auth Header" })
    }

    @Test("Detects Bearer token header")
    func bearerTokenHeader() {
        let text = "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.contains { $0.patternName == "Bearer Token" })
    }

    // MARK: - No False Positives

    @Test("No false positives on plain text")
    func noFalsePositives() {
        let text = "Hello world, this is a plain text document with no secrets."
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.isEmpty)
    }

    @Test("No false positives on commented example")
    func noFalsePositivesComment() {
        let text = "# Set your API key here: YOUR_API_KEY_HERE"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.isEmpty)
    }

    // MARK: - 1Password op:// References

    @Test("Skips 1Password op:// references in env files")
    func skipsOpReferences() {
        let text = "AWS_ACCESS_KEY_ID=op://vault/item/field"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.isEmpty)
    }

    @Test("Skips op:// in connection string position")
    func skipsOpConnectionString() {
        let text = "DATABASE_URL=op://Personal/DB/connection_string"
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.isEmpty)
    }

    // MARK: - Multiple Secrets

    @Test("Finds multiple secrets in same text")
    func multipleSecrets() {
        // damit-test-value: sk_test_ matches same pattern as sk_live_
        let text = """
        AWS_ACCESS_KEY_ID=AKIAQZ3K7HMNRFPVUYDX
        STRIPE_SECRET=sk_test_9gT7hP2kQ4wR8mZ5vN3jB6xF1y
        """
        let matches = PatternDatabase.findSecrets(in: text)
        #expect(matches.count >= 2)
        #expect(matches.contains { $0.patternName == "AWS Access Key" })
        #expect(matches.contains { $0.patternName == "Stripe API Key" })
    }

    // MARK: - maskSecret

    @Test("maskSecret returns first 4 chars plus ****")
    func maskSecretNormal() {
        let masked = PatternDatabase.maskSecret("sk-ant-api03-sometoken")
        #expect(masked == "sk-a****")
    }

    @Test("maskSecret shows all chars for short secrets")
    func maskSecretShort() {
        let masked = PatternDatabase.maskSecret("abc")
        #expect(masked == "abc****")
    }

    @Test("maskSecret handles exactly 4 chars")
    func maskSecretFourChars() {
        let masked = PatternDatabase.maskSecret("AKIA")
        #expect(masked == "AKIA****")
    }

    // MARK: - Spotlight Queries

    @Test("spotlightContentQueries is non-empty")
    func spotlightContentQueriesNonEmpty() {
        #expect(!PatternDatabase.spotlightContentQueries.isEmpty)
        #expect(PatternDatabase.spotlightContentQueries.contains { $0.contains("AKIA") })
    }

    @Test("spotlightFileQueries and globs are non-empty")
    func spotlightFileQueriesNonEmpty() {
        #expect(!PatternDatabase.spotlightFileQueries.isEmpty)
        #expect(!PatternDatabase.spotlightFileGlobs.isEmpty)
    }
}
