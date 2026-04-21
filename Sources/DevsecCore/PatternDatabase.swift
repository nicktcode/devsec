import Foundation

// MARK: - PatternDatabase

/// Central registry of secret detection patterns used by all scanners.
public enum PatternDatabase {

    // MARK: - Public Types

    public struct SecretMatch: Sendable {
        public let patternName: String
        public let matchedText: String
        public let range: Range<String.Index>
    }

    // MARK: - Public API

    /// Scans `text` against all registered patterns and returns every match found.
    /// Any value that starts with `op://` (1Password secret references) is skipped.
    public static func findSecrets(in text: String) -> [SecretMatch] {
        var results: [SecretMatch] = []
        let fullRange = NSRange(text.startIndex..<text.endIndex, in: text)

        for compiled in compiledPatterns {
            compiled.regex.enumerateMatches(in: text, options: [], range: fullRange) { result, _, _ in
                guard let result, result.range.location != NSNotFound else { return }
                guard let swiftRange = Range(result.range, in: text) else { return }
                let matched = String(text[swiftRange])
                if containsOpReference(matched) { return }

                // Pattern-specific context check: cheap short-circuit when
                // no contextRegex is set; otherwise the match must sit near
                // a credential-identifying keyword.
                guard satisfiesContext(compiled, matchRange: swiftRange, in: text) else { return }

                // Extract the "secret" portion of the match. For patterns
                // whose regex encodes surrounding context (e.g.
                // `Authorization: Bearer …`), the secret lives in a
                // named capture group; entropy/stopword checks should
                // apply to just that group, not the full match including
                // envelope text.
                let secret: String
                if compiled.secretGroup > 0,
                   compiled.secretGroup < result.numberOfRanges,
                   let groupRange = Range(result.range(at: compiled.secretGroup), in: text) {
                    secret = String(text[groupRange])
                } else {
                    secret = matched
                }

                // Stopword reject list. Applies to both the global list
                // (obvious placeholders everyone uses) and any
                // per-pattern additions.
                let lowered = secret.lowercased()
                if globalStopwords.contains(where: { lowered.contains($0) }) { return }
                if compiled.stopwords.contains(where: { lowered.contains($0) }) { return }

                // Entropy gate. Catches low-randomness placeholders that
                // slip past stopwords (hand-crafted fakes, long repeats
                // of the same character). Skipped when the pattern does
                // not declare an entropy floor. not every match type
                // looks like a random-alphabet blob (password
                // assignments, connection strings, etc.).
                if let minEnt = compiled.minEntropy {
                    if !Entropy.meetsMinimum(secret, charset: compiled.entropyCharset, min: minEnt) {
                        return
                    }
                }

                results.append(SecretMatch(
                    patternName: compiled.name,
                    matchedText: matched,
                    range: swiftRange
                ))
            }
        }

        // BIP-39 crypto recovery phrases. Handled outside the regex loop because
        // detection requires wordlist membership checks, not pattern matching.
        for mnemonic in BIP39Detector.findMnemonics(in: text) {
            results.append(SecretMatch(
                patternName: "Crypto Recovery Phrase",
                matchedText: mnemonic.matchedText,
                range: mnemonic.range
            ))
        }

        return results
    }

    /// Masks a secret: returns the first 4 characters (or all if shorter) followed by "****".
    public static func maskSecret(_ secret: String) -> String {
        let prefix = String(secret.prefix(4))
        return prefix + "****"
    }

    // MARK: - Spotlight Queries

    /// Key prefixes and distinctive strings suitable for Spotlight `kMDItemTextContent` queries.
    public static let spotlightContentQueries: [String] = [
        "AKIA",
        "sk-ant-api",
        "sk-proj-",
        "ghp_",
        "ghs_",
        "sk_live_",
        "sk_test_",
        "xoxb-",
        "xoxp-",
        "AIzaSy",
        "SG.",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ]

    /// Filename strings for Spotlight `kMDItemDisplayName` queries.
    public static let spotlightFileQueries: [String] = [
        ".env",
        "credentials",
        "secret",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        ".pem",
        ".p12",
        ".pfx",
        "htpasswd",
        "netrc",
        ".aws",
    ]

    /// Glob patterns for file-system scanning of credential files.
    public static let spotlightFileGlobs: [String] = [
        "**/.env",
        "**/.env.*",
        "**/credentials",
        "**/credentials.json",
        "**/credentials.csv",
        "**/secret.json",
        "**/secrets.json",
        "**/secrets.yaml",
        "**/secrets.yml",
        "**/*.pem",
        "**/*.p12",
        "**/*.pfx",
        "**/.netrc",
        "**/.htpasswd",
        "**/.aws/credentials",
        "**/.aws/config",
        "**/id_rsa",
        "**/id_ed25519",
        "**/id_ecdsa",
        "**/id_dsa",
        "**/*.key",
    ]

    // MARK: - Private Pattern Table

    private struct PatternEntry {
        let name: String
        let regex: String
        /// Optional case-insensitive regex that must match the surrounding
        /// text (±``contextWindow`` chars) for a raw match to count. Used
        /// to tame generic shapes like bare UUIDs. e.g. a UUID in shell
        /// history should only count as a Heroku API key when "heroku" is
        /// sitting right next to it.
        var contextRegex: String? = nil
        /// Character window on each side of the raw match to examine for
        /// ``contextRegex``. Only meaningful when `contextRegex` is set.
        var contextWindow: Int = 64
        /// When set, the matched text must have at least this Shannon
        /// entropy (bits per character) against ``entropyCharset`` to
        /// count. Rejects placeholders like `sk-ant-api03-YOURKEYHERE`
        /// that pass the regex but aren't random.
        var minEntropy: Double? = nil
        /// Character-set assumption for ``minEntropy``. Defaults to
        /// base64. most API tokens use a base64/base64url alphabet.
        var entropyCharset: Entropy.CharacterSet = .base64
        /// Optional secret-group extractor. When set, the entropy +
        /// stopword checks apply to this capture group instead of the
        /// whole match. Useful for patterns where the regex captures
        /// envelope context (e.g. `Authorization: Bearer <token>`).
        var secretGroup: Int = 0
        /// Matches that contain any of these substrings (case-insensitive)
        /// are rejected. Complements ``minEntropy`` for values that happen
        /// to have enough entropy but obviously name themselves as fake
        /// ("example", "placeholder", "your-key-here").
        var stopwords: [String] = []
    }

    /// A `PatternEntry` whose regex has been compiled once for reuse across files.
    private struct CompiledPattern {
        let name: String
        let regex: NSRegularExpression
        let contextRegex: NSRegularExpression?
        let contextWindow: Int
        let minEntropy: Double?
        let entropyCharset: Entropy.CharacterSet
        let secretGroup: Int
        let stopwords: [String]
    }

    /// Regex patterns compiled once at first use. `NSRegularExpression` is thread-safe
    /// for matching, so a single instance can be shared across concurrent scans.
    private static let compiledPatterns: [CompiledPattern] = {
        patterns.compactMap { entry in
            guard let regex = try? NSRegularExpression(pattern: entry.regex, options: []) else {
                assertionFailure("Invalid regex for pattern '\(entry.name)': \(entry.regex)")
                return nil
            }
            let ctx: NSRegularExpression? = entry.contextRegex.flatMap {
                try? NSRegularExpression(pattern: $0, options: [.caseInsensitive])
            }
            return CompiledPattern(
                name: entry.name,
                regex: regex,
                contextRegex: ctx,
                contextWindow: entry.contextWindow,
                minEntropy: entry.minEntropy,
                entropyCharset: entry.entropyCharset,
                secretGroup: entry.secretGroup,
                stopwords: entry.stopwords.map { $0.lowercased() }
            )
        }
    }()

    /// Global stopword list applied to *every* match regardless of
    /// pattern. These are values that are obviously placeholders. if
    /// the captured secret contains one of these substrings
    /// (case-insensitive), we reject the match.
    ///
    /// Chosen to overlap with the placeholder vocabulary found in our
    /// pattern fixtures, the gitleaks stopword list, and TruffleHog's
    /// common detector rejections.
    private static let globalStopwords: [String] = [
        "example", "yourkey", "your-key", "your_key", "your-token",
        "your_token", "yourapikey", "your-api-key", "placeholder",
        "xxxxxxxx", "changeme", "replace-me", "replaceme",
        "fakekey", "fake-key", "test-key-here", "abcdefg",
        "dummy", "testtest", "1234567890",
    ]

    /// Evaluates a pattern's context requirement. Returns true when the
    /// pattern has no context requirement, or when `contextRegex` matches
    /// the window around `matchRange` inside `text`.
    private static func satisfiesContext(
        _ compiled: CompiledPattern,
        matchRange: Range<String.Index>,
        in text: String
    ) -> Bool {
        guard let ctx = compiled.contextRegex else { return true }
        let window = compiled.contextWindow
        let start = text.index(matchRange.lowerBound, offsetBy: -window, limitedBy: text.startIndex) ?? text.startIndex
        let end = text.index(matchRange.upperBound, offsetBy: window, limitedBy: text.endIndex) ?? text.endIndex
        let snippet = String(text[start..<end])
        let range = NSRange(snippet.startIndex..<snippet.endIndex, in: snippet)
        return ctx.firstMatch(in: snippet, options: [], range: range) != nil
    }

    /// Returns `true` when the matched text value resolves to a 1Password `op://` reference,
    /// meaning it is a placeholder rather than an actual credential.
    private static func containsOpReference(_ text: String) -> Bool {
        // Match op:// that appears after an assignment separator (=, :, whitespace) or at start
        let opPattern = #"(?:=|:\s*|\s)op://"#
        if text.range(of: opPattern, options: .regularExpression) != nil { return true }
        // Also catch bare op:// at the very start of the value
        if text.hasPrefix("op://") { return true }
        return false
    }

    // swiftlint:disable line_length
    private static let patterns: [PatternEntry] = [

        // MARK: API Keys

        PatternEntry(
            name: "AWS Access Key",
            // AKIA followed by exactly 16 uppercase alphanumeric characters
            regex: #"AKIA[0-9A-Z]{16}"#,
            minEntropy: 3.0
        ),

        PatternEntry(
            name: "AWS Secret Access Key",
            // 40-char base64/url alphabet. only flag in proximity to
            // `AWS_SECRET_ACCESS_KEY`/`aws_secret` to avoid grabbing every
            // long token. Entropy threshold on top.
            regex: #"(?i)aws(?:_|-|\.)?secret(?:_|-|\.)?access(?:_|-|\.)?key[^\S\n]*[=:][^\S\n]*['\"]?([A-Za-z0-9/+=]{40})['\"]?"#,
            minEntropy: 4.0,
            secretGroup: 1
        ),

        PatternEntry(
            name: "Anthropic API Key",
            regex: #"sk-ant-api\d{2}-[A-Za-z0-9\-_]{80,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "OpenAI API Key",
            regex: #"sk-proj-[A-Za-z0-9\-_]{40,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "GitHub Token",
            regex: #"gh[psor]_[A-Za-z0-9]{36,}"#,
            minEntropy: 3.5
        ),

        PatternEntry(
            name: "GitHub Fine-Grained PAT",
            // github_pat_ followed by a short prefix, an underscore, and a
            // long suffix. Fine-grained tokens always start this way.
            regex: #"github_pat_[A-Za-z0-9_]{80,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "GitLab Token",
            // Personal access tokens (glpat-), pipeline triggers (glptt-),
            // deploy tokens (gldt-), and runner tokens (glrt-).
            regex: #"gl(?:pat|ptt|dt|rt)-[A-Za-z0-9_\-]{20,}"#,
            minEntropy: 3.5
        ),

        PatternEntry(
            name: "Bitbucket App Password",
            // Atlassian API tokens for Bitbucket use the ATATT prefix.
            regex: #"ATATT[A-Za-z0-9_\-]{40,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Stripe API Key",
            regex: #"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}"#,
            minEntropy: 3.0
        ),

        PatternEntry(
            name: "Stripe Publishable Key",
            // Publishable keys aren't strictly secret but often leak
            // alongside the matching secret key; useful signal.
            regex: #"pk_(?:live|test)_[A-Za-z0-9]{10,}"#,
            minEntropy: 3.0
        ),

        PatternEntry(
            name: "Slack Token",
            regex: #"xox[bprs]-[0-9A-Za-z\-]{20,}"#,
            minEntropy: 3.0
        ),

        PatternEntry(
            name: "Slack Webhook URL",
            regex: #"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Discord Bot Token",
            // Discord bot tokens: <user_id_b64>.<timestamp_b64>.<hmac>
            // The three base64url segments separated by dots; 24+ char hmac.
            regex: #"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Discord Webhook URL",
            regex: #"https://(?:discord|discordapp)\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Telegram Bot Token",
            // <bot_id>:<35-char base64url>
            regex: #"\d{8,10}:[A-Za-z0-9_\-]{35}"#,
            minEntropy: 3.5
        ),

        PatternEntry(
            name: "Google API Key",
            regex: #"AIzaSy[A-Za-z0-9\-_]{33}"#,
            minEntropy: 3.5
        ),

        PatternEntry(
            name: "SendGrid API Key",
            regex: #"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Twilio Auth Token",
            regex: #"(?i)(?:twilio.{0,20})?[0-9a-f]{32}(?![0-9a-f])"#,
            minEntropy: 2.5,
            entropyCharset: .hex
        ),

        PatternEntry(
            name: "Twilio Account SID",
            // AC + 32 hex. the public identifier, useful as a leak signal
            // even without the matching auth token.
            regex: #"AC[0-9a-f]{32}"#,
            minEntropy: 2.5,
            entropyCharset: .hex
        ),

        PatternEntry(
            name: "Mailgun API Key",
            regex: #"key-[0-9a-zA-Z]{32}"#,
            minEntropy: 3.5
        ),

        PatternEntry(
            name: "DigitalOcean PAT",
            regex: #"dop_v1_[a-f0-9]{64}"#,
            minEntropy: 3.0,
            entropyCharset: .hex
        ),

        PatternEntry(
            name: "Cloudflare API Token",
            // CF tokens are 40 base62 chars and appear alongside the word
            // "cloudflare" or `CF_API_TOKEN` in the wild; we use a
            // context check to avoid grabbing every 40-char blob.
            regex: #"[A-Za-z0-9_-]{40}"#,
            contextRegex: #"cloudflare|cf_api|CF_API_TOKEN"#,
            contextWindow: 48,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "NPM Access Token",
            regex: #"npm_[A-Za-z0-9]{36}"#,
            minEntropy: 3.5
        ),

        PatternEntry(
            name: "PyPI Upload Token",
            // pypi-AgE.... token is base64 up to ~160 chars.
            regex: #"pypi-AgE[A-Za-z0-9_\-]{50,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Docker Hub PAT",
            regex: #"dckr_pat_[A-Za-z0-9_\-]{20,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Azure Storage Connection String",
            // DefaultEndpointsProtocol=https;AccountName=…;AccountKey=<b64>;
            // Only the AccountKey portion carries the secret.
            regex: #"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{80,})"#,
            minEntropy: 4.0,
            secretGroup: 1
        ),

        PatternEntry(
            name: "JSON Web Token",
            // JWT: header.payload.signature, all base64url.
            regex: #"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "GCP Service Account Private Key",
            // The "private_key" field inside a Google service-account JSON
            // file. an RSA PRIVATE KEY embedded in a JSON string with
            // escaped newlines.
            regex: #""private_key"\s*:\s*"-----BEGIN (?:RSA |)PRIVATE KEY-----[^"]{100,}""#
        ),

        PatternEntry(
            name: "GCP OAuth Client Secret",
            regex: #"GOCSPX-[A-Za-z0-9_\-]{28}"#,
            minEntropy: 3.5
        ),

        PatternEntry(
            name: "Square Access Token",
            regex: #"EAAA[A-Za-z0-9_\-]{60,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Shopify Access Token",
            regex: #"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}"#,
            minEntropy: 3.0,
            entropyCharset: .hex
        ),

        PatternEntry(
            name: "Linear API Key",
            regex: #"lin_api_[A-Za-z0-9]{40}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Notion Integration Token",
            regex: #"(?:secret_|ntn_)[A-Za-z0-9]{43,46}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Vercel Token",
            regex: #"vercel_[A-Za-z0-9]{24,}"#,
            minEntropy: 3.5
        ),

        PatternEntry(
            name: "Supabase Service Key",
            regex: #"eyJhbGciOi[A-Za-z0-9_\-]{10,}\.eyJpc3Mi[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"#,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Okta API Token",
            regex: #"00[a-zA-Z0-9_\-]{40}"#,
            contextRegex: #"okta"#,
            contextWindow: 48,
            minEntropy: 4.0
        ),

        PatternEntry(
            name: "Datadog API Key",
            regex: #"[a-f0-9]{32}"#,
            contextRegex: #"datadog|DD_API_KEY|DD_APP_KEY"#,
            contextWindow: 48,
            minEntropy: 3.0,
            entropyCharset: .hex
        ),

        PatternEntry(
            name: "SonarCloud / SonarQube Token",
            regex: #"sq[pa]_[a-f0-9]{40}"#,
            minEntropy: 3.0,
            entropyCharset: .hex
        ),

        PatternEntry(
            name: "Postman API Key",
            regex: #"PMAK-[a-f0-9]{24}-[a-f0-9]{34}"#,
            minEntropy: 3.0,
            entropyCharset: .hex
        ),

        PatternEntry(
            name: "Segment Write Key",
            // Segment keys are 32-char base64; only flag in proximity.
            regex: #"[A-Za-z0-9]{32}"#,
            contextRegex: #"segment|writeKey|analytics\.load"#,
            contextWindow: 48,
            minEntropy: 4.2
        ),

        PatternEntry(
            name: "Heroku API Key",
            // Modern Heroku tokens always start with "HRKU-AA". The legacy
            // bare-UUID form was dropped because any session/run/build ID
            // in shell history (Claude, EAS, GitHub Actions, Datadog, …)
            // matched it and drowned the report in false positives.
            regex: #"HRKU-AA[A-Za-z0-9_\-]{40,}"#
        ),

        PatternEntry(
            name: "Heroku API Key",
            // Legacy UUID-style key. only counts when "heroku" sits
            // within 64 chars. Picks up `.netrc` blocks (machine
            // api.heroku.com … password …), `HEROKU_API_KEY=…` envs, and
            // `heroku auth:token` command output while ignoring bare UUIDs.
            regex: #"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
            contextRegex: #"heroku"#,
            contextWindow: 64
        ),

        PatternEntry(
            name: "Firebase Config",
            // Firebase project API keys start with AIzaSy but also appear in firebase config objects
            regex: #"\"apiKey\"\s*:\s*\"AIza[A-Za-z0-9\-_]{35}\""#
        ),

        // MARK: Private Keys

        PatternEntry(
            name: "Private Key",
            // Covers RSA, OpenSSH, EC, PGP, DSA, and generic PRIVATE KEY headers
            regex: #"-----BEGIN (?:RSA |OPENSSH |EC |PGP |DSA )?PRIVATE KEY(?:\sBLOCK)?-----"#
        ),

        // MARK: Password Assignments

        PatternEntry(
            name: "Password Assignment",
            // Matches: password=value, passwd: value, pwd=value, secret=value,
            //          api_key=value, token=value, auth=value etc. (not inside op:// refs)
            // Excludes placeholder-style values (YOUR_, <, >, {, })
            regex: #"(?i)(?:^|[\s,;'"&])?(?:password|passwd|pwd|secret|api_key|apikey|api_token|auth_token|access_token|token|auth)\s*[=:]\s*(?!op://|YOUR_|<|>|\{|\})[^\s"']{6,}"#
        ),

        // MARK: Connection Strings

        PatternEntry(
            name: "Connection String",
            // postgres, postgresql, mysql, mongodb, mongodb+srv, redis, rediss, amqp, amqps URLs with credentials
            regex: #"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqps?)://[A-Za-z0-9%._\-+]+:[A-Za-z0-9%._\-+!@#$^&*()]+@[A-Za-z0-9.\-]+"#
        ),

        // MARK: Auth Headers

        PatternEntry(
            name: "Basic Auth Header",
            // Authorization: Basic <base64>
            regex: #"(?i)Authorization\s*:\s*Basic\s+[A-Za-z0-9+/=]{8,}"#
        ),

        PatternEntry(
            name: "Bearer Token",
            // Authorization: Bearer <token>. token must be at least 20 chars to avoid false positives
            regex: #"(?i)Authorization\s*:\s*Bearer\s+[A-Za-z0-9\-._~+/=]{20,}"#
        ),
    ]
    // swiftlint:enable line_length
}
