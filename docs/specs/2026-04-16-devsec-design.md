# devsec - Developer Workstation Security Auditor

**Date:** 2026-04-16
**Status:** Design approved

## Overview

A macOS security auditor that continuously scans a developer's entire machine for exposed secrets, credentials, and security misconfigurations. Unlike code scanners (gitleaks, truffleHog) that scan repos, or server auditors (Lynis) that scan servers, devsec scans your **workstation** holistically -- code, documents, shell history, AI tool configs, clipboard, SSH keys, and more.

**Key differentiators:**
- Full-disk content search via macOS Spotlight (finds secrets inside PDFs, Word docs, Notes, spreadsheets -- not just code)
- AI coding tool config scanner (Claude Code, Cursor, Copilot, Windsurf, Aider, Codex, and more)
- Two-dimensional risk classification (git leak risk vs. local compromise risk)
- Migration recommendations toward proper secret management (1Password `op://` references)
- Zero configuration required -- discovers everything automatically

**Distribution model:**
- Open source CLI on GitHub (full scanner, all features)
- Paid menubar app on Mac App Store (continuous monitoring, notifications, one-click actions)

## Architecture

```
devsec/
├── DevsecCore/              # Swift package -- shared detection engine
│   ├── Scanner.swift        # Orchestrates all scan modules
│   ├── SpotlightEngine.swift    # mdfind wrapper + fallback
│   ├── PatternDatabase.swift    # All regex patterns for secrets/keys/passwords
│   ├── RiskClassifier.swift     # Two-dimensional risk scoring
│   ├── WhitelistManager.swift   # Load/save/match whitelist rules
│   ├── FindingStore.swift       # Persist findings, detect new vs known
│   ├── Scanners/
│   │   ├── SSHScanner.swift
│   │   ├── HistoryScanner.swift
│   │   ├── EnvFileScanner.swift
│   │   ├── GitRepoScanner.swift
│   │   ├── PermissionScanner.swift
│   │   ├── PortScanner.swift
│   │   ├── ClipboardScanner.swift
│   │   ├── CredentialFileScanner.swift
│   │   ├── DocumentScanner.swift
│   │   └── AIToolScanner.swift
│   └── Models/
│       ├── Finding.swift        # Single detected issue
│       ├── Severity.swift       # critical/high/medium/low/info
│       └── RiskDimension.swift  # git risk + local risk
├── devsec-cli/              # CLI executable
│   └── main.swift
├── DevsecApp/               # macOS menubar app (paid)
│   ├── DevsecApp.swift
│   ├── MenuBarView.swift
│   ├── ReportView.swift
│   ├── SettingsView.swift
│   ├── ScanScheduler.swift
│   └── NotificationManager.swift
├── Tests/
│   └── DevsecCoreTests/
├── Package.swift
└── README.md
```

The core detection engine is a Swift package shared by both the CLI and menubar app. Same engine, same results, different interfaces.

## Detection Engine

### Discovery Strategy

All discovery is Spotlight-based with automatic fallback:

1. Check Spotlight health via `mdutil -s /`
2. If healthy: use `mdfind` for instant full-disk search
3. If broken: warn user, fall back to `find` + `grep` on `~/` (slower, ~30-60s)
4. Cache discovery results between scans for faster subsequent runs

### Scan Modules

#### 1. SSH Scanner
**Discovery:** Spotlight content search for private key headers + filename patterns + SSH config parsing

```
Spotlight queries:
  kMDItemTextContent == "BEGIN OPENSSH PRIVATE KEY"
  kMDItemTextContent == "BEGIN RSA PRIVATE KEY"
  kMDItemTextContent == "BEGIN EC PRIVATE KEY"
  kMDItemTextContent == "BEGIN DSA PRIVATE KEY"
  kMDItemFSName == "id_rsa" || "id_ed25519" || "id_ecdsa" || "*.pem"

SSH config parsing:
  Parse ~/.ssh/config and /etc/ssh/ssh_config for IdentityFile directives
```

**Checks:**
- Keys without passphrases (attempt ssh-keygen -y -P "" -f <key>)
- Weak key types (RSA < 2048 bit, DSA)
- Wrong file permissions (should be 0600)
- Keys in unexpected locations (Desktop, Downloads, Documents)
- Stale entries in authorized_keys
- Permissive SSH config options (PermitRootLogin, PasswordAuthentication)

#### 2. History Scanner
**Discovery:** Spotlight for `*_history`, `*hist*` files + known paths

**Checks:** Regex pattern matching against shell history for:
- API key patterns (all formats from pattern database)
- Password assignments in commands
- Connection strings with credentials
- Bearer tokens, auth headers
- `curl` commands with credentials in headers or URLs

#### 3. Env File Scanner
**Discovery:** Spotlight for `.env*` files across entire disk

**Checks:**
- Plaintext secrets (regex pattern matching on values)
- Whether file is in .gitignore (affects git leak risk, NOT local risk)
- Whether values use `op://` or vault references (marks as properly managed)
- Whether values appear to be local-only (localhost, 127.0.0.1, dev placeholders)
- Duplicate secrets across multiple .env files

**Risk classification:**
- `op://` reference: green (properly managed)
- Plaintext + in .gitignore + local value: medium (local risk only)
- Plaintext + in .gitignore + real value: high (local compromise risk)
- Plaintext + NOT in .gitignore: critical (both git and local risk)

#### 4. Git Repo Scanner
**Discovery:** Spotlight for `.git` directories

**Checks:**
- Recent commits containing secrets (pattern match on diffs)
- Untracked files with secrets
- Missing .gitignore for common secret files (.env, *.key, *.pem)

#### 5. Permission Scanner
**Discovery:** Direct path checks + Spotlight for sensitive file types

**Checks:**
- ~/.ssh/* permissions (should be 0600 for keys, 0700 for directory)
- ~/.aws/* permissions
- ~/.gnupg/* permissions
- Any private key file with overly permissive access (world-readable)
- config.toml/yaml/json files containing secrets with wrong permissions

#### 6. Port Scanner
**Discovery:** System call (lsof -i -P -n)

**Checks:**
- Unexpectedly listening ports
- Services bound to 0.0.0.0 (all interfaces) vs 127.0.0.1 (local only)
- Known development ports with services exposed externally
- Compare against user's known-safe list

#### 7. Clipboard Scanner
**Discovery:** NSPasteboard system API

**Checks:**
- Current clipboard content against secret patterns
- Flag if clipboard contains what appears to be an API key or password

#### 8. Credential File Scanner
**Discovery:** Spotlight for known credential file patterns

```
Spotlight queries:
  kMDItemFSName == "passwords.csv"
  kMDItemFSName == "1password-export*"
  kMDItemFSName == "bitwarden-export*"
  kMDItemFSName == "logins.csv"
  kMDItemFSName == "credentials*"
  kMDItemFSName == ".htpasswd"
  kMDItemFSName == "*.pfx" || "*.p12"
  kMDItemFSName == "wp-config.php"
```

**Checks:**
- Password manager export files (should be deleted after use)
- Certificate/key bundle files in unexpected locations
- Configuration files with embedded credentials (wp-config, database configs)

#### 9. Document Scanner
**Discovery:** Spotlight content search across all document types

```
Spotlight queries (content-based):
  kMDItemTextContent == "AKIA"              # AWS keys
  kMDItemTextContent == "sk-ant-api"        # Anthropic keys
  kMDItemTextContent == "sk-proj-"          # OpenAI keys  
  kMDItemTextContent == "ghp_"             # GitHub tokens
  kMDItemTextContent == "gho_"             # GitHub OAuth
  kMDItemTextContent == "sk_live_"          # Stripe live keys
  kMDItemTextContent == "rk_live_"          # Stripe restricted
  kMDItemTextContent == "xoxb-"             # Slack bot tokens
  kMDItemTextContent == "xoxp-"             # Slack user tokens
  kMDItemTextContent == "SG."               # SendGrid
  kMDItemTextContent == "eyJ"               # JWTs (base64 JSON)
```

**Coverage:** PDFs, Word docs, Pages, Excel, Numbers, Keynote, PowerPoint, RTF, Apple Notes, plain text, markdown, any Spotlight-indexed format.

**Password detection (two-step):**
1. Spotlight finds files containing "password", "passwd", "pwd", "secret_key"
2. Regex scan those files for actual password assignments, connection strings, auth headers

#### 10. AI Tool Scanner
**Discovery:** Known config paths (these are fixed by each tool) + Spotlight for project-level configs

| Tool | Config locations |
|------|-----------------|
| Claude Code | `~/.claude/settings.json`, `~/.claude/settings.local.json`, `.claude/settings.json` in projects, `CLAUDE.md` files, MCP configs |
| Cursor | `~/.cursor/`, workspace `.cursor/` dirs, MCP configs |
| GitHub Copilot | `~/.config/github-copilot/` |
| Windsurf / Codeium | `~/.codeium/`, `~/.windsurf/` |
| Continue.dev | `~/.continue/config.json`, `~/.continue/config.ts` |
| Aider | `~/.aider.conf.yml`, `.aider.conf.yml` in projects |
| OpenAI Codex CLI | `~/.codex/` |
| ChatGPT Desktop | `~/Library/Application Support/com.openai.chat/` |
| Cline | VS Code extension settings |
| Amazon Q | `~/.aws/amazonq/` |
| Gemini CLI | `~/.gemini/` |
| Copilot CLI | `~/.copilot/` |
| Any MCP server | All discovered `mcp*.json`, `claude_desktop_config.json` |

**Checks per tool:**
- Hardcoded API keys/tokens in config files
- MCP server configs: missing auth, overly permissive tool access, suspicious tool descriptions
- Installed skills/plugins: prompt injection patterns, data exfiltration indicators, suspicious shell commands
- Sandbox settings: is sandboxing disabled when it should be on?
- Environment variable definitions with plaintext secrets
- Hook configurations that could be exploited

### Pattern Database

The pattern database is built from the regex collection at github.com/Lu3ky13/Search-for-all-leaked-keys-secrets-using-one-regex- plus additional patterns:

**API Key Formats:**
- AWS: `AKIA[0-9A-Z]{16}`
- Google: `AIza[0-9A-Za-z-_]{35}`
- Stripe: `sk_live_[0-9a-zA-Z]{24,}`
- OpenAI: `sk-proj-[A-Za-z0-9_-]{40,}`
- Anthropic: `sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{40,}`
- GitHub: `gh[ps]_[A-Za-z0-9_]{36,}`
- Slack: `xox[bprs]-[A-Za-z0-9-]+`
- Twilio: `SK[0-9a-fA-F]{32}`
- SendGrid: `SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}`
- (200+ more patterns)

**Private Keys:**
- RSA: `-----BEGIN RSA PRIVATE KEY-----`
- OpenSSH: `-----BEGIN OPENSSH PRIVATE KEY-----`
- EC: `-----BEGIN EC PRIVATE KEY-----`
- PGP: `-----BEGIN PGP PRIVATE KEY BLOCK-----`
- Generic: `-----BEGIN PRIVATE KEY-----`

**Password Patterns:**
- Key-value: `(?:password|passwd|pwd|token|secret|api_key|apikey|auth)[=:]\s*['"]?([^\s'"]+)`
- Connection strings: `(?:postgres|mysql|mongodb|redis|amqp)://[^:]+:([^@]+)@`
- Basic auth: `Authorization:\s*Basic\s+[A-Za-z0-9+/=]+`
- Bearer tokens: `Authorization:\s*Bearer\s+[A-Za-z0-9._-]+`

**Credential Files:**
- Password exports: `passwords.csv`, `*-export*.csv`, `logins.csv`
- Key files: `*.pem`, `*.key`, `*.pfx`, `*.p12`
- Config with creds: `wp-config.php`, `.htpasswd`, `credentials`, `*.keystore`

## Risk Classification

Every finding gets two independent risk scores:

```swift
struct Finding {
    let id: String              // stable identifier for whitelisting
    let module: ScanModule      // which scanner found it
    let severity: Severity      // critical / high / medium / low / info
    let gitRisk: RiskLevel      // none / low / medium / high / critical
    let localRisk: RiskLevel    // none / low / medium / high / critical
    let filePath: String?
    let lineNumber: Int?
    let description: String
    let secretPreview: String   // first 4 chars + masked remainder
    let recommendation: String  // what to do about it
    let isNew: Bool             // first time seeing this finding
}
```

**Severity is derived from the higher of the two risk dimensions.**

Classification signals:
- In `.gitignore` -> lowers git risk, does NOT affect local risk
- Uses `op://` or vault reference -> both risks are none (properly managed)
- Value contains `localhost`/`127.0.0.1`/`dev`/`test` -> lowers severity but still flags
- File is in `~/Desktop` or `~/Downloads` -> raises severity (likely forgotten)
- File is a password manager export -> always critical
- Finding is in a document (PDF/Word/etc.) -> raises severity (unusual place for secrets)

## Whitelisting System

### Config File

```toml
# ~/.config/devsec/config.toml

[scan]
interval = 300              # seconds between scans (menubar app only)

[whitelist]
# Specific files to ignore entirely
files = [
    "~/Projects/demo/.env.example",
]

# Directories to skip
dirs = [
    "~/Projects/archived",
    "~/.Trash",
]

# Specific finding IDs to ignore (added via CLI or menubar app)
findings = []

# Patterns that are known-safe (test keys, example values)
safe_patterns = [
    "sk-test-*",
    "pk_test_*",
    "AKIAIOSFODNN7EXAMPLE",
    "django-insecure-*",
    "your-api-key-here",
    "changeme",
    "TODO",
]
```

### Whitelist Behavior
- Whitelisted items are hidden from reports by default
- `devsec scan --show-whitelisted` reveals them with a "whitelisted" tag
- Changed files are always re-scanned even if previously whitelisted
- The menubar app offers right-click "Whitelist this finding" which appends to config
- No auto-whitelisting -- every plaintext secret is a finding regardless of gitignore status

## CLI Interface

```bash
# Full scan (default)
devsec scan

# Scan specific modules only
devsec scan --modules ssh,env,ai

# Output formats
devsec scan --format text          # human readable (default)
devsec scan --format json          # machine readable
devsec scan --format markdown      # for reports

# Show whitelisted items too
devsec scan --show-whitelisted

# Manage whitelist
devsec whitelist add <finding-id>
devsec whitelist remove <finding-id>
devsec whitelist list

# Show details for a specific finding
devsec explain <finding-id>

# Migrate a .env file to 1Password references
devsec migrate <path-to-env-file>

# Check tool version and Spotlight health
devsec status
```

### CLI Output Example

```
$ devsec scan

devsec v1.0.0 -- scanning your machine
Using Spotlight (indexed, fast mode)

SSH Keys ............................................. 2 findings
Shell History ........................................ 3 findings
Environment Files .................................... 8 findings
Git Repositories ..................................... 1 finding
File Permissions ..................................... 1 finding
Ports ................................................ 0 findings
Clipboard ............................................ 0 findings
Credential Files ..................................... 1 finding
Documents ............................................ 2 findings
AI Tool Configs ...................................... 3 findings

--------------------------------------------------
21 findings (4 critical, 7 high, 6 medium, 4 low)
5 are new since last scan
--------------------------------------------------

CRITICAL  ~/Desktop/passwords.csv
          Password manager export file with 142 entries
          Recommendation: Delete this file immediately

CRITICAL  ~/Documents/onboarding.pdf
          Contains AWS key AKIA****EXAMPLE (page 3)
          Git risk: N/A | Local risk: CRITICAL
          Recommendation: Rotate this key and remove from document

CRITICAL  ~/Projects/api/.env
          DATABASE_URL contains production credentials
          Git risk: LOW (in .gitignore) | Local risk: HIGH
          Recommendation: Migrate to op://Production/Database/url

HIGH      ~/.zsh_history:4521
          Contains GitHub token ghp_****xxxx
          Recommendation: Rotate token, clear history entry

HIGH      ~/.cursor/mcp.json
          MCP server "filesystem" has unrestricted access
          Recommendation: Add path restrictions

...

Run 'devsec explain <id>' for details on any finding.
Run 'devsec whitelist add <id>' to suppress known-safe findings.
Run 'devsec migrate <file>' to move secrets to 1Password.
```

## Menubar App (Paid)

### UI Components

**Menu bar icon:** Colored dot indicating status
- Green: no critical/high findings
- Yellow: medium findings or scan in progress  
- Red: critical or high findings detected

**Popover (click icon):**
```
┌──────────────────────────────────┐
│ devsec                  ● green  │
├──────────────────────────────────┤
│ Last scan: 2 minutes ago         │
│ Next scan: in 3 minutes          │
│                                  │
│ SSH Keys        ✓  0 issues      │
│ Shell History   ⚠  2 medium      │
│ Env Files       ✗  1 critical    │
│ Git Repos       ✓  0 issues      │
│ Permissions     ✓  0 issues      │
│ Ports           ✓  0 issues      │
│ Clipboard       ✓  ok            │
│ Credentials     ✓  0 issues      │
│ Documents       ⚠  1 medium      │
│ AI Tools        ✓  0 issues      │
│                                  │
│ ┌──────────────────────────────┐ │
│ │ NEW: ~/Projects/api/.env     │ │
│ │ Production DB password       │ │
│ │ [Whitelist] [View] [Migrate] │ │
│ └──────────────────────────────┘ │
│                                  │
│ View Full Report                 │
│ Scan Now                         │
│ ──────────────────────────────── │
│ Settings...                      │
│ Quit                             │
└──────────────────────────────────┘
```

**Notifications:**
- Native macOS notifications for new critical/high findings
- Grouped notifications if multiple findings appear at once
- Action buttons in notification: "View" / "Whitelist"

**Settings window:**
- Scan interval slider (1 min to 1 hour)
- Enable/disable specific scan modules
- Manage whitelist (table view with delete)
- Notification preferences
- Spotlight status indicator + "Rebuild Index" button
- Launch at login toggle

### Menubar App Features (paid-only)
- Continuous background scanning on interval
- Native macOS notifications
- One-click whitelist from notification or popover
- One-click "Migrate to 1Password" action
- Auto-launch at login
- Settings GUI
- Auto-updates via App Store

## Migration Feature

The `devsec migrate` command helps move plaintext secrets to 1Password:

```bash
$ devsec migrate ~/Projects/myapp/.env

Scanning .env for secrets...
Found 4 values, 3 appear to be real secrets.

1. OPENAI_API_KEY=sk-proj-abc123...
   Store in 1Password? [Y/n] y
   Vault [Development]: 
   Item name [OpenAI API Key]: 
   Field [credential]: 
   Stored. Replaced with: op://Development/OpenAI API Key/credential

2. DATABASE_URL=postgres://user:pass@prod.server/db
   Store in 1Password? [Y/n] y
   Vault [Development]: Production
   Item name [Database]: 
   Field [url]: 
   Stored. Replaced with: op://Production/Database/url

3. DEBUG=true
   This does not appear to be a secret. Skip? [Y/n] y
   Skipped.

4. SECRET_KEY=django-insecure-abc123
   This appears to be a local dev placeholder. Skip? [Y/n] y
   Skipped.

Migration complete: 2 of 4 values moved to 1Password.

Your .env now requires: op run --env-file .env -- <your-command>

Updated .env:
  OPENAI_API_KEY=op://Development/OpenAI API Key/credential
  DATABASE_URL=op://Production/Database/url
  DEBUG=true
  SECRET_KEY=django-insecure-abc123
```

Requires: 1Password CLI (`op`) installed and authenticated. If not present, `devsec migrate` prints setup instructions instead.

## Tech Stack

- **Language:** Swift (native macOS, shared between CLI and app)
- **UI framework:** SwiftUI (menubar app)
- **Package structure:** Swift Package Manager (SPM)
- **Spotlight:** Foundation's `NSMetadataQuery` or shell `mdfind`
- **Pattern matching:** Swift Regex (Swift 5.7+)
- **Data persistence:** JSON files in `~/.config/devsec/`
- **1Password integration:** Shell out to `op` CLI
- **Minimum macOS:** 14.0 (Sonoma) -- for latest SwiftUI menubar APIs
- **Distribution:** Homebrew (CLI), Mac App Store (menubar app)

## Project Scope Boundaries

**In scope:**
- All 10 scan modules described above
- CLI with scan, whitelist, migrate, status commands
- Menubar app with continuous monitoring
- Whitelisting system
- JSON and text output formats
- 1Password migration helper
- Spotlight-based discovery with fallback

**Out of scope (potential future features):**
- Linux/Windows support (macOS only for v1)
- Team/enterprise features (dashboards, shared whitelists)
- CI/CD integration
- Automatic secret rotation
- Support for other secret managers beyond 1Password (Bitwarden, Vault)
- Browser extension
- Remote server scanning

## Testing Strategy

- Unit tests for each scanner module with fixture files containing known patterns
- Unit tests for pattern database (ensure all patterns match expected formats, no false positives on common text)
- Integration test: create a temporary directory with known secrets, run full scan, verify all found
- Spotlight fallback test: mock broken Spotlight, verify find+grep fallback works
- Whitelist test: verify whitelisted findings are excluded
- Risk classification tests: verify correct scoring for various scenarios
