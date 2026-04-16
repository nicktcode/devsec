# devsec

A macOS security auditor for developer workstations. Finds exposed secrets, API keys, passwords, and credentials across the entire machine - not just code repositories.

## What it finds

- API keys in any file: AWS, OpenAI, Anthropic, GitHub, Stripe, Slack, and 200+ additional patterns
- SSH private keys anywhere on disk, including randomly named files, with permission checks
- Passwords in `.env` files, config files, shell history, and documents
- Credential exports left on disk: `passwords.csv`, 1Password exports, Bitwarden exports, and similar files
- AI tool misconfigurations: hardcoded keys in Claude Code, Cursor, Copilot, Windsurf, Aider, Codex, and more
- Secrets in documents: PDFs, Word docs, spreadsheets, and Apple Notes

## How it works

devsec uses macOS Spotlight to perform instant full-disk searches without traversing the filesystem manually. It finds secrets by content pattern, not just filename. If Spotlight is unavailable or restricted, it falls back to `find` + `grep`.

Each finding receives two independent risk scores:

- **Git leak risk** - likelihood that this secret could end up in a public repository
- **Local compromise risk** - severity if an attacker gained local access to the machine

## Install

### Build from source

```sh
git clone https://github.com/nickthommen/devsec
cd devsec
swift build -c release
cp .build/release/devsec-cli /usr/local/bin/devsec
```

Homebrew tap coming soon.

## Usage

Run a full scan:

```sh
devsec scan
```

Scan specific modules only:

```sh
devsec scan --modules ssh,env,ai-tools
```

Output results as JSON:

```sh
devsec scan --format json
```

Whitelist a finding by ID:

```sh
devsec whitelist add "finding-id"
```

Show current configuration and whitelist summary:

```sh
devsec status
```

## Whitelisting

The first run will surface a number of findings that are intentional - test credentials, local-only keys, demo configs. Use whitelisting to mark these as reviewed so they no longer appear in subsequent scans.

```sh
devsec whitelist add "finding-id"
```

The whitelist is stored at `~/.config/devsec/whitelist.json`. Findings are matched by a stable ID derived from the file path and matched pattern, so the whitelist remains valid across runs as long as the file is not moved.

## Modules

| Module | What it scans |
|---|---|
| `env` | `.env` files, `.env.*` variants, config files with `PASSWORD=`, `SECRET=`, `TOKEN=` patterns |
| `history` | Shell history files (bash, zsh, fish) for inline credentials and `export` statements |
| `ssh` | SSH private keys by header pattern and file permissions; identifies keys outside `~/.ssh` |
| `documents` | PDFs, Word documents, Excel spreadsheets, Apple Notes for credential patterns |
| `ai-tools` | Config files for AI coding tools: Claude Code, Cursor, Copilot, Windsurf, Aider, Codex |
| `credential-files` | Exported credential files: password manager exports, `credentials.json`, `passwords.csv` |

## License

AGPL-3.0 - see [LICENSE](LICENSE).
