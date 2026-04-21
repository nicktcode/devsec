import Foundation

// MARK: - BuiltInScanExclusions

/// Path-segment rules that damit always applies, regardless of user
/// configuration. Surfaced in the Settings UI so the user can see what's
/// being skipped (and why) without having to read the source.
///
/// These are **noise filters**, not security policy. we skip things that
/// are known to be generated caches, vendored dependencies, or third-party
/// data files that would otherwise flood the report with false positives.
///
/// A scanner should call ``isExcluded(_:)`` on every candidate path and skip
/// files that match. User-added exclusions (``ScanExclusions``) are applied
/// in addition to this list; neither overrides the other.
public enum BuiltInScanExclusions {

    // MARK: - Rule

    public struct Rule: Sendable, Hashable, Identifiable {
        public enum Kind: String, Sendable, Hashable {
            /// Match if any path component equals this string exactly.
            case component
            /// Match if any path component starts with this string.
            /// Example: prefix `"venv"` matches `"venv"`, `"venvNew"`, `"venv3.12"`.
            case componentPrefix
        }

        public let pattern: String
        public let kind: Kind
        public let category: String
        public let reason: String

        public var id: String { "\(kind.rawValue):\(pattern)" }
    }

    // MARK: - Rule List

    /// All built-in rules, grouped by ecosystem. Order matters for UI
    /// display but not for matching. the matcher scans the whole list.
    public static let rules: [Rule] = [
        // JS / TS ecosystem
        .init(pattern: "node_modules",  kind: .component, category: "Node.js", reason: "Installed npm dependencies. not your code."),
        .init(pattern: ".next",         kind: .component, category: "Node.js", reason: "Next.js build output."),
        .init(pattern: ".nuxt",         kind: .component, category: "Node.js", reason: "Nuxt.js build output."),
        .init(pattern: ".turbo",        kind: .component, category: "Node.js", reason: "Turborepo build cache."),
        .init(pattern: ".parcel-cache", kind: .component, category: "Node.js", reason: "Parcel bundler cache."),
        .init(pattern: ".svelte-kit",   kind: .component, category: "Node.js", reason: "SvelteKit build output."),
        .init(pattern: ".vercel",       kind: .component, category: "Node.js", reason: "Vercel build output."),
        .init(pattern: ".netlify",      kind: .component, category: "Node.js", reason: "Netlify build output."),
        .init(pattern: ".expo",         kind: .component, category: "Node.js", reason: "Expo build output."),
        .init(pattern: ".yarn",         kind: .component, category: "Node.js", reason: "Yarn cache/state."),
        .init(pattern: ".pnpm-store",   kind: .component, category: "Node.js", reason: "pnpm content-addressable store."),

        // Python ecosystem
        .init(pattern: "site-packages", kind: .component,       category: "Python", reason: "Installed Python packages (often contain fake test keys)."),
        .init(pattern: "__pycache__",   kind: .component,       category: "Python", reason: "Python bytecode cache."),
        .init(pattern: "venv",          kind: .componentPrefix, category: "Python", reason: "Virtual environment (venv, venvNew, venv3.12, …)."),
        .init(pattern: ".venv",         kind: .componentPrefix, category: "Python", reason: "Virtual environment (.venv, .venv-py311, …)."),
        .init(pattern: "virtualenv",    kind: .component,       category: "Python", reason: "Virtual environment."),
        .init(pattern: ".tox",          kind: .component,       category: "Python", reason: "tox multi-env test cache."),
        .init(pattern: ".pytest_cache", kind: .component,       category: "Python", reason: "pytest cache."),
        .init(pattern: ".mypy_cache",   kind: .component,       category: "Python", reason: "mypy type-check cache."),
        .init(pattern: ".ruff_cache",   kind: .component,       category: "Python", reason: "ruff lint cache."),
        .init(pattern: ".eggs",         kind: .component,       category: "Python", reason: "Installed egg packages."),

        // Ruby / PHP / Go
        .init(pattern: "vendor", kind: .component, category: "Vendored", reason: "Vendored third-party code (Ruby/PHP/Go)."),

        // Build output
        .init(pattern: "dist",   kind: .component, category: "Build output", reason: "Distribution/build output."),
        .init(pattern: "build",  kind: .component, category: "Build output", reason: "Build output directory."),
        .init(pattern: "out",    kind: .component, category: "Build output", reason: "Build output directory."),
        .init(pattern: "target", kind: .component, category: "Build output", reason: "Rust/Java/Maven build output."),

        // Xcode / iOS
        .init(pattern: "DerivedData", kind: .component, category: "Xcode", reason: "Xcode derived data / build output."),
        .init(pattern: "Pods",        kind: .component, category: "Xcode", reason: "CocoaPods vendored dependencies."),
        .init(pattern: "Carthage",    kind: .component, category: "Xcode", reason: "Carthage vendored dependencies."),

        // OS / tool caches
        .init(pattern: ".cache",     kind: .component, category: "Caches", reason: "Generic build cache directory."),
        .init(pattern: "Caches",     kind: .component, category: "Caches", reason: "macOS cache directory."),
        .init(pattern: "CachedData", kind: .component, category: "Caches", reason: "App cache directory."),
        .init(pattern: ".Trash",     kind: .component, category: "Caches", reason: "macOS Trash."),

        // macOS Library churn. directories that fire FSEvents constantly
        // (app sandboxes, system stores, browser engine data). Excluding
        // them stops file-change triggers from storming damit every few
        // seconds. Any credential-bearing data in these dirs (e.g. Mail
        // messages) would need a dedicated scanner anyway. a raw-file
        // scan of ~/Library/Mail is too noisy to be useful.
        .init(pattern: "Logs",                     kind: .component, category: "macOS Library", reason: "~/Library/Logs. constant system/app log churn."),
        .init(pattern: "Saved Application State",  kind: .component, category: "macOS Library", reason: "Window-state snapshots written on every app switch."),
        .init(pattern: "Containers",               kind: .component, category: "macOS Library", reason: "App sandbox containers. write constantly, no credentials in plaintext."),
        .init(pattern: "Group Containers",         kind: .component, category: "macOS Library", reason: "Shared app-group sandboxes. same churn pattern as Containers."),
        .init(pattern: "Cookies",                  kind: .component, category: "macOS Library", reason: "Browser / app cookie stores. not our detection target."),
        .init(pattern: "HTTPStorages",             kind: .component, category: "macOS Library", reason: "WebKit/HTTP session state. writes on every request."),
        .init(pattern: "WebKit",                   kind: .component, category: "macOS Library", reason: "WebKit internal data store."),
        .init(pattern: "Metadata",                 kind: .component, category: "macOS Library", reason: "CoreSpotlight + app metadata churn."),
        .init(pattern: "Mail",                     kind: .component, category: "macOS Library", reason: "Apple Mail store. encrypted on disk with local keys."),
        .init(pattern: "Messages",                 kind: .component, category: "macOS Library", reason: "iMessage SQLite store. updates on every message."),
        .init(pattern: "Mobile Documents",         kind: .component, category: "macOS Library", reason: "iCloud Drive local cache. constant sync churn."),
        .init(pattern: "CloudStorage",             kind: .component, category: "macOS Library", reason: "Dropbox/Drive/OneDrive local caches."),
        .init(pattern: "IdentityServices",         kind: .component, category: "macOS Library", reason: "iMessage/FaceTime identity cache. churns frequently."),
        .init(pattern: "Biome",                    kind: .component, category: "macOS Library", reason: "On-device learning data. written continuously."),
        .init(pattern: "Safari",                   kind: .component, category: "macOS Library", reason: "Safari browser data (history, bookmarks, sessions)."),
        .init(pattern: "Accounts",                 kind: .component, category: "macOS Library", reason: "Accounts framework storage. churns on login state changes."),
        .init(pattern: "CallServices",             kind: .component, category: "macOS Library", reason: "Phone / FaceTime call logs."),
        .init(pattern: "Suggestions",              kind: .component, category: "macOS Library", reason: "Proactive / Siri suggestions cache."),
        .init(pattern: "Assistant",                kind: .component, category: "macOS Library", reason: "Siri assistant state."),

        // Third-party library data
        .init(
            pattern: "ZxcvbnData",
            kind: .component,
            category: "Library data",
            reason: "zxcvbn password-strength dictionary (common-passwords wordlist shipped by Chromium/Electron. not your credentials)."
        ),

        // Electron / Chromium app churn. Every Electron app (VS Code,
        // Claude Desktop, Discord, Slack, Beeper, Cursor, …) writes to
        // these subdirectories constantly. Excluding them at the
        // component level kills most of the FSEvents spam from the
        // modern desktop-app ecosystem without losing anything we
        // actually want to scan.
        .init(pattern: "Local Storage",           kind: .component, category: "Electron apps", reason: "Chromium leveldb store. continuous writes for every Electron app."),
        .init(pattern: "IndexedDB",               kind: .component, category: "Electron apps", reason: "Browser IndexedDB. updates on any app state change."),
        .init(pattern: "Session Storage",         kind: .component, category: "Electron apps", reason: "Browser session storage."),
        .init(pattern: "Code Cache",              kind: .component, category: "Electron apps", reason: "V8 bytecode cache."),
        .init(pattern: "GPUCache",                kind: .component, category: "Electron apps", reason: "GPU shader cache."),
        .init(pattern: "Cache_Data",              kind: .component, category: "Electron apps", reason: "Chromium disk cache data."),
        .init(pattern: "Service Worker",          kind: .component, category: "Electron apps", reason: "Service worker storage. writes on every page load."),
        .init(pattern: "Crashpad",                kind: .component, category: "Electron apps", reason: "Crash reporting spool."),
        .init(pattern: "Dictionaries",            kind: .component, category: "Electron apps", reason: "Spellcheck dictionary downloads."),
        .init(pattern: "Network Persistent State", kind: .component, category: "Electron apps", reason: "Chromium network state. writes on every network event."),
        .init(pattern: "sentry",                  kind: .component, category: "Electron apps", reason: "Sentry SDK crash/telemetry cache."),
        .init(pattern: "sdk-tmp",                 kind: .component, category: "Electron apps", reason: "Matrix / Beeper SDK temp files. high-frequency writes."),

        // macOS Continuity / Handoff system data
        .init(pattern: "DuetExpertCenter",        kind: .component, category: "macOS Library", reason: "Apple Continuity / Handoff bookmark store. writes constantly."),
        .init(pattern: "com.apple.aiml.instrumentation", kind: .component, category: "macOS Library", reason: "Apple machine learning telemetry."),
        .init(pattern: "knowledge",               kind: .component, category: "macOS Library", reason: "Apple knowledge store (Siri suggestions). frequent writes."),
        .init(pattern: "DuetKnowledgeBase",       kind: .component, category: "macOS Library", reason: "Apple Continuity knowledge base."),

    ]

    /// Absolute-path substrings that never count as changes for the
    /// watcher (and never count as scannable content). Specifically
    /// damit's own on-disk state: without this, every scan writes to
    /// `~/.config/damit/history.json`, which fires FSEvents, which
    /// triggers the next scan. Feedback loop that keeps the app
    /// perpetually scanning.
    ///
    /// Kept separate from the component rule list because these are
    /// path-substring matches, not component matches. we don't want
    /// to accidentally exclude a folder the user names "damit" (like
    /// their clone of this repo).
    public static let selfPathFragments: [String] = [
        "/.config/damit/",
        "/Library/Preferences/com.nicktcode.damit.",
        "/Library/Application Support/damit/",
        "/Library/Caches/com.nicktcode.damit/",
    ]

    // MARK: - Matching

    /// Returns true if `path` has any component that matches a built-in
    /// rule, or contains any self-path fragment (damit's own state
    /// directory). Both checks are component- or substring-based so
    /// they're cheap on the FSEvents hot path.
    public static func isExcluded(_ path: String) -> Bool {
        // Self-paths: cheap substring check first. This is what kills
        // the "scan writes state → FSEvents fires → new scan" loop.
        for fragment in selfPathFragments {
            if path.contains(fragment) { return true }
        }
        let components = (path as NSString).pathComponents
        for component in components {
            for rule in rules {
                switch rule.kind {
                case .component:
                    if component == rule.pattern { return true }
                case .componentPrefix:
                    if component.hasPrefix(rule.pattern) { return true }
                }
            }
        }
        return false
    }

    /// Rules grouped by category, preserving first-appearance order so the
    /// Settings UI shows a predictable list.
    public static var rulesByCategory: [(category: String, rules: [Rule])] {
        var seenOrder: [String] = []
        var grouped: [String: [Rule]] = [:]
        for rule in rules {
            if grouped[rule.category] == nil {
                seenOrder.append(rule.category)
            }
            grouped[rule.category, default: []].append(rule)
        }
        return seenOrder.map { ($0, grouped[$0] ?? []) }
    }
}
