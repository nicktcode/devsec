import ArgumentParser
import DevsecCore
import Foundation

struct ScanCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "scan",
        abstract: "Scan this machine for secrets and security issues"
    )

    // MARK: - Options

    @Option(name: .long, help: "Comma-separated list of modules to run (env,history,ssh,documents,ai-tools,credential-files)")
    var modules: String?

    @Option(name: .long, help: "Output format: text or json (default: text)")
    var format: String = "text"

    @Flag(name: .long, help: "Include whitelisted findings in output")
    var showWhitelisted: Bool = false

    // MARK: - Run

    func run() async throws {
        let isText = format != "json"

        // Print header and Spotlight health in text mode
        if isText {
            print("devsec v0.1.0")
            let health = await SpotlightEngine.checkHealth()
            if health.available {
                print("Spotlight: enabled")
            } else {
                print("Spotlight: unavailable -- using fallback search (slower)")
                print("  \(health.message)")
            }
            print("")
        }

        // Parse modules
        let selectedModules = parseModules(modules)

        // Set up managers
        let whitelist = WhitelistManager()
        try? whitelist.load()

        let store = FindingStore()

        // Run orchestrator
        let orchestrator = ScanOrchestrator(
            whitelistManager: whitelist,
            findingStore: store,
            modules: selectedModules
        )

        let result = try await orchestrator.scan()

        // Output
        if isText {
            print(TextFormatter.format(result))
        } else {
            print(JSONFormatter.format(result))
        }
    }

    // MARK: - Private

    private func parseModules(_ input: String?) -> Set<ScanModule>? {
        guard let input = input, !input.isEmpty else { return nil }
        let parts = input.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        var result: Set<ScanModule> = []
        for part in parts {
            if let module = ScanModule(rawValue: part) {
                result.insert(module)
            } else {
                fputs("Warning: unknown module '\(part)' -- ignoring\n", stderr)
            }
        }
        return result.isEmpty ? nil : result
    }
}
