import ArgumentParser

@main
struct DevsecCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "devsec",
        abstract: "macOS developer workstation security auditor",
        version: "0.1.0",
        subcommands: [ScanCommand.self, StatusCommand.self, WhitelistCommand.self]
    )
}
