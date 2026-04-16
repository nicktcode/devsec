import ArgumentParser
import DevsecCore
import Foundation

struct WhitelistCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "whitelist",
        abstract: "Manage the finding whitelist",
        subcommands: [Add.self, Remove.self, List.self]
    )
}

// MARK: - Add

extension WhitelistCommand {
    struct Add: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "add",
            abstract: "Add a finding ID to the whitelist"
        )

        @Argument(help: "The finding ID to whitelist")
        var findingID: String

        func run() throws {
            let manager = WhitelistManager()
            try? manager.load()
            manager.addFinding(findingID)
            try manager.save()
            print("Added '\(findingID)' to the whitelist.")
        }
    }
}

// MARK: - Remove

extension WhitelistCommand {
    struct Remove: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "remove",
            abstract: "Remove a finding ID from the whitelist"
        )

        @Argument(help: "The finding ID to remove from the whitelist")
        var findingID: String

        func run() throws {
            let manager = WhitelistManager()
            try? manager.load()
            manager.removeFinding(findingID)
            try manager.save()
            print("Removed '\(findingID)' from the whitelist.")
        }
    }
}

// MARK: - List

extension WhitelistCommand {
    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "list",
            abstract: "List all whitelisted finding IDs"
        )

        func run() throws {
            let manager = WhitelistManager()
            try? manager.load()
            let all = manager.allFindings
            if all.isEmpty {
                print("No findings are whitelisted.")
            } else {
                print("Whitelisted finding IDs:")
                for id in all {
                    print("  \(id)")
                }
            }
        }
    }
}
