import ArgumentParser
import DevsecCore
import Foundation

struct StatusCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Show the current status of damit"
    )

    func run() async throws {
        print("damit v0.1.0")
        print("")

        // Spotlight health
        let health = await SpotlightEngine.checkHealth()
        let spotlightStatus = health.available ? "enabled" : "unavailable"
        print("Spotlight   : \(spotlightStatus)")

        // Config file
        let configPath = NSHomeDirectory() + "/.config/damit/config.json"
        let configExists = FileManager.default.fileExists(atPath: configPath)
        print("Config      : \(configExists ? configPath : "not found")")

        // Finding store
        let storePath = NSHomeDirectory() + "/.config/damit/findings.json"
        let storeExists = FileManager.default.fileExists(atPath: storePath)
        print("Finding store: \(storeExists ? storePath : "not found")")
    }
}
