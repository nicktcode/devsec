import Foundation
import UserNotifications

// MARK: - NotificationService

public final class NotificationService: Sendable {

    // MARK: - Init

    public init() {}

    // MARK: - Permission

    public func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(
            options: [.alert, .sound, .badge]
        ) { _, _ in
            // Ignore result; user can change in System Settings later
        }
    }

    // MARK: - Notifications

    public func sendNewFindingsNotification(count: Int, critical: Int) {
        let content = UNMutableNotificationContent()
        content.title = "devsec: New Findings Detected"

        if critical > 0 {
            content.body = "\(count) new finding\(count == 1 ? "" : "s") — \(critical) critical. Tap to review."
            content.sound = .defaultCritical
        } else {
            content.body = "\(count) new finding\(count == 1 ? "" : "s") detected. Tap to review."
            content.sound = .default
        }

        let request = UNNotificationRequest(
            identifier: "devsec.newFindings.\(Date().timeIntervalSince1970)",
            content: content,
            trigger: nil // deliver immediately
        )

        UNUserNotificationCenter.current().add(request) { _ in
            // Ignore errors silently
        }
    }
}
