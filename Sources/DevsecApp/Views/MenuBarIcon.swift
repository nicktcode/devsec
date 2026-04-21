import SwiftUI
import AppKit

// MARK: - MenuBarIcon

/// Menubar icon with an optional count badge. The beaver silhouette is
/// loaded as a template image so macOS tints it to match the menubar's
/// natural color (dark in light mode, light in dark mode). We don't
/// override the tint per status. the count badge next to the beaver
/// already turns red / orange to signal severity, so coloring the
/// beaver itself is redundant.
struct MenuBarIcon: View {
    let status: ScanStatus
    /// Number shown in the badge. `nil` or `0` = no badge. Caller
    /// decides what counts (typically unacknowledged critical + high).
    let badgeCount: Int?

    init(status: ScanStatus, badgeCount: Int? = nil) {
        self.status = status
        self.badgeCount = badgeCount
    }

    var body: some View {
        HStack(alignment: .center, spacing: 3) {
            // Menubar icons sit on the system baseline; the beaver has
            // more bbox weight above center than below (the tail
            // extends up-right), so geometric centering makes it look
            // like it's floating. A 1pt downward offset aligns the
            // visual center with the other menubar icons.
            beaverImage
                .frame(width: 18, height: 18)
                .offset(y: 1)

            if let badgeCount, badgeCount > 0 {
                Text(badgeText(badgeCount))
                    .font(.system(size: 10, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .foregroundStyle(.white)
                    .padding(.horizontal, 4)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(badgeColor))
            }
        }
    }

    // MARK: - Beaver Image

    /// Renders the bundled silhouette as a template image so macOS
    /// applies its menubar-appropriate tint automatically. Falls back
    /// to an SF Symbol shield if the resource is missing.
    @ViewBuilder
    private var beaverImage: some View {
        if let nsImage = Self.templateImage {
            Image(nsImage: nsImage)
                .resizable()
                .aspectRatio(contentMode: .fit)
        } else {
            Image(systemName: "shield")
                .symbolRenderingMode(.hierarchical)
        }
    }

    /// Cached NSImage of the beaver silhouette, marked as a template
    /// so macOS handles rendering in the menubar's natural color.
    private static let templateImage: NSImage? = {
        guard let url = Bundle.module.url(forResource: "MenubarBeaver", withExtension: "png"),
              let image = NSImage(contentsOf: url) else {
            return nil
        }
        image.isTemplate = true
        return image
    }()

    // MARK: - Badge

    /// Background color of the numeric count pill. Red when any
    /// critical findings are outstanding, orange for warnings, gray
    /// otherwise. This is the only visible severity signal in the
    /// menubar icon, so the pill color does the full job.
    private var badgeColor: Color {
        switch status {
        case .critical: return .red
        case .warnings: return .orange
        default:        return .secondary
        }
    }

    private func badgeText(_ count: Int) -> String {
        count > 99 ? "99+" : "\(count)"
    }
}
