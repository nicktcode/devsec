import Foundation

// MARK: - ScanScheduler

@MainActor
public final class ScanScheduler {

    // MARK: - Properties

    private weak var appState: AppState?
    private var timer: Timer?

    // MARK: - Init

    public init(appState: AppState) {
        self.appState = appState
    }

    // MARK: - Public Interface

    public func start() {
        stop()

        // Run an initial scan immediately
        Task { [weak appState] in
            await appState?.runScan()
        }

        scheduleRepeating()
    }

    public func stop() {
        timer?.invalidate()
        timer = nil
    }

    public func updateInterval(_ interval: TimeInterval) {
        guard let appState else { return }
        appState.scanInterval = interval
        if timer != nil {
            stop()
            scheduleRepeating()
        }
    }

    // MARK: - Private

    private func scheduleRepeating() {
        guard let appState else { return }
        let interval = appState.scanInterval

        // Timer callbacks fire on the run loop; capture weak ref and dispatch to MainActor
        let t = Timer(timeInterval: interval, repeats: true) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor [weak self] in
                await self?.appState?.runScan()
            }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }
}
