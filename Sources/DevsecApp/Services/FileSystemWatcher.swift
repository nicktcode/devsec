import Foundation
import CoreServices
import DevsecCore
import os.log

private let watcherLog = Logger(
    subsystem: "com.nicktcode.damit",
    category: "fsevents"
)

// MARK: - FileSystemWatcher

/// FSEvents-backed watcher that observes the user's home directory for
/// file *creations and modifications*, coalesces them into a short
/// debounce window, and fires a callback with the list of changed
/// paths. This is the core of damit's "always on" value proposition, 
/// a scheduled-every-5-minutes scanner would miss a secret that lives
/// on disk for 30 seconds, but FSEvents catches it in roughly real
/// time with effectively zero CPU cost.
///
/// Intentional limitations:
///  - We only watch the home directory, not the whole volume. An
///    external drive or `/tmp` is out of scope.
///  - We ignore events from excluded / built-in-excluded paths
///    (node_modules, .venv, caches, etc.) so a `yarn install` doesn't
///    kick off 40,000 callback invocations.
///  - We debounce by 2 seconds. Rapid bursts from an IDE save, a
///    `git checkout`, or a test run collapse into a single scan
///    request with the unioned path set.
@MainActor
public final class FileSystemWatcher {

    // MARK: - Callback

    /// Called on the main actor with a deduplicated list of paths that
    /// changed inside the debounce window. Callers should treat the
    /// list as "scan these or fall back to a full scan".
    public var onChange: (([String]) -> Void)?

    // MARK: - State

    private var stream: FSEventStreamRef?
    private var pendingPaths: Set<String> = []
    private var debounceTask: Task<Void, Never>?
    // 5-second debounce window. A longer window gives us more
    // coalescing (fewer scans per unit time) at the cost of a slower
    // first-event-to-alert latency. Tuned empirically: 2s lets rapid
    // editor-save churn fire too often, 5s batches most IDE save-all
    // sequences and `git checkout`s into a single burst.
    private let debounce: TimeInterval = 5.0

    // MARK: - Lifecycle

    public init() {}

    // Intentionally no deinit: the watcher is owned by AppState for
    // the life of the app, and FSEventStreamRef isn't Sendable which
    // makes cleanup from a non-isolated deinit unsafe under strict
    // concurrency. Callers who need to tear down early should call
    // ``stop()`` from the main actor.

    // MARK: - Public API

    public func start() {
        guard stream == nil else { return }

        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let paths: CFArray = [home] as CFArray
        let context = UnsafeMutablePointer<FSEventStreamContext>.allocate(capacity: 1)
        context.initialize(to: FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        ))
        defer {
            context.deinitialize(count: 1)
            context.deallocate()
        }

        let flags: FSEventStreamCreateFlags =
            FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents) |
            FSEventStreamCreateFlags(kFSEventStreamCreateFlagNoDefer) |
            FSEventStreamCreateFlags(kFSEventStreamCreateFlagUseCFTypes)

        // Debounce latency here is in addition to our own 2-second debounce
        //. keeping this small means the first event in a burst still
        // arrives quickly, but we still coalesce in our own queue.
        let latency: CFTimeInterval = 0.5

        let created = FSEventStreamCreate(
            kCFAllocatorDefault,
            fsEventsCallback,
            context,
            paths,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            latency,
            flags
        )
        guard let created else { return }

        FSEventStreamSetDispatchQueue(created, DispatchQueue.global(qos: .utility))
        FSEventStreamStart(created)
        self.stream = created
    }

    public func stop() {
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
        debounceTask?.cancel()
        debounceTask = nil
        pendingPaths.removeAll()
    }

    // MARK: - Event Ingestion

    /// Called from the FSEvents queue. Pushes incoming paths into a
    /// pending set and kicks the debounce timer.
    nonisolated fileprivate func ingest(paths: [String]) {
        // Filter out paths under known-noisy directories *before*
        // accumulating. a `yarn install` can fire tens of thousands of
        // events in the first second, and we want to collapse them
        // cheaply without scheduling a scan per package.
        let filtered = paths.filter { path in
            !BuiltInScanExclusions.isExcluded(path)
                && !ScanExclusions.isExcluded(path)
        }

        // Log every raw FSEvents burst so the firing rate is visible
        // via `log stream --process DevsecApp --predicate 'subsystem ==
        // "com.nicktcode.damit"'`. Includes total vs filtered counts
        // so we can see how effective exclusions are, plus a sample
        // path when something survives the filter.
        if filtered.isEmpty {
            watcherLog.debug("raw \(paths.count, privacy: .public) events, all filtered out")
        } else {
            let sample = filtered.first ?? ""
            watcherLog.info(
                "raw \(paths.count, privacy: .public) events, \(filtered.count, privacy: .public) after filter, sample: \(sample, privacy: .public)"
            )
        }

        guard !filtered.isEmpty else { return }

        Task { @MainActor [weak self] in
            self?.receive(filtered)
        }
    }

    /// Main-actor ingestion: add to pending set and (re)arm the debounce.
    private func receive(_ paths: [String]) {
        pendingPaths.formUnion(paths)

        debounceTask?.cancel()
        debounceTask = Task { @MainActor [weak self] in
            guard let self else { return }
            try? await Task.sleep(for: .seconds(debounce))
            if Task.isCancelled { return }
            let batch = Array(pendingPaths)
            pendingPaths.removeAll()
            onChange?(batch)
        }
    }
}

// MARK: - FSEvents C Callback

/// FSEvents requires a C callback. We route back to the Swift watcher
/// via the retained self-pointer stashed in the stream context.
private func fsEventsCallback(
    streamRef: ConstFSEventStreamRef,
    clientCallbackInfo: UnsafeMutableRawPointer?,
    numEvents: Int,
    eventPaths: UnsafeMutableRawPointer,
    eventFlags: UnsafePointer<FSEventStreamEventFlags>,
    eventIds: UnsafePointer<FSEventStreamEventId>
) {
    guard let info = clientCallbackInfo else { return }
    let watcher = Unmanaged<FileSystemWatcher>.fromOpaque(info).takeUnretainedValue()

    // With kFSEventStreamCreateFlagUseCFTypes, eventPaths is a CFArray
    // of CFString (bridged to [String]).
    guard let cfPaths = unsafeBitCast(eventPaths, to: CFArray.self) as? [String] else {
        return
    }

    // Filter down to events we care about: file creation, modification,
    // or rename. Directory-only events would spam the set without
    // adding scan value.
    var changed: [String] = []
    changed.reserveCapacity(numEvents)
    for i in 0..<numEvents {
        let flags = eventFlags[i]
        let isFile = (flags & FSEventStreamEventFlags(kFSEventStreamEventFlagItemIsFile)) != 0
        let created = (flags & FSEventStreamEventFlags(kFSEventStreamEventFlagItemCreated)) != 0
        let modified = (flags & FSEventStreamEventFlags(kFSEventStreamEventFlagItemModified)) != 0
        let renamed = (flags & FSEventStreamEventFlags(kFSEventStreamEventFlagItemRenamed)) != 0
        guard isFile, (created || modified || renamed) else { continue }
        if i < cfPaths.count { changed.append(cfPaths[i]) }
    }
    if !changed.isEmpty {
        watcher.ingest(paths: changed)
    }
}
