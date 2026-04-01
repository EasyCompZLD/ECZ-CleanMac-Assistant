import AppKit
import SwiftUI

struct InstalledApplicationRecord: Identifiable {
    let id: String
    let name: String
    let url: URL
    let bundleIdentifier: String?
    let version: String?
    let icon: NSImage

    var displayLocation: String {
        if url.path.hasPrefix("/Applications") {
            return "/Applications"
        }

        let homePrefix = FileManager.default.homeDirectoryForCurrentUser.path + "/"
        if url.path.hasPrefix(homePrefix) {
            return "~/" + String(url.path.dropFirst(homePrefix.count))
        }

        return url.deletingLastPathComponent().path
    }
}

@MainActor
final class AppViewModel: ObservableObject {
    private enum UpdateCheckTrigger {
        case automatic
        case manual
    }

    @Published var selectedModuleID: MaintenanceModuleID = .smartCare
    @Published var enabledTaskIDs: Set<MaintenanceTaskID>
    @Published var taskStates: [MaintenanceTaskID: TaskRunState] = [:]
    @Published var scanStates: [MaintenanceTaskID: TaskScanState] = [:]
    @Published var activityEntries: [ActivityEntry] = []
    @Published var isRunning = false
    @Published var isScanningModule = false
    @Published var currentTaskID: MaintenanceTaskID?
    @Published var completedTaskCount = 0
    @Published var totalTaskCount = 0
    @Published var currentRunTitle = ""
    @Published var lastRunSummary = localized("No maintenance run yet.", "Nog geen onderhoudsrun uitgevoerd.")
    @Published var lastRunReport: RunCompletionReport?
    @Published var updateState: UpdateCheckState = .idle
    @Published var availableUpdateOffer: AppUpdateOffer?
    @Published var updateInstallState: AppUpdateInstallState = .idle
    @Published var reviewTaskID: MaintenanceTaskID?
    @Published var reviewSelections: Set<String> = []
    @Published var reviewInputText = ""
    @Published var applicationPickerQuery = ""
    @Published var taskOutputs: [MaintenanceTaskID: String] = [:]
    @Published var liveTaskPhase = ""
    @Published var liveTaskCurrentItem = ""
    @Published var liveTaskProcessedCount = 0
    @Published var liveTaskExpectedCount = 0
    @Published var liveTaskRecentLines: [String] = []
    @Published var liveDetectedThreats: [MalwareThreat] = []
    @Published var latestMalwareOutcome: MalwareScanOutcome?
    @Published var malwareThreatActionSelections: [String: MalwareThreatActionChoice] = [:]
    @Published var malwareThreatResolutions: [String: MalwareThreatResolution] = [:]
    @Published var isApplyingMalwareThreatActions = false
    @Published var isShowingAbout = false
    @Published private(set) var managedFileAccessFolders: [ManagedFileAccessFolder] = ManagedFileAccessStore.storedFolders()
    @Published private(set) var installedApplications: [InstalledApplicationRecord] = []
    @Published private(set) var isLoadingInstalledApplications = false
    #if DEVELOPER_BUILD
    @Published var isPlaceboModeEnabled = false {
        didSet {
            closeReview()
            closeAbout()
            Task {
                await scanCurrentModule()
            }
        }
    }
    @Published var isShowingDeveloperPanel = false
    @Published var debugLanguageOverride: DebugLanguageOverride = .load() {
        didSet {
            debugLanguageOverride.persist()
        }
    }
    @Published var isPlayingDeveloperTour = false
    @Published var developerTourTitle = ""
    @Published var developerTourDetail = ""
    @Published var developerTourStepIndex = 0
    @Published var developerTourStepCount = 0
    #endif

    private let executor = MaintenanceCommandExecutor()
    private let scanner = MaintenanceScanner()
    private let updateChecker = UpdateChecker()
    private let selfUpdater = AppSelfUpdater()
    private var progressObserver: NSObjectProtocol?
    private var activeRunTasks: [MaintenanceTaskDefinition] = []
    private var runStartedAt: Date?
    private var currentTaskStartedAt: Date?

    private var savedPromptValues: [MaintenanceTaskID: String] = [:]
    private var savedComponentSelections: [MaintenanceTaskID: Set<String>] = [:]
    private var reviewedConfirmationTasks: Set<MaintenanceTaskID> = []
    #if DEVELOPER_BUILD
    private var developerTourTask: Task<Void, Never>?
    #endif

    init() {
        enabledTaskIDs = Set(MaintenanceCatalog.tasks.map(\.id))
        activityEntries = [
            ActivityEntry(
                timestamp: Date(),
                title: localized("Ready", "Klaar"),
                detail: localized("CleanMac Assistant is ready. Pick a page on the left to see what can be cleaned or checked.", "CleanMac Assistant is klaar. Kies links een pagina om te zien wat kan worden opgeschoond of gecontroleerd."),
                isError: false
            )
        ]

        progressObserver = NotificationCenter.default.addObserver(
            forName: MaintenanceProgressNotification.name,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let taskIDRaw = notification.userInfo?[MaintenanceProgressNotification.taskIDKey] as? String,
                  let line = notification.userInfo?[MaintenanceProgressNotification.lineKey] as? String
            else {
                return
            }

            Task { @MainActor [weak self] in
                self?.consumeMaintenanceProgress(taskIDRaw: taskIDRaw, line: line)
            }
        }

        Task {
            await scanCurrentModule()
        }

        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2.2))
            performAutomaticUpdateCheckIfNeeded()
        }
    }

    var isPlaceboModeActive: Bool {
        #if DEVELOPER_BUILD
        return isPlaceboModeEnabled
        #else
        return false
        #endif
    }

    var modules: [MaintenanceModule] {
        MaintenanceCatalog.modules
    }

    var selectedModule: MaintenanceModule {
        MaintenanceCatalog.module(for: selectedModuleID)
    }

    var selectedModuleTasks: [MaintenanceTaskDefinition] {
        MaintenanceCatalog.tasks(for: selectedModuleID)
    }

    var selectedTaskCount: Int {
        selectedModuleTasks.filter { enabledTaskIDs.contains($0.id) }.count
    }

    var highImpactTaskCount: Int {
        selectedModuleTasks.filter { $0.impact == .high || $0.impact == .longRunning }.count
    }

    var selectedModuleEstimatedCleanup: String {
        if isScanningModule {
            return localized("Checking...", "Controleren...")
        }

        let totalBytes = selectedModuleTasks.reduce(Int64(0)) { partialResult, task in
            partialResult + (scanFinding(for: task.id)?.reclaimableBytes ?? 0)
        }

        guard totalBytes > 0 else {
            return localized("Nothing big", "Niets groots")
        }

        return byteCountString(totalBytes)
    }

    var selectedModuleEstimatedCleanupCaption: String {
        if isScanningModule {
            return localized("Looking through this page first", "Deze pagina wordt eerst bekeken")
        }

        let findings = selectedModuleTasks.compactMap { scanFinding(for: $0.id) }
        let matchedTasks = findings.filter { ($0.reclaimableBytes ?? 0) > 0 || ($0.itemCount ?? 0) > 0 }.count

        if matchedTasks == 0 {
            return localized("No major cleanup found here right now", "Hier is nu geen grote opschoning gevonden")
        }

        return localized("\(matchedTasks) task(s) found something to review", "\(matchedTasks) taak/taken hebben iets gevonden om te bekijken")
    }

    var updateStatusText: String {
        switch updateState {
        case .idle:
            return localized("No update check yet.", "Nog geen updatecontrole uitgevoerd.")
        case .checking:
            return localized("Checking for a new version...", "Controleren op een nieuwe versie...")
        case let .upToDate(currentVersion, latestVersion):
            if currentVersion == latestVersion {
                return localized(
                    "Latest found: version \(latestVersion). This Mac is up to date.",
                    "Nieuwste gevonden: versie \(latestVersion). Deze Mac is bijgewerkt."
                )
            }

            return localized(
                "Latest in downloads: \(latestVersion). This Mac is already on \(currentVersion).",
                "Nieuwste in downloads: \(latestVersion). Deze Mac draait al op \(currentVersion)."
            )
        case let .updateAvailable(version, _, _):
            return localized("Version \(version) is available.", "Versie \(version) is beschikbaar.")
        case let .failed(message):
            return message
        }
    }

    var appVersionLabel: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? AppBuildFlavor.currentVersion
        return localized(
            "Version \(version) • \(AppBuildFlavor.buildLabel)",
            "Versie \(version) • \(AppBuildFlavor.buildLabel)"
        )
    }

    var selectedModuleTaskReports: [RunTaskReport] {
        selectedModuleTasks.compactMap { task in
            let state = taskStates[task.id] ?? .idle
            let output = latestTaskOutput(for: task.id)
            guard state.isTerminal || output != nil else {
                return nil
            }

            return RunTaskReport(
                id: task.id,
                title: task.title.appLocalized,
                state: state,
                summary: state.resultSummary ?? task.subtitle.appLocalized,
                output: output
            )
        }
    }

    var hasSelectedModuleTaskResults: Bool {
        !selectedModuleTaskReports.isEmpty
    }

    var selectedModuleCompletedResultCount: Int {
        selectedModuleTaskReports.reduce(into: 0) { count, report in
            if case .succeeded = report.state {
                count += 1
            }
        }
    }

    var selectedModuleSkippedResultCount: Int {
        selectedModuleTaskReports.reduce(into: 0) { count, report in
            if case .skipped = report.state {
                count += 1
            }
        }
    }

    var selectedModuleIssueResultCount: Int {
        selectedModuleTaskReports.reduce(into: 0) { count, report in
            if case .failed = report.state {
                count += 1
            }
        }
    }

    var selectedModuleResultSummary: String {
        localized(
            "\(selectedModuleCompletedResultCount) done • \(selectedModuleSkippedResultCount) skipped • \(selectedModuleIssueResultCount) issues. The tool cards below keep each result separated per action.",
            "\(selectedModuleCompletedResultCount) klaar • \(selectedModuleSkippedResultCount) overgeslagen • \(selectedModuleIssueResultCount) problemen. De toolkaarten hieronder houden elk resultaat per actie gescheiden."
        )
    }

    var shouldShowActivityConsole: Bool {
        !hasSelectedModuleTaskResults && (activityEntries.count > 1 || lastRunReport != nil)
    }

    var hasManagedFileAccess: Bool {
        !managedFileAccessFolders.isEmpty
    }

    var managedFileAccessSummary: String {
        guard !managedFileAccessFolders.isEmpty else {
            return localized(
                "No folders connected yet. Choose folders once to avoid repeated macOS prompts during file scans.",
                "Er zijn nog geen mappen gekoppeld. Kies mappen één keer om herhaalde macOS-meldingen tijdens bestandsscans te voorkomen."
            )
        }

        return localized(
            "\(managedFileAccessFolders.count) folder(s) connected for file scans.",
            "\(managedFileAccessFolders.count) map(pen) gekoppeld voor bestandsscans."
        )
    }

    var isShowingUpdateExperience: Bool {
        availableUpdateOffer != nil || updateInstallState.isPresented
    }

    var updateInstallTitle: String {
        switch updateInstallState {
        case .idle:
            return localized("Update ready", "Update klaar")
        case .downloading:
            return localized("Downloading update", "Update downloaden")
        case .preparing:
            return localized("Preparing install", "Installatie voorbereiden")
        case .installing:
            return localized("Installing update", "Update installeren")
        case .failed:
            return localized("Update did not finish", "Update is niet voltooid")
        }
    }

    var updateInstallDetail: String {
        switch updateInstallState {
        case .idle:
            return ""
        case let .downloading(version):
            return localized(
                "Version \(version) is downloading now.",
                "Versie \(version) wordt nu gedownload."
            )
        case let .preparing(version):
            return localized(
                "Version \(version) is being prepared for installation.",
                "Versie \(version) wordt voorbereid voor installatie."
            )
        case let .installing(version):
            return localized(
                "Version \(version) is being installed. The app will relaunch automatically.",
                "Versie \(version) wordt geïnstalleerd. De app start daarna automatisch opnieuw."
            )
        case let .failed(_, message):
            return message
        }
    }

    var runProgressFraction: Double {
        guard totalTaskCount > 0 else { return 0 }
        let completed = Double(completedTaskCount)
        let currentFraction = currentTaskProgressFraction
        return min(max((completed + currentFraction) / Double(totalTaskCount), 0), 1)
    }

    var visibleProgressFraction: Double {
        if currentTaskID == .malware, liveTaskExpectedCount > 0 {
            return currentTaskProgressFraction
        }
        return runProgressFraction
    }

    var visibleProgressPercent: Int {
        Int((visibleProgressFraction * 100).rounded())
    }

    var visibleProgressCaption: String {
        if currentTaskID == .malware, liveTaskExpectedCount > 0 {
            return localized("scanned", "gescand")
        }
        return localized("done", "klaar")
    }

    var visibleProgressSectionTitle: String {
        if currentTaskID == .malware, liveTaskExpectedCount > 0 {
            return localized("Live scan progress", "Live scanvoortgang")
        }
        return localized("Live progress", "Live voortgang")
    }

    var runProgressTitle: String {
        if let currentTaskID {
            return MaintenanceCatalog.task(for: currentTaskID).title.appLocalized
        }

        if !currentRunTitle.isEmpty {
            return currentRunTitle.appLocalized
        }

        return localized("Maintenance", "Onderhoud")
    }

    var runProgressDetail: String {
        guard totalTaskCount > 0 else {
            return localized("Choose a page and review what can be cleaned.", "Kies een pagina en bekijk wat opgeschoond kan worden.")
        }

        if let progressSummary = liveTaskProgressSummary {
            return progressSummary
        }

        if let livePhase = liveTaskPhase.trimmed.nilIfEmpty {
            return livePhase
        }

        if currentTaskID != nil {
            let step = min(completedTaskCount + 1, totalTaskCount)
            return localized("Step \(step) of \(totalTaskCount)", "Stap \(step) van \(totalTaskCount)")
        }

        return localized("\(completedTaskCount) of \(totalTaskCount) steps finished", "\(completedTaskCount) van \(totalTaskCount) stappen voltooid")
    }

    func runElapsedChipText(at now: Date) -> String? {
        guard let elapsed = runElapsedSeconds(at: now) else { return nil }
        return localized("Elapsed \(formattedDuration(elapsed))", "Verstreken \(formattedDuration(elapsed))")
    }

    func runRemainingChipText(at now: Date) -> String? {
        guard let remaining = runRemainingSeconds(at: now) else { return nil }
        return localized("ETA \(formattedDuration(remaining)) left", "ETA nog \(formattedDuration(remaining))")
    }

    func runCompletionTimeChipText(at now: Date) -> String? {
        guard let remaining = runRemainingSeconds(at: now) else { return nil }
        return localized(
            "Around \(formattedClock(now.addingTimeInterval(remaining)))",
            "Rond \(formattedClock(now.addingTimeInterval(remaining)))"
        )
    }

    func currentTaskTimingDetail(at now: Date) -> String {
        let elapsed = currentTaskElapsedSeconds(at: now)
        let remaining = currentTaskRemainingSeconds(at: now)

        switch (remaining, elapsed) {
        case let (.some(remaining), .some(elapsed)):
            return localized(
                "ETA \(formattedDuration(remaining)) left • \(formattedDuration(elapsed)) elapsed",
                "ETA nog \(formattedDuration(remaining)) • \(formattedDuration(elapsed)) verstreken"
            )
        case let (.some(remaining), nil):
            return localized(
                "ETA \(formattedDuration(remaining)) left",
                "ETA nog \(formattedDuration(remaining))"
            )
        case let (nil, .some(elapsed)):
            return localized(
                "\(formattedDuration(elapsed)) elapsed",
                "\(formattedDuration(elapsed)) verstreken"
            )
        case (nil, nil):
            return localized("Calculating time", "Tijd wordt berekend")
        }
    }

    var hasLiveTaskProgress: Bool {
        !liveTaskCurrentItem.isEmpty || liveTaskProcessedCount > 0 || !liveTaskRecentLines.isEmpty
    }

    var liveTaskCurrentItemLabel: String? {
        liveTaskCurrentItem.trimmed.nilIfEmpty
    }

    var liveTaskProcessedCountLabel: String? {
        guard liveTaskProcessedCount > 0 else { return nil }

        if currentTaskID == .malware {
            if liveTaskExpectedCount > 0 {
                return localized(
                    "\(liveTaskProcessedCount) of \(liveTaskExpectedCount) files checked",
                    "\(liveTaskProcessedCount) van \(liveTaskExpectedCount) bestanden gecontroleerd"
                )
            }
            return localized(
                "\(liveTaskProcessedCount) files checked",
                "\(liveTaskProcessedCount) bestanden gecontroleerd"
            )
        }

        return localized(
            "\(liveTaskProcessedCount) updates received",
            "\(liveTaskProcessedCount) updates ontvangen"
        )
    }

    var liveTaskSectionTitle: String {
        currentTaskID == .malware
            ? localized("Current scan", "Huidige scan")
            : localized("Recent", "Recent")
    }

    var liveThreatCount: Int {
        liveDetectedThreats.count
    }

    var liveThreatStatusValue: String {
        if liveDetectedThreats.isEmpty {
            return localized("None so far", "Nog niets")
        }

        let count = liveDetectedThreats.count
        return count == 1
            ? localized("1 possible threat", "1 mogelijke dreiging")
            : localized("\(count) possible threats", "\(count) mogelijke dreigingen")
    }

    var liveThreatStatusDetail: String {
        guard let latestThreat = liveDetectedThreats.first else {
            return localized("ClamAV will surface detections here as soon as they appear.", "ClamAV toont hier detecties zodra ze opduiken.")
        }

        return localized(
            "\(latestThreat.signature)\n\(compactHomePaths(in: latestThreat.path))",
            "\(latestThreat.signature)\n\(compactHomePaths(in: latestThreat.path))"
        )
    }

    var hasMalwareThreatsInLatestRun: Bool {
        !(latestMalwareOutcome?.threats.isEmpty ?? true)
    }

    var latestMalwareThreats: [MalwareThreat] {
        latestMalwareOutcome?.threats ?? []
    }

    var malwareThreatCountLabel: String {
        let count = latestMalwareThreats.count
        return count == 1
            ? localized("1 threat needs a decision", "1 dreiging wacht op uw keuze")
            : localized("\(count) threats need a decision", "\(count) dreigingen wachten op uw keuze")
    }

    var latestMalwareTargetSummary: String {
        let targets = latestMalwareOutcome?.targetTitles ?? []
        guard !targets.isEmpty else {
            return localized("Focused scan areas selected in Review.", "Gerichte scangebieden geselecteerd in Bekijken.")
        }
        return targets.joined(separator: " • ")
    }

    var liveTaskProgressSummary: String? {
        guard currentTaskID == .malware, liveTaskExpectedCount > 0 else { return nil }
        let percent = Int((currentTaskProgressFraction * 100).rounded())
        return localized(
            "\(percent)% of the selected malware scan finished",
            "\(percent)% van de geselecteerde malwarescan is voltooid"
        )
    }

    var canApplyMalwareThreatActions: Bool {
        hasMalwareThreatsInLatestRun && hasPendingMalwareThreatActions && !isApplyingMalwareThreatActions
    }

    var activeReviewTask: MaintenanceTaskDefinition? {
        guard let reviewTaskID else { return nil }
        return MaintenanceCatalog.task(for: reviewTaskID)
    }

    var activeReviewComponents: [TaskScanComponent] {
        guard let reviewTaskID else { return [] }
        return reviewComponents(for: reviewTaskID)
    }

    var selectedReviewComponents: [TaskScanComponent] {
        activeReviewComponents.filter { reviewSelections.contains($0.id) }
    }

    var activeReviewConfirmation: TaskConfirmation? {
        guard let task = activeReviewTask else { return nil }
        return resolvedConfirmation(for: task, inputValue: reviewInputText.trimmed.nilIfEmpty)
    }

    var filteredInstalledApplications: [InstalledApplicationRecord] {
        let query = applicationPickerQuery.trimmed.lowercased()
        guard !query.isEmpty else { return installedApplications }

        return installedApplications.filter { app in
            app.name.lowercased().contains(query)
                || app.url.lastPathComponent.lowercased().contains(query)
                || app.bundleIdentifier?.lowercased().contains(query) == true
                || app.displayLocation.lowercased().contains(query)
        }
    }

    var activeSelectedInstalledApplication: InstalledApplicationRecord? {
        guard let task = activeReviewTask else { return nil }
        return selectedInstalledApplication(for: task.id, inputValue: reviewInputText.trimmed.nilIfEmpty)
    }

    var selectedReviewSummary: String {
        if activeReviewComponents.isEmpty {
            if let task = activeReviewTask {
                switch task.id {
                case .uninstall:
                    if let app = activeSelectedInstalledApplication {
                        return localized("Ready to remove \(app.name)", "Klaar om \(app.name) te verwijderen")
                    }
                case .reset:
                    if let app = activeSelectedInstalledApplication {
                        return localized("Ready to reset \(app.name)", "Klaar om \(app.name) te resetten")
                    }
                default:
                    break
                }
            }

            if let task = activeReviewTask, task.prompt != nil {
                let value = reviewInputText.trimmed
                return value.isEmpty
                    ? localized("Enter the requested name to continue", "Vul de gevraagde naam in om door te gaan")
                    : localized("Ready to run for \(value)", "Klaar om uit te voeren voor \(value)")
            }

            return localized("Ready to run", "Klaar om uit te voeren")
        }

        if activeReviewTask?.id == .malware {
            let selectedCount = selectedReviewComponents.count
            return selectedCount == 1
                ? localized("1 scan area selected", "1 scangebied geselecteerd")
                : localized("\(selectedCount) scan areas selected", "\(selectedCount) scangebieden geselecteerd")
        }

        return selectionSummary(for: selectedReviewComponents)
    }

    var canRunActiveReview: Bool {
        guard let task = activeReviewTask else { return false }

        let needsInput = task.prompt != nil
        let hasInput = !reviewInputText.trimmed.isEmpty
        let needsSelection = !activeReviewComponents.isEmpty
        let hasSelection = !selectedReviewComponents.isEmpty

        return (!needsInput || hasInput) && (!needsSelection || hasSelection)
    }

    func state(for taskID: MaintenanceTaskID) -> TaskRunState {
        taskStates[taskID] ?? .idle
    }

    func scanState(for taskID: MaintenanceTaskID) -> TaskScanState {
        scanStates[taskID] ?? .idle
    }

    func scanFinding(for taskID: MaintenanceTaskID) -> TaskScanFinding? {
        guard case let .ready(finding) = scanStates[taskID] else { return nil }
        return finding
    }

    func isTaskEnabled(_ taskID: MaintenanceTaskID) -> Bool {
        enabledTaskIDs.contains(taskID)
    }

    func isTaskReviewable(_ task: MaintenanceTaskDefinition) -> Bool {
        task.prompt != nil || task.confirmation != nil || !reviewComponents(for: task.id).isEmpty
    }

    func actionTitle(for task: MaintenanceTaskDefinition) -> String {
        if case .scanning = scanState(for: task.id) {
            return localized("Checking", "Controleren")
        }

        if isTaskReviewable(task) {
            return localized("Review", "Bekijken")
        }

        if case .inlineReport = task.command {
            return localized("Run Report", "Rapport uitvoeren")
        }

        return localized("Run Task", "Taak uitvoeren")
    }

    func reviewComponents(for taskID: MaintenanceTaskID) -> [TaskScanComponent] {
        scanFinding(for: taskID)?.components ?? []
    }

    func reviewedSelection(for taskID: MaintenanceTaskID) -> Set<String> {
        savedComponentSelections[taskID] ?? defaultSelectionIDs(for: taskID)
    }

    func savedPrompt(for taskID: MaintenanceTaskID) -> String {
        savedPromptValues[taskID] ?? ""
    }

    func latestTaskOutput(for taskID: MaintenanceTaskID) -> String? {
        taskOutputs[taskID]?.trimmed.nilIfEmpty
    }

    func isReviewComponentSelected(_ componentID: String) -> Bool {
        reviewSelections.contains(componentID)
    }

    func setReviewComponent(_ componentID: String, selected: Bool) {
        if selected {
            reviewSelections.insert(componentID)
        } else {
            reviewSelections.remove(componentID)
        }
    }

    func selectAllReviewComponents() {
        reviewSelections = Set(activeReviewComponents.map(\.id))
    }

    func useSuggestedReviewComponents() {
        reviewSelections = Set(activeReviewComponents.filter(\.selectedByDefault).map(\.id))
    }

    func usesInstalledApplicationPicker(for task: MaintenanceTaskDefinition) -> Bool {
        switch task.id {
        case .uninstall, .reset:
            return isLoadingInstalledApplications || !installedApplications.isEmpty
        default:
            return false
        }
    }

    func selectInstalledApplication(_ app: InstalledApplicationRecord, for taskID: MaintenanceTaskID) {
        switch taskID {
        case .uninstall:
            reviewInputText = app.url.path
        case .reset:
            reviewInputText = app.bundleIdentifier ?? ""
        default:
            break
        }
    }

    func revealInstalledApplication(_ app: InstalledApplicationRecord) {
        NSWorkspace.shared.activateFileViewerSelecting([app.url])
    }

    func beginReview(for task: MaintenanceTaskDefinition) {
        guard !isRunning else { return }

        dismissRunReport()
        Task {
            await ensureReviewData(for: task)
            reviewTaskID = task.id
            reviewSelections = reviewedSelection(for: task.id)
            reviewInputText = savedPrompt(for: task.id)
            applicationPickerQuery = ""

            switch task.id {
            case .uninstall, .reset:
                await ensureInstalledApplicationsLoaded()
            default:
                break
            }
        }
    }

    func closeReview(persist: Bool = true) {
        if persist {
            persistCurrentReviewState()
        }
        reviewTaskID = nil
        reviewSelections = []
        reviewInputText = ""
        applicationPickerQuery = ""
    }

    func runReviewTask() {
        guard let task = activeReviewTask, canRunActiveReview, !isRunning else { return }

        persistCurrentReviewState()
        closeReview(persist: false)
        dismissRunReport()

        Task {
            await execute(tasks: [task], runTitle: task.title)
        }
    }

    func selectModule(_ moduleID: MaintenanceModuleID) {
        closeReview()
        closeAbout()
        dismissRunReport()
        #if DEVELOPER_BUILD
        isShowingDeveloperPanel = false
        #endif
        selectedModuleID = moduleID
        Task {
            if moduleID == .applications {
                await ensureInstalledApplicationsLoaded()
            }
            if shouldAutoScanModuleOnSelection(moduleID) {
                await scanCurrentModule()
            }
        }
    }

    func setTaskEnabled(_ taskID: MaintenanceTaskID, enabled: Bool) {
        if enabled {
            enabledTaskIDs.insert(taskID)
        } else {
            enabledTaskIDs.remove(taskID)
        }
    }

    func runSmartCare() {
        guard !isRunning else { return }

        closeReview()
        closeAbout()
        dismissRunReport()
        #if DEVELOPER_BUILD
        isShowingDeveloperPanel = false
        #endif

        selectedModuleID = .smartCare

        Task {
            let module = MaintenanceCatalog.module(for: .smartCare)
            let tasks = MaintenanceCatalog.tasks(for: module.id).filter { enabledTaskIDs.contains($0.id) }
            guard !tasks.isEmpty else {
                appendActivity(title: module.title, detail: localized("No tasks are enabled in this module right now.", "Er zijn op deze pagina nu geen taken ingeschakeld."), isError: true)
                return
            }
            await runModuleFlow(module: module, tasks: tasks)
        }
    }

    func runModule(_ module: MaintenanceModule) {
        guard !isRunning else { return }

        closeReview()
        closeAbout()
        dismissRunReport()
        #if DEVELOPER_BUILD
        isShowingDeveloperPanel = false
        #endif
        selectedModuleID = module.id

        Task {
            let tasks = MaintenanceCatalog.tasks(for: module.id).filter { enabledTaskIDs.contains($0.id) }
            guard !tasks.isEmpty else {
                appendActivity(title: module.title, detail: localized("No tasks are enabled in this module right now.", "Er zijn op deze pagina nu geen taken ingeschakeld."), isError: true)
                return
            }
            await runModuleFlow(module: module, tasks: tasks)
        }
    }

    func runTask(_ task: MaintenanceTaskDefinition) {
        guard !isRunning else { return }

        dismissRunReport()
        if task.prompt != nil || isTaskReviewable(task) {
            beginReview(for: task)
            return
        }

        Task {
            await execute(tasks: [task], runTitle: task.title)
        }
    }

    func openWebsite() {
        open(urlString: "https://cleanmac-assistant.easycompzeeland.nl")
    }

    func chooseFileAccessFolders() {
        let panel = NSOpenPanel()
        panel.title = localized("Choose folders for file scans", "Kies mappen voor bestandsscans")
        panel.message = localized(
            "Pick the folders that Files tools may scan. This avoids repeated macOS prompts for Desktop, Documents, and Downloads.",
            "Kies de mappen die de Bestandstools mogen scannen. Dit voorkomt herhaalde macOS-meldingen voor Bureaublad, Documenten en Downloads."
        )
        panel.prompt = localized("Use folders", "Gebruik mappen")
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.canCreateDirectories = false
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser

        let response = panel.runModal()
        guard response == .OK, !panel.urls.isEmpty else { return }

        ManagedFileAccessStore.save(urls: panel.urls)
        managedFileAccessFolders = ManagedFileAccessStore.storedFolders()

        appendActivity(
            title: localized("File access updated", "Bestandstoegang bijgewerkt"),
            detail: localized(
                "File scans will now use: \(managedFileAccessFolders.map(\.displayPath).joined(separator: ", "))",
                "Bestandsscans gebruiken nu: \(managedFileAccessFolders.map(\.displayPath).joined(separator: ", "))"
            ),
            isError: false
        )

        Task {
            await scanCurrentModule(force: true)
        }
    }

    func clearFileAccessFolders() {
        ManagedFileAccessStore.clear()
        managedFileAccessFolders = []
        appendActivity(
            title: localized("File access cleared", "Bestandstoegang gewist"),
            detail: localized(
                "Files tools will stop scanning Desktop, Documents, or Downloads until you choose folders again.",
                "Bestandstools scannen Bureaublad, Documenten of Downloads niet meer totdat u opnieuw mappen kiest."
            ),
            isError: false
        )

        Task {
            await scanCurrentModule(force: true)
        }
    }

    func openAbout() {
        guard !isRunning else { return }
        closeReview()
        dismissRunReport()
        #if DEVELOPER_BUILD
        isShowingDeveloperPanel = false
        #endif
        isShowingAbout = true
    }

    func closeAbout() {
        isShowingAbout = false
    }

    func dismissRunReport() {
        lastRunReport = nil
        latestMalwareOutcome = nil
        malwareThreatActionSelections = [:]
        malwareThreatResolutions = [:]
    }

    #if DEVELOPER_BUILD
    func toggleDeveloperPanel() {
        guard !isRunning else { return }
        closeReview()
        closeAbout()
        dismissRunReport()
        isShowingDeveloperPanel.toggle()
    }

    func closeDeveloperPanel() {
        isShowingDeveloperPanel = false
    }

    func toggleDeveloperAutoTour() {
        if isPlayingDeveloperTour {
            stopDeveloperAutoTour()
        } else {
            startDeveloperAutoTour()
        }
    }

    func startDeveloperAutoTour() {
        guard !isPlayingDeveloperTour else { return }

        if !isPlaceboModeEnabled {
            isPlaceboModeEnabled = true
        }

        developerTourTask?.cancel()
        isShowingDeveloperPanel = false
        dismissRunReport()
        closeReview(persist: false)
        closeAbout()

        isPlayingDeveloperTour = true
        developerTourStepIndex = 0
        developerTourStepCount = 8
        developerTourTitle = localized("Starting demo", "Demo starten")
        developerTourDetail = localized(
            "Preparing a hands-off preview tour for screen recording.",
            "Bezig met het voorbereiden van een hands-off previewtour voor screen recording."
        )

        developerTourTask = Task { @MainActor in
            await runDeveloperAutoTour()
        }
    }

    func stopDeveloperAutoTour() {
        developerTourTask?.cancel()
        developerTourTask = nil
        finishDeveloperAutoTour(
            title: localized("Demo stopped", "Demo gestopt"),
            detail: localized(
                "The automatic preview tour was stopped. You can reopen Preview Tools at any time.",
                "De automatische previewtour is gestopt. U kunt Preview Tools altijd opnieuw openen."
            )
        )
    }
    #endif

    func openSupport() {
        open(urlString: "https://easycompzeeland.nl/en/services/hulp-op-afstand")
    }

    func openBrew() {
        open(urlString: "https://brew.sh")
    }

    func checkForUpdates() {
        checkForUpdates(trigger: .manual)
    }

    func dismissAvailableUpdateOffer() {
        availableUpdateOffer = nil
    }

    func dismissUpdateInstallState() {
        if case .failed = updateInstallState {
            updateInstallState = .idle
        }
    }

    func installAvailableUpdate() {
        guard let offer = availableUpdateOffer else { return }

        availableUpdateOffer = nil
        Task {
            await install(updateOffer: offer)
        }
    }

    private func checkForUpdates(trigger: UpdateCheckTrigger) {
        if case .checking = updateState {
            return
        }

        #if DEVELOPER_BUILD
        if isPlaceboModeEnabled {
            let currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? AppBuildFlavor.currentVersion
            let previewVersion = incrementPatchVersion(currentVersion)
            let changelog = developerPreviewChangelog()
            updateState = .updateAvailable(version: previewVersion, notes: changelog, downloadURL: nil)
            updateInstallState = .idle
            availableUpdateOffer = AppUpdateOffer(version: previewVersion, notes: changelog, downloadURL: nil)
            appendActivity(
                title: localized("Update available", "Update beschikbaar"),
                detail: localized("Version \(previewVersion) is ready.\n\nChangelog:\n\(changelog)", "Versie \(previewVersion) is klaar.\n\nChangelog:\n\(changelog)"),
                isError: false
            )
            return
        }
        #endif

        updateState = .checking
        Task {
            let currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? AppBuildFlavor.currentVersion
            let result = await updateChecker.check(currentVersion: currentVersion)
            updateState = result

            switch result {
            case let .updateAvailable(version, notes, downloadURL):
                updateInstallState = .idle
                availableUpdateOffer = AppUpdateOffer(version: version, notes: notes, downloadURL: downloadURL)
                appendActivity(
                    title: localized("Update available", "Update beschikbaar"),
                    detail: localized("Version \(version) is ready.\n\nChangelog:\n\(notes)", "Versie \(version) is klaar.\n\nChangelog:\n\(notes)"),
                    isError: false
                )
            case let .upToDate(currentVersion, latestVersion):
                updateInstallState = .idle
                availableUpdateOffer = nil
                if trigger == .manual {
                    let detail: String
                    if currentVersion == latestVersion {
                        detail = localized(
                            "The EasyComp download folder currently lists version \(latestVersion). This Mac is already up to date.",
                            "In de EasyComp-downloadmap staat nu versie \(latestVersion). Deze Mac is al bijgewerkt."
                        )
                    } else {
                        detail = localized(
                            "The EasyComp download folder currently lists version \(latestVersion), while this Mac is already on version \(currentVersion).",
                            "In de EasyComp-downloadmap staat nu versie \(latestVersion), terwijl deze Mac al op versie \(currentVersion) draait."
                        )
                    }
                    appendActivity(title: localized("Updates", "Updates"), detail: detail, isError: false)
                }
            case let .failed(message):
                if trigger == .manual {
                    appendActivity(title: localized("Update check", "Updatecontrole"), detail: message, isError: true)
                }
            case .idle, .checking:
                break
            }
        }
    }

    private func performAutomaticUpdateCheckIfNeeded() {
        #if DEVELOPER_BUILD
        if isPlaceboModeEnabled {
            return
        }
        #endif
        checkForUpdates(trigger: .automatic)
    }

    private func install(updateOffer: AppUpdateOffer) async {
        guard let downloadURL = updateOffer.downloadURL else {
            let message = localized(
                "This update does not provide a direct download link yet.",
                "Deze update heeft nog geen directe downloadlink."
            )
            updateInstallState = .failed(version: updateOffer.version, message: message)
            appendActivity(title: localized("Update install", "Update-installatie"), detail: message, isError: true)
            return
        }

        updateInstallState = .downloading(version: updateOffer.version)

        do {
            let currentAppURL = Bundle.main.bundleURL
            let preparedInstallation = try await selfUpdater.prepareInstallation(
                from: downloadURL,
                version: updateOffer.version,
                currentAppURL: currentAppURL,
                expectedAppName: AppBuildFlavor.appName
            )

            updateInstallState = .preparing(version: updateOffer.version)
            try? await Task.sleep(for: .milliseconds(350))
            updateInstallState = .installing(version: updateOffer.version)
            appendActivity(
                title: localized("Installing update", "Update installeren"),
                detail: localized(
                    "Version \(updateOffer.version) is being installed. The app will relaunch automatically.",
                    "Versie \(updateOffer.version) wordt geïnstalleerd. De app start daarna automatisch opnieuw."
                ),
                isError: false
            )

            try preparedInstallation.launch()
            try? await Task.sleep(for: .milliseconds(850))
            NSApplication.shared.terminate(nil)
        } catch {
            let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            updateInstallState = .failed(version: updateOffer.version, message: message)
            appendActivity(title: localized("Update install", "Update-installatie"), detail: message, isError: true)
        }
    }

    func openUpdateDownload() {
        guard case let .updateAvailable(_, _, downloadURL?) = updateState else { return }
        NSWorkspace.shared.open(downloadURL)
    }

    func scanCurrentModule(force: Bool = false) async {
        let tasks = selectedModuleTasks
        guard !tasks.isEmpty else { return }

        if selectedModuleID == .files && !force {
            return
        }

        isScanningModule = true
        for task in tasks {
            scanStates[task.id] = .scanning
        }

        for task in tasks {
            #if DEVELOPER_BUILD
            let result: TaskScanState
            if isPlaceboModeEnabled {
                result = placeboScanState(for: task)
            } else {
                result = await scanner.scan(taskID: task.id)
            }
            #else
            let result = await scanner.scan(taskID: task.id)
            #endif
            scanStates[task.id] = result
        }

        isScanningModule = false
    }

    private func execute(tasks: [MaintenanceTaskDefinition], runTitle: String) async {
        #if DEVELOPER_BUILD
        if isPlaceboModeEnabled {
            await executePlacebo(tasks: tasks, runTitle: runTitle)
            return
        }
        #endif

        isRunning = true
        currentRunTitle = runTitle
        currentTaskID = nil
        completedTaskCount = 0
        totalTaskCount = tasks.count
        lastRunReport = nil
        clearLiveTaskProgress()
        beginRunTiming(tasks: tasks)
        latestMalwareOutcome = nil
        malwareThreatActionSelections = [:]
        malwareThreatResolutions = [:]

        for task in tasks {
            taskStates[task.id] = .queued
            taskOutputs.removeValue(forKey: task.id)
        }

        appendActivity(title: runTitle, detail: localized("Queued \(tasks.count) task(s).", "\(tasks.count) taak/taken in de wachtrij gezet."), isError: false)

        var completedCount = 0
        var skippedCount = 0
        var failureCount = 0

        let shouldRefreshInstalledApplications = tasks.contains { $0.id == .uninstall }

        for task in tasks {
            currentTaskID = task.id
            currentTaskStartedAt = Date()
            taskStates[task.id] = .running
            resetLiveTaskProgress(for: task)
            let currentStep = completedCount + skippedCount + failureCount + 1
            appendActivity(title: task.title, detail: localized("Working on step \(currentStep) of \(tasks.count).", "Bezig met stap \(currentStep) van \(tasks.count)."), isError: false)

            switch prepareExecutionContext(for: task) {
            case .skip:
                taskStates[task.id] = .skipped
                taskOutputs.removeValue(forKey: task.id)
                skippedCount += 1
                appendActivity(title: task.title, detail: localized("Skipped for now.", "Voor nu overgeslagen."), isError: false)

            case let .ready(request):
                let result = await executor.run(task: task, request: request)

                let visibleMalwareThreatCount: Int
                if task.id == .malware {
                    prepareLatestMalwareOutcome(result.malwareOutcome)
                    visibleMalwareThreatCount = latestMalwareThreats.count
                } else {
                    visibleMalwareThreatCount = 0
                }

                let trimmedOutput = result.output.trimmed
                if trimmedOutput.isEmpty {
                    taskOutputs.removeValue(forKey: task.id)
                } else {
                    taskOutputs[task.id] = trimmedOutput
                }

                let treatedAsIssue = task.id == .malware && visibleMalwareThreatCount > 0
                if treatedAsIssue {
                    let summary = visibleMalwareThreatCount == 1
                        ? localized("1 potential threat needs your review.", "1 mogelijke dreiging wacht op uw controle.")
                        : localized("\(visibleMalwareThreatCount) potential threats need your review.", "\(visibleMalwareThreatCount) mogelijke dreigingen wachten op uw controle.")
                    taskStates[task.id] = .failed(summary: summary)
                    failureCount += 1
                } else if task.id == .malware,
                          let rawThreatCount = result.malwareOutcome?.threats.count,
                          rawThreatCount > 0 {
                    taskStates[task.id] = .succeeded(summary: localized("Only previously ignored detections were found.", "Er zijn alleen eerder genegeerde detecties gevonden."))
                    completedCount += 1
                } else if result.success {
                    taskStates[task.id] = .succeeded(summary: result.summary)
                    completedCount += 1
                } else {
                    taskStates[task.id] = .failed(summary: result.summary)
                    failureCount += 1
                }

                let detail = result.output.isEmpty ? result.summary : result.summary + "\n\n" + result.output
                appendActivity(title: task.title, detail: detail, isError: treatedAsIssue || !result.success)
                playTaskCompletionSound(success: !(treatedAsIssue || !result.success))

                let refreshedScan = await scanner.scan(taskID: task.id)
                scanStates[task.id] = refreshedScan
            }

            completedTaskCount = completedCount + skippedCount + failureCount
        }

        if shouldRefreshInstalledApplications {
            await ensureInstalledApplicationsLoaded(force: true)
        }

        currentTaskID = nil
        currentTaskStartedAt = nil
        isRunning = false
        clearLiveTaskProgress()
        lastRunSummary = localized("\(runTitle.appLocalized): \(completedCount) completed, \(skippedCount) skipped, \(failureCount) with issues.", "\(runTitle.appLocalized): \(completedCount) voltooid, \(skippedCount) overgeslagen, \(failureCount) met problemen.")
        lastRunReport = buildRunReport(
            title: runTitle,
            summary: lastRunSummary,
            completedCount: completedCount,
            skippedCount: skippedCount,
            failureCount: failureCount,
            tasks: tasks
        )
        appendActivity(title: localized("Run finished", "Run voltooid"), detail: lastRunSummary, isError: failureCount > 0)
        playRunCompletionSound(hasIssues: failureCount > 0)

        currentRunTitle = ""
        completedTaskCount = 0
        totalTaskCount = 0
        clearRunTiming()

        await scanCurrentModule(force: true)
    }

    private func appendActivity(title: String, detail: String, isError: Bool) {
        activityEntries.insert(
            ActivityEntry(timestamp: Date(), title: title, detail: detail, isError: isError),
            at: 0
        )
    }

    private func consumeMaintenanceProgress(taskIDRaw: String, line: String) {
        guard let taskID = MaintenanceTaskID(rawValue: taskIDRaw),
              taskID == currentTaskID
        else {
            return
        }

        updateLiveTaskProgress(taskID: taskID, rawLine: line)
    }

    private func resetLiveTaskProgress(for task: MaintenanceTaskDefinition) {
        liveTaskPhase = initialLivePhase(for: task.id)
        liveTaskCurrentItem = ""
        liveTaskProcessedCount = 0
        liveTaskExpectedCount = 0
        liveTaskRecentLines = []
        liveDetectedThreats = []
    }

    private func clearLiveTaskProgress() {
        liveTaskPhase = ""
        liveTaskCurrentItem = ""
        liveTaskProcessedCount = 0
        liveTaskExpectedCount = 0
        liveTaskRecentLines = []
        liveDetectedThreats = []
    }

    private func initialLivePhase(for taskID: MaintenanceTaskID) -> String {
        switch taskID {
        case .malware:
            return localized(
                "Preparing ClamAV signatures and focused scan targets.",
                "ClamAV-signatures en gerichte scanlocaties worden voorbereid."
            )
        default:
            return ""
        }
    }

    private func updateLiveTaskProgress(taskID: MaintenanceTaskID, rawLine: String) {
        let trimmedRawLine = rawLine.trimmed
        guard !trimmedRawLine.isEmpty else { return }

        switch taskID {
        case .malware:
            updateMalwareLiveProgress(with: trimmedRawLine)
        default:
            let compactedLine = compactHomePaths(in: trimmedRawLine).trimmed
            liveTaskPhase = compactedLine
            if !liveTaskRecentLines.contains(compactedLine) {
                liveTaskRecentLines = Array(([compactedLine] + liveTaskRecentLines).prefix(4))
            }
        }
    }

    private func updateMalwareLiveProgress(with line: String) {
        if line == "__ECZ_SCAN_PREPARING_SCOPE__" {
            liveTaskPhase = localized(
                "Counting selected files so the scan progress can stay accurate.",
                "Geselecteerde bestanden worden geteld zodat de scanvoortgang nauwkeurig blijft."
            )
            return
        }

        if let estimatedTotal = trailingInteger(in: line, afterPrefix: "__ECZ_SCAN_TOTAL_FILES__:") {
            liveTaskExpectedCount = max(estimatedTotal, liveTaskProcessedCount)
            liveTaskPhase = localized(
                "Preparing to scan about \(liveTaskExpectedCount) files across the selected areas.",
                "Bereidt een scan voor van ongeveer \(liveTaskExpectedCount) bestanden in de geselecteerde gebieden."
            )
            return
        }

        if let threat = parseLiveMalwareThreat(from: line),
           !IgnoredMalwareThreatStore.contains(threat.id),
           !liveDetectedThreats.contains(where: { $0.id == threat.id }) {
            liveDetectedThreats.insert(threat, at: 0)
        }

        let displayLine = compactHomePaths(in: line)

        if line.localizedCaseInsensitiveContains("scan summary") {
            liveTaskPhase = localized("Wrapping up scan summary.", "Scansamenvatting wordt afgerond.")
        } else if line.localizedCaseInsensitiveContains("download") || line.localizedCaseInsensitiveContains("database") || line.localizedCaseInsensitiveContains("bytecode") {
            liveTaskPhase = localized("Refreshing malware signatures.", "Malwaresignatures worden vernieuwd.")
        } else if let scannedFiles = trailingInteger(in: line, afterPrefix: "Scanned files:") {
            liveTaskProcessedCount = max(liveTaskProcessedCount, scannedFiles)
            liveTaskExpectedCount = max(liveTaskExpectedCount, scannedFiles)
            liveTaskPhase = localized("Summarizing checked files.", "Gecontroleerde bestanden worden samengevat.")
        } else if let currentItem = clamPath(from: line) {
            liveTaskProcessedCount += 1
            liveTaskCurrentItem = compactHomePaths(in: currentItem)
            liveTaskPhase = line.localizedCaseInsensitiveContains("FOUND")
                ? localized("Potential threat detected. Reviewing result.", "Mogelijke dreiging gevonden. Resultaat wordt nagekeken.")
                : localized("Scanning files and startup locations.", "Bestanden en opstartlocaties worden gescand.")
        }

        let shouldStoreLine =
            line.localizedCaseInsensitiveContains("FOUND") ||
            line.localizedCaseInsensitiveContains("ERROR") ||
            line.localizedCaseInsensitiveContains("database") ||
            line.localizedCaseInsensitiveContains("download") ||
            line.localizedCaseInsensitiveContains("scan summary") ||
            clamPath(from: line) != nil

        if shouldStoreLine, !liveTaskRecentLines.contains(displayLine) {
            liveTaskRecentLines = Array(([displayLine] + liveTaskRecentLines).prefix(4))
        }
    }

    private func parseLiveMalwareThreat(from line: String) -> MalwareThreat? {
        guard line.localizedCaseInsensitiveContains(" FOUND"),
              let separator = line.firstIndex(of: ":")
        else {
            return nil
        }

        let path = String(line[..<separator]).trimmed
        let signature = String(line[line.index(after: separator)...])
            .replacingOccurrences(of: "FOUND", with: "", options: [.caseInsensitive])
            .trimmed

        guard !path.isEmpty, !signature.isEmpty else { return nil }

        return MalwareThreat(id: "\(path)|\(signature)", path: path, signature: signature)
    }

    private func prepareLatestMalwareOutcome(_ outcome: MalwareScanOutcome?) {
        let mergedThreats = uniqueMalwareThreats((outcome?.threats ?? []) + liveDetectedThreats)
        let visibleThreats = mergedThreats.filter { !IgnoredMalwareThreatStore.contains($0.id) }
        if let outcome {
            latestMalwareOutcome = MalwareScanOutcome(
                threats: visibleThreats,
                targetTitles: outcome.targetTitles,
                checkedFileCount: outcome.checkedFileCount
            )
        } else if !visibleThreats.isEmpty {
            latestMalwareOutcome = MalwareScanOutcome(
                threats: visibleThreats,
                targetTitles: [],
                checkedFileCount: nil
            )
        } else {
            latestMalwareOutcome = nil
        }
        malwareThreatActionSelections = [:]
        malwareThreatResolutions = [:]

        for threat in latestMalwareThreats {
            malwareThreatActionSelections[threat.id] = .quarantine
            malwareThreatResolutions[threat.id] = .pending
        }
    }

    private func uniqueMalwareThreats(_ threats: [MalwareThreat]) -> [MalwareThreat] {
        var seen = Set<String>()
        var ordered: [MalwareThreat] = []

        for threat in threats where seen.insert(threat.id).inserted {
            ordered.append(threat)
        }

        return ordered
    }

    func malwareThreatAction(for threat: MalwareThreat) -> MalwareThreatActionChoice {
        malwareThreatActionSelections[threat.id] ?? .quarantine
    }

    func setMalwareThreatAction(_ action: MalwareThreatActionChoice, for threatID: String) {
        malwareThreatActionSelections[threatID] = action
        if malwareThreatResolutions[threatID] != .pending {
            malwareThreatResolutions[threatID] = .pending
        }
    }

    func malwareThreatResolution(for threatID: String) -> MalwareThreatResolution {
        malwareThreatResolutions[threatID] ?? .pending
    }

    func applyMalwareThreatActions() {
        let threats = latestMalwareThreats
        guard !threats.isEmpty, !isApplyingMalwareThreatActions else { return }

        isApplyingMalwareThreatActions = true

        Task {
            let results = await executor.resolveMalwareThreats(threats, actions: malwareThreatActionSelections)
            malwareThreatResolutions = results
            isApplyingMalwareThreatActions = false

            let ignored = results.values.filter { if case .ignored = $0 { return true } else { return false } }.count
            let quarantined = results.values.filter { if case .quarantined = $0 { return true } else { return false } }.count
            let deleted = results.values.filter { if case .deleted = $0 { return true } else { return false } }.count
            let failures = results.values.filter { if case .failed = $0 { return true } else { return false } }.count

            let summary = localized(
                "Ignored: \(ignored) • Quarantined: \(quarantined) • Deleted: \(deleted) • Issues: \(failures)",
                "Genegeerd: \(ignored) • In quarantaine: \(quarantined) • Verwijderd: \(deleted) • Problemen: \(failures)"
            )

            let ignoredThreatIDs = results
                .filter { entry in
                    if case .ignored = entry.value {
                        return true
                    }
                    return false
                }
                .map(\.key)
            let nonIgnoredThreatIDs = results
                .filter { entry in
                    if case .ignored = entry.value {
                        return false
                    }
                    return true
                }
                .map(\.key)
            IgnoredMalwareThreatStore.insert(ignoredThreatIDs)
            IgnoredMalwareThreatStore.remove(nonIgnoredThreatIDs)

            let existingOutput = taskOutputs[.malware]?.trimmed ?? ""
            let actionOutput = localized(
                "Threat action summary\n\(summary)",
                "Samenvatting dreigingsacties\n\(summary)"
            )
            taskOutputs[.malware] = existingOutput.isEmpty
                ? actionOutput
                : existingOutput + "\n\n" + actionOutput

            taskStates[.malware] = failures > 0
                ? .failed(summary: localized("Some threat actions still need attention.", "Sommige dreigingsacties vragen nog aandacht."))
                : .succeeded(summary: localized("Threat review completed.", "Dreigingscontrole voltooid."))
            refreshLastRunReport()

            appendActivity(
                title: localized("Threat actions applied", "Dreigingsacties toegepast"),
                detail: summary,
                isError: failures > 0
            )
        }
    }

    private var hasPendingMalwareThreatActions: Bool {
        latestMalwareThreats.contains { malwareThreatResolution(for: $0.id) == .pending }
    }

    private func shouldAutoScanModuleOnSelection(_ moduleID: MaintenanceModuleID) -> Bool {
        moduleID != .files
    }

    private func runModuleFlow(module: MaintenanceModule, tasks: [MaintenanceTaskDefinition]) async {
        await scanCurrentModule(force: true)

        if let blockingTask = firstBlockingReviewTask(in: tasks) {
            appendActivity(
                title: module.title,
                detail: localized(
                    "\(blockingTask.title.appLocalized) still needs a quick Review before this page can continue. Review it once, then run the page again.",
                    "\(blockingTask.title.appLocalized) heeft nog een korte controle in Bekijken nodig voordat deze pagina verder kan. Bekijk dit onderdeel eenmalig en voer de pagina daarna opnieuw uit."
                ),
                isError: false
            )
            await openReviewForModuleRun(blockingTask)
            return
        }

        await execute(tasks: tasks, runTitle: module.title)
    }

    private func compactHomePaths(in line: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return line.replacingOccurrences(of: home, with: "~")
    }

    private func clamPath(from line: String) -> String? {
        guard line.hasPrefix("/") || line.hasPrefix("~"),
              let separator = line.firstIndex(of: ":")
        else {
            return nil
        }

        let path = String(line[..<separator]).trimmed
        return path.isEmpty ? nil : path
    }

    private func trailingInteger(in line: String, afterPrefix prefix: String) -> Int? {
        guard line.hasPrefix(prefix) else { return nil }
        let remainder = line.dropFirst(prefix.count).trimmingCharacters(in: .whitespacesAndNewlines)
        return Int(remainder.components(separatedBy: CharacterSet.decimalDigits.inverted).joined())
    }

    private func open(urlString: String) {
        guard let url = URL(string: urlString) else { return }
        NSWorkspace.shared.open(url)
    }

    private func ensureReviewData(for task: MaintenanceTaskDefinition) async {
        guard task.prompt == nil else { return }

        switch scanState(for: task.id) {
        case .idle:
            scanStates[task.id] = .scanning
            let result = await scanner.scan(taskID: task.id)
            scanStates[task.id] = result
        case .scanning, .ready, .unavailable:
            break
        }
    }

    private func persistCurrentReviewState() {
        guard let reviewTaskID else { return }

        savedComponentSelections[reviewTaskID] = reviewSelections
        if MaintenanceCatalog.task(for: reviewTaskID).confirmation != nil {
            reviewedConfirmationTasks.insert(reviewTaskID)
        }

        let trimmedInput = reviewInputText.trimmed
        if trimmedInput.isEmpty {
            savedPromptValues.removeValue(forKey: reviewTaskID)
        } else {
            savedPromptValues[reviewTaskID] = trimmedInput
        }
    }

    private func prepareExecutionContext(for task: MaintenanceTaskDefinition) -> PreparedExecutionContext {
        let inputValue = savedPrompt(for: task.id).trimmed.nilIfEmpty

        if task.prompt != nil && inputValue == nil {
            appendActivity(
                title: task.title,
                detail: localized("Open Review first and fill in the requested name before running this item.", "Open eerst Bekijken en vul de gevraagde naam in voordat u dit onderdeel uitvoert."),
                isError: true
            )
            return .skip
        }

        if task.confirmation != nil && !reviewedConfirmationTasks.contains(task.id) {
            appendActivity(
                title: task.title,
                detail: localized("Open Review first so you can confirm this action inside the app.", "Open eerst Bekijken zodat u deze actie binnen de app kunt bevestigen."),
                isError: true
            )
            return .skip
        }

        let selectedComponents = selectedComponentsForExecution(for: task)
        if let finding = scanFinding(for: task.id), !finding.components.isEmpty, selectedComponents.isEmpty {
            appendActivity(
                title: task.title,
                detail: localized("Nothing is selected yet. Open Review and choose the exact parts you want to clean.", "Er is nog niets geselecteerd. Open Bekijken en kies precies welke onderdelen u wilt opschonen."),
                isError: true
            )
            return .skip
        }

        let actionableComponents = selectedComponents.filter { $0.cleanupAction != nil }
        let request = TaskExecutionRequest(
            input: inputValue,
            selectedComponents: actionableComponents,
            selectedReviewComponents: selectedComponents
        )
        return .ready(request: request)
    }

    private func selectedComponentsForExecution(for task: MaintenanceTaskDefinition) -> [TaskScanComponent] {
        let components = reviewComponents(for: task.id)
        guard !components.isEmpty else { return [] }

        let selectedIDs = savedComponentSelections[task.id] ?? defaultSelectionIDs(for: task.id)
        return components.filter { selectedIDs.contains($0.id) }
    }

    private func defaultSelectionIDs(for taskID: MaintenanceTaskID) -> Set<String> {
        Set(reviewComponents(for: taskID).filter(\.selectedByDefault).map(\.id))
    }

    private func selectionSummary(for components: [TaskScanComponent]) -> String {
        let selectedCount = components.count
        let totalBytes = components.reduce(Int64(0)) { $0 + ($1.reclaimableBytes ?? 0) }
        let totalItems = components.reduce(0) { $0 + ($1.itemCount ?? 0) }

        var parts: [String] = []
        parts.append(localized("\(selectedCount) part(s) selected", "\(selectedCount) onderdeel/onderdelen geselecteerd"))

        if totalBytes > 0 {
            parts.append(localized("about \(byteCountString(totalBytes))", "ongeveer \(byteCountString(totalBytes))"))
        }

        if totalItems > 0 {
            parts.append(localized("\(totalItems) item(s)", "\(totalItems) item(s)"))
        }

        return parts.joined(separator: " • ")
    }

    private func byteCountString(_ byteCount: Int64) -> String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useKB, .useMB, .useGB, .useTB]
        formatter.countStyle = .file
        formatter.isAdaptive = true
        return formatter.string(fromByteCount: byteCount)
    }

    private func resolvedConfirmation(for task: MaintenanceTaskDefinition, inputValue: String?) -> TaskConfirmation? {
        switch task.id {
        case .uninstall:
            guard let inputValue else { return task.confirmation }
            let app = selectedInstalledApplication(for: task.id, inputValue: inputValue)
            let displayName = app?.name ?? inputValue
            return TaskConfirmation(
                title: localized("Uninstall \(displayName)?", "\(displayName) verwijderen?"),
                message: localized(
                    "\(displayName) and common leftovers will be removed from this Mac.",
                    "\(displayName) en veelvoorkomende restbestanden worden van deze Mac verwijderd."
                ),
                confirmTitle: localized("Remove App", "App verwijderen"),
                style: .critical
            )

        case .reset:
            guard let inputValue else { return task.confirmation }
            let app = selectedInstalledApplication(for: task.id, inputValue: inputValue)
            let displayName = app?.name ?? inputValue
            let bundleIdentifier = app?.bundleIdentifier ?? inputValue
            return TaskConfirmation(
                title: localized("Reset preferences for \(displayName)?", "Voorkeuren voor \(displayName) resetten?"),
                message: localized("The saved defaults for \(bundleIdentifier) will be deleted.", "De opgeslagen voorkeuren voor \(bundleIdentifier) worden verwijderd."),
                confirmTitle: localized("Reset Preferences", "Voorkeuren resetten"),
                style: .warning
            )

        default:
            return task.confirmation
        }
    }

    private func firstBlockingReviewTask(in tasks: [MaintenanceTaskDefinition]) -> MaintenanceTaskDefinition? {
        for task in tasks {
            let savedInput = savedPrompt(for: task.id).trimmed.nilIfEmpty
            let needsPromptInput = task.prompt != nil && savedInput == nil
            let needsConfirmation = resolvedConfirmation(for: task, inputValue: savedInput) != nil
                && !reviewedConfirmationTasks.contains(task.id)
            let hasReviewComponents = !reviewComponents(for: task.id).isEmpty
            let needsSelection = hasReviewComponents && selectedComponentsForExecution(for: task).isEmpty

            if needsPromptInput || needsConfirmation || needsSelection {
                return task
            }
        }

        return nil
    }

    private func openReviewForModuleRun(_ task: MaintenanceTaskDefinition) async {
        reviewTaskID = task.id
        reviewSelections = reviewedSelection(for: task.id)
        reviewInputText = savedPrompt(for: task.id)
        applicationPickerQuery = ""

        switch task.id {
        case .uninstall, .reset:
            await ensureInstalledApplicationsLoaded()
        default:
            break
        }
    }

    private func refreshLastRunReport() {
        guard let existingReport = lastRunReport else { return }

        let taskDefinitions = existingReport.tasks.map { MaintenanceCatalog.task(for: $0.id) }
        let completedCount = taskDefinitions.reduce(into: 0) { count, task in
            if case .succeeded = taskStates[task.id] ?? .idle {
                count += 1
            }
        }
        let skippedCount = taskDefinitions.reduce(into: 0) { count, task in
            if case .skipped = taskStates[task.id] ?? .idle {
                count += 1
            }
        }
        let failureCount = taskDefinitions.reduce(into: 0) { count, task in
            if case .failed = taskStates[task.id] ?? .idle {
                count += 1
            }
        }

        let summary = localized(
            "\(existingReport.title.appLocalized): \(completedCount) completed, \(skippedCount) skipped, \(failureCount) with issues.",
            "\(existingReport.title.appLocalized): \(completedCount) voltooid, \(skippedCount) overgeslagen, \(failureCount) met problemen."
        )
        lastRunSummary = summary
        lastRunReport = buildRunReport(
            title: existingReport.title,
            summary: summary,
            completedCount: completedCount,
            skippedCount: skippedCount,
            failureCount: failureCount,
            tasks: taskDefinitions
        )
    }

    private func buildRunReport(
        title: String,
        summary: String,
        completedCount: Int,
        skippedCount: Int,
        failureCount: Int,
        tasks: [MaintenanceTaskDefinition]
    ) -> RunCompletionReport {
        let items = tasks.map { task in
            let state = taskStates[task.id] ?? .idle
            return RunTaskReport(
                id: task.id,
                title: task.title.appLocalized,
                state: state,
                summary: state.resultSummary ?? task.subtitle.appLocalized,
                output: latestTaskOutput(for: task.id)
            )
        }

        return RunCompletionReport(
            title: title.appLocalized,
            summary: summary,
            completedCount: completedCount,
            skippedCount: skippedCount,
            failureCount: failureCount,
            timestamp: Date(),
            tasks: items
        )
    }

    private func playTaskCompletionSound(success: Bool) {
        playSound(named: success ? "Glass" : "Basso")
    }

    private func playRunCompletionSound(hasIssues: Bool) {
        playSound(named: hasIssues ? "Basso" : "Hero")
    }

    private func playSound(named name: String) {
        NSSound(named: NSSound.Name(name))?.play()
    }

    private func beginRunTiming(tasks: [MaintenanceTaskDefinition]) {
        activeRunTasks = tasks
        runStartedAt = Date()
        currentTaskStartedAt = nil
    }

    private func clearRunTiming() {
        activeRunTasks = []
        runStartedAt = nil
        currentTaskStartedAt = nil
    }

    private func currentTaskDefinition() -> MaintenanceTaskDefinition? {
        guard let currentTaskID else { return nil }
        return activeRunTasks.first(where: { $0.id == currentTaskID }) ?? MaintenanceCatalog.task(for: currentTaskID)
    }

    private func runElapsedSeconds(at now: Date) -> TimeInterval? {
        guard isRunning, let runStartedAt else { return nil }
        return max(0, now.timeIntervalSince(runStartedAt))
    }

    private func currentTaskElapsedSeconds(at now: Date) -> TimeInterval? {
        guard isRunning, currentTaskID != nil, let currentTaskStartedAt else { return nil }
        return max(0, now.timeIntervalSince(currentTaskStartedAt))
    }

    private func runRemainingSeconds(at now: Date) -> TimeInterval? {
        guard isRunning, !activeRunTasks.isEmpty else { return nil }

        if let currentTaskID,
           let currentIndex = activeRunTasks.firstIndex(where: { $0.id == currentTaskID }) {
            let currentTask = activeRunTasks[currentIndex]
            var remaining = currentTaskRemainingSeconds(at: now) ?? refinedEstimatedDuration(for: currentTask)

            if currentIndex + 1 < activeRunTasks.count {
                remaining += activeRunTasks[(currentIndex + 1)...].reduce(0) { partial, task in
                    partial + refinedEstimatedDuration(for: task)
                }
            }

            return max(0, remaining)
        }

        let remainingTasks = activeRunTasks.dropFirst(min(completedTaskCount, activeRunTasks.count))
        let remaining = remainingTasks.reduce(0) { partial, task in
            partial + refinedEstimatedDuration(for: task)
        }
        return remaining > 0 ? remaining : nil
    }

    private func currentTaskRemainingSeconds(at now: Date) -> TimeInterval? {
        guard isRunning,
              let task = currentTaskDefinition(),
              let elapsed = currentTaskElapsedSeconds(at: now)
        else {
            return nil
        }

        let expected = adjustedExpectedDuration(for: task, elapsed: elapsed)
        return max(0, expected - elapsed)
    }

    private func refinedEstimatedDuration(for task: MaintenanceTaskDefinition) -> TimeInterval {
        var duration = task.estimatedDuration

        switch task.id {
        case .malware:
            let selectedAreas = max(1, selectedComponentsForExecution(for: task).count)
            duration = max(180, Double(selectedAreas + 1) * 120)
        case .largeOldFiles, .duplicates, .installerFiles, .downloadsReview, .cloudAudit:
            let folderFactor = max(1, min(managedFileAccessFolders.count, 4))
            duration *= Double(folderFactor)
        default:
            break
        }

        return duration
    }

    private func adjustedExpectedDuration(for task: MaintenanceTaskDefinition, elapsed: TimeInterval) -> TimeInterval {
        if task.id == .malware,
           liveTaskExpectedCount > 0,
           liveTaskProcessedCount > 0 {
            let fraction = min(max(Double(liveTaskProcessedCount) / Double(liveTaskExpectedCount), 0.01), 0.99)
            let projectedTotal = elapsed / fraction
            return max(refinedEstimatedDuration(for: task), projectedTotal)
        }

        let base = refinedEstimatedDuration(for: task)
        guard elapsed > 0 else { return base }

        let adaptiveMultiplier: Double
        switch task.impact {
        case .light:
            adaptiveMultiplier = 1.12
        case .medium:
            adaptiveMultiplier = 1.16
        case .high:
            adaptiveMultiplier = 1.2
        case .longRunning:
            adaptiveMultiplier = 1.24
        }

        if elapsed <= base * 0.82 {
            return base
        }

        return max(base, elapsed * adaptiveMultiplier)
    }

    private func formattedDuration(_ duration: TimeInterval) -> String {
        let totalSeconds = max(Int(duration.rounded()), 0)
        let hours = totalSeconds / 3600
        let minutes = (totalSeconds % 3600) / 60
        let seconds = totalSeconds % 60

        if hours > 0 {
            if minutes == 0 {
                return localized("\(hours)h", "\(hours)u")
            }
            return localized("\(hours)h \(minutes)m", "\(hours)u \(minutes)m")
        }

        if minutes > 0 {
            if minutes >= 4 || seconds == 0 {
                return "\(minutes)m"
            }
            return "\(minutes)m \(seconds)s"
        }

        return "\(seconds)s"
    }

    private func formattedClock(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale.autoupdatingCurrent
        formatter.timeStyle = .short
        formatter.dateStyle = .none
        return formatter.string(from: date)
    }

    private var currentTaskProgressFraction: Double {
        guard isRunning, let currentTaskID else { return 0 }

        if currentTaskID == .malware, liveTaskExpectedCount > 0 {
            return min(max(Double(liveTaskProcessedCount) / Double(liveTaskExpectedCount), 0), 0.99)
        }

        guard currentTaskStartedAt != nil else { return 0 }
        let task = currentTaskDefinition() ?? MaintenanceCatalog.task(for: currentTaskID)
        let elapsed = currentTaskElapsedSeconds(at: Date()) ?? 0
        let expected = adjustedExpectedDuration(for: task, elapsed: elapsed)
        guard expected > 0 else { return 0 }
        return min(max(elapsed / expected, 0), 0.92)
    }

    private func ensureInstalledApplicationsLoaded(force: Bool = false) async {
        if isLoadingInstalledApplications {
            return
        }

        if !force && !installedApplications.isEmpty {
            return
        }

        isLoadingInstalledApplications = true
        installedApplications = await discoverInstalledApplications()
        isLoadingInstalledApplications = false
    }

    private func discoverInstalledApplications() async -> [InstalledApplicationRecord] {
        let fileManager = FileManager.default
        let roots = [
            URL(fileURLWithPath: "/Applications", isDirectory: true),
            fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Applications", isDirectory: true)
        ]

        var records: [InstalledApplicationRecord] = []
        var seenPaths = Set<String>()

        for root in roots where fileManager.fileExists(atPath: root.path) {
            let contents = (try? fileManager.contentsOfDirectory(
                at: root,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            )) ?? []

            for appURL in contents where appURL.pathExtension == "app" {
                if Task.isCancelled {
                    return records
                }

                let resolvedPath = appURL.standardizedFileURL.path
                guard seenPaths.insert(resolvedPath).inserted else { continue }

                let bundle = Bundle(url: appURL)
                let name = (bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
                    ?? (bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String)
                    ?? appURL.deletingPathExtension().lastPathComponent

                let record = InstalledApplicationRecord(
                    id: resolvedPath,
                    name: name,
                    url: appURL,
                    bundleIdentifier: bundle?.bundleIdentifier,
                    version: bundle?.infoDictionary?["CFBundleShortVersionString"] as? String,
                    icon: NSWorkspace.shared.icon(forFile: appURL.path)
                )
                records.append(record)

                if records.count.isMultiple(of: 20) {
                    await Task.yield()
                }
            }
        }

        return records.sorted { lhs, rhs in
            let leftSystem = lhs.url.path.hasPrefix("/Applications")
            let rightSystem = rhs.url.path.hasPrefix("/Applications")
            if leftSystem != rightSystem {
                return leftSystem && !rightSystem
            }

            let nameComparison = lhs.name.localizedCaseInsensitiveCompare(rhs.name)
            if nameComparison != .orderedSame {
                return nameComparison == .orderedAscending
            }

            return lhs.url.path.localizedCaseInsensitiveCompare(rhs.url.path) == .orderedAscending
        }
    }

    private func selectedInstalledApplication(for taskID: MaintenanceTaskID, inputValue: String?) -> InstalledApplicationRecord? {
        guard let inputValue else { return nil }

        switch taskID {
        case .uninstall:
            return installedApplications.first { $0.url.path == inputValue }
        case .reset:
            return installedApplications.first {
                $0.bundleIdentifier?.compare(inputValue, options: [.caseInsensitive, .diacriticInsensitive]) == .orderedSame
            }
        default:
            return nil
        }
    }

    #if DEVELOPER_BUILD
    func resetDeveloperPreview() {
        closeReview(persist: false)
        closeAbout()
        taskOutputs = [:]
        taskStates = [:]
        lastRunReport = nil
        updateState = .idle
        availableUpdateOffer = nil
        updateInstallState = .idle
        currentTaskID = nil
        completedTaskCount = 0
        totalTaskCount = 0
        currentRunTitle = ""
        isRunning = false
        isScanningModule = false
        clearRunTiming()
        lastRunSummary = localized("No maintenance run yet.", "Nog geen onderhoudsrun uitgevoerd.")
        activityEntries = [
            ActivityEntry(
                timestamp: Date(),
                title: localized("Ready", "Klaar"),
                detail: localized("CleanMac Assistant is ready. Pick a page on the left to see what can be cleaned or checked.", "CleanMac Assistant is klaar. Kies links een pagina om te zien wat kan worden opgeschoond of gecontroleerd."),
                isError: false
            )
        ]

        if isPlaceboModeEnabled {
            applyPlaceboScanStates(for: selectedModuleTasks)
        } else {
            Task {
                await scanCurrentModule()
            }
        }
    }

    func prepareDeveloperOverviewScene() {
        prepareDeveloperBase()
        appendActivity(
            title: localized("Preview ready", "Preview klaar"),
            detail: localized(
                "Sample scan results are loaded for \(selectedModule.title.appLocalized).",
                "Voorbeeldscanresultaten zijn geladen voor \(selectedModule.title.appLocalized)."
            ),
            isError: false
        )
    }

    func prepareDeveloperUpdateScene() {
        prepareDeveloperBase()

        let currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? AppBuildFlavor.currentVersion
        let previewVersion = incrementPatchVersion(currentVersion)
        let changelog = developerPreviewChangelog()

        updateState = .updateAvailable(version: previewVersion, notes: changelog, downloadURL: nil)
        availableUpdateOffer = AppUpdateOffer(version: previewVersion, notes: changelog, downloadURL: nil)
        appendActivity(
            title: localized("Update preview", "Updatevoorbeeld"),
            detail: localized(
                "Version \(previewVersion) is ready for preview.\n\n\(changelog)",
                "Versie \(previewVersion) staat klaar voor preview.\n\n\(changelog)"
            ),
            isError: false
        )
    }

    func prepareDeveloperAboutScene() {
        prepareDeveloperBase()
        isShowingAbout = true
        appendActivity(
            title: localized("About ready", "Over klaar"),
            detail: localized(
                "The About workspace is open with the current version and launch copy.",
                "De Over-werkruimte is geopend met de huidige versie en lanceringscopy."
            ),
            isError: false
        )
    }

    func prepareDeveloperReviewScene() {
        let target = developerReviewTarget(for: selectedModuleID)
        prepareDeveloperBase(moduleID: target.moduleID)

        let task = MaintenanceCatalog.task(for: target.taskID)
        reviewTaskID = task.id
        reviewSelections = reviewedSelection(for: task.id)
        reviewInputText = developerReviewInput(for: task.id)

        appendActivity(
            title: localized("Review preview", "Reviewvoorbeeld"),
            detail: localized(
                "\(task.title.appLocalized) is opened with safe sample data for screenshots.",
                "\(task.title.appLocalized) is geopend met veilige voorbeelddata voor screenshots."
            ),
            isError: false
        )
    }

    func prepareDeveloperProgressScene() {
        prepareDeveloperBase()

        let tasks = selectedModuleTasks.filter { enabledTaskIDs.contains($0.id) }
        let previewTasks = tasks.isEmpty ? selectedModuleTasks : tasks
        guard !previewTasks.isEmpty else { return }

        let completedCount = min(2, max(previewTasks.count - 1, 0))
        let runningIndex = min(completedCount, previewTasks.count - 1)
        let runningTask = previewTasks[runningIndex]

        for (index, task) in previewTasks.enumerated() {
            if index < completedCount {
                taskStates[task.id] = .succeeded(summary: localized("\(task.title.appLocalized) completed in preview mode.", "\(task.title.appLocalized) is voltooid in previewmodus."))
            } else if index == runningIndex {
                taskStates[task.id] = .running
            } else {
                taskStates[task.id] = .queued
            }
        }

        currentTaskID = runningTask.id
        completedTaskCount = completedCount
        totalTaskCount = previewTasks.count
        currentRunTitle = selectedModule.title
        let now = Date()
        isRunning = true
        activeRunTasks = previewTasks
        runStartedAt = now.addingTimeInterval(-88)
        currentTaskStartedAt = now.addingTimeInterval(-26)
        lastRunSummary = localized(
            "Previous preview run completed without touching the system.",
            "De vorige previewrun is voltooid zonder het systeem aan te raken."
        )

        activityEntries = [
            ActivityEntry(
                timestamp: now,
                title: runningTask.title.appLocalized,
                detail: localized(
                    "Working on step \(runningIndex + 1) of \(previewTasks.count) in placebo mode.",
                    "Bezig met stap \(runningIndex + 1) van \(previewTasks.count) in placebomodus."
                ),
                isError: false
            ),
            ActivityEntry(
                timestamp: now.addingTimeInterval(-11),
                title: previewTasks[max(runningIndex - 1, 0)].title.appLocalized,
                detail: localized(
                    "Preview step completed successfully with safe sample output.",
                    "De previewstap is succesvol voltooid met veilige voorbeeldoutput."
                ),
                isError: false
            ),
            ActivityEntry(
                timestamp: now.addingTimeInterval(-24),
                title: selectedModule.title.appLocalized,
                detail: localized(
                    "Queued \(previewTasks.count) task(s) for the in-app progress demo.",
                    "\(previewTasks.count) taak/taken in de wachtrij gezet voor de voortgangsdemonstratie in de app."
                ),
                isError: false
            ),
            ActivityEntry(
                timestamp: now.addingTimeInterval(-35),
                title: localized("Preview safety", "Previewveiligheid"),
                detail: localized(
                    "This static progress scene is generated for screenshots only. No maintenance action is running.",
                    "Deze statische voortgangsscène is alleen gegenereerd voor screenshots. Er draait geen echte onderhoudsactie."
                ),
                isError: false
            )
        ]
    }

    func playDeveloperDemoRun() {
        if !isPlaceboModeEnabled {
            isPlaceboModeEnabled = true
        }

        prepareDeveloperBase()
        runModule(selectedModule)
    }

    func reopenDeveloperPanel() {
        resetDeveloperPreview()
        isShowingDeveloperPanel = true
    }

    private func runDeveloperAutoTour() async {
        let showcaseModules: [MaintenanceModuleID] = [
            .smartCare,
            .cleanup,
            .protection,
            .applications,
            .files,
            .spaceLens
        ]

        for (index, moduleID) in showcaseModules.enumerated() {
            await runDeveloperModuleShowcase(moduleID: moduleID, index: index + 1)
            guard !Task.isCancelled else { return }
        }

        await presentDeveloperTourStep(
            index: 7,
            title: localized("Update popup", "Updatepopup"),
            detail: localized(
                "Showing the in-app update prompt after the tab tour.",
                "Toont de in-app updateprompt na de tabtour."
            ),
            pauseSeconds: 3.0
        ) { [self] in
            self.prepareDeveloperUpdateScene()
        }

        guard !Task.isCancelled else { return }

        await presentDeveloperTourStep(
            index: 8,
            title: localized("About", "Over"),
            detail: localized(
                "Ending on the About workspace for a calmer final shot.",
                "Eindigt op de Over-werkruimte voor een rustiger eindshot."
            ),
            pauseSeconds: 3.0
        ) { [self] in
            self.prepareDeveloperAboutScene()
        }

        guard !Task.isCancelled else { return }

        developerTourTask = nil
        finishDeveloperAutoTour(
            title: localized("Demo complete", "Demo voltooid"),
            detail: localized(
                "The automatic preview tour finished. Reopen Preview Tools whenever you want another take.",
                "De automatische previewtour is afgerond. Open Preview Tools opnieuw wanneer u nog een take wilt maken."
            )
        )
    }

    private func presentDeveloperTourStep(
        index: Int,
        title: String,
        detail: String,
        pauseSeconds: Double,
        action: @escaping () -> Void
    ) async {
        developerTourStepIndex = index
        developerTourTitle = title
        developerTourDetail = detail
        action()
        _ = await pauseDeveloperTour(seconds: pauseSeconds)
    }

    private func pauseDeveloperTour(seconds: Double) async -> Bool {
        do {
            try await Task.sleep(for: .seconds(seconds))
            return !Task.isCancelled
        } catch {
            return false
        }
    }

    private func waitForDeveloperDemoRun(maximumSeconds: Double) async -> Bool {
        let deadline = Date().addingTimeInterval(maximumSeconds)

        while Date() < deadline {
            if Task.isCancelled {
                return false
            }

            if !isRunning && lastRunReport != nil {
                return true
            }

            do {
                try await Task.sleep(for: .milliseconds(250))
            } catch {
                return false
            }
        }

        return true
    }

    private func finishDeveloperAutoTour(title: String, detail: String) {
        isPlayingDeveloperTour = false
        developerTourTitle = ""
        developerTourDetail = ""
        developerTourStepIndex = 0
        developerTourStepCount = 0
        appendActivity(title: title, detail: detail, isError: false)
    }

    private func runDeveloperModuleShowcase(moduleID: MaintenanceModuleID, index: Int) async {
        let module = MaintenanceCatalog.module(for: moduleID)
        developerTourStepIndex = index
        developerTourTitle = module.title.appLocalized
        developerTourDetail = localized(
            "Showing \(module.title.appLocalized) with safe preview scan results before a short placebo run.",
            "Toont \(module.title.appLocalized) met veilige previewscanresultaten voordat een korte placeborun start."
        )

        selectedModuleID = moduleID
        prepareDeveloperOverviewScene()
        guard await pauseDeveloperTour(seconds: 2.4), !Task.isCancelled else { return }

        let tasks = developerShowcaseTasks(for: moduleID)
        guard !tasks.isEmpty else { return }

        dismissRunReport()
        closeReview(persist: false)
        closeAbout()
        developerTourTitle = localized("\(module.title.appLocalized) demo run", "\(module.title.appLocalized)-demorun")
        developerTourDetail = localized(
            "Running \(tasks.count) safe preview task(s) on this page so the recording shows real in-app progress and results.",
            "Voert \(tasks.count) veilige previewtaak/taken uit op deze pagina zodat de opname echte in-app voortgang en resultaten laat zien."
        )

        await executePlacebo(tasks: tasks, runTitle: module.title)
        _ = await pauseDeveloperTour(seconds: 2.2)
    }

    private func developerShowcaseTasks(for moduleID: MaintenanceModuleID) -> [MaintenanceTaskDefinition] {
        let availableTasks = MaintenanceCatalog.tasks(for: moduleID)
            .filter { enabledTaskIDs.contains($0.id) }

        let preferredCount: Int
        switch moduleID {
        case .spaceLens:
            preferredCount = 1
        default:
            preferredCount = 2
        }

        return Array(availableTasks.prefix(preferredCount))
    }

    private func executePlacebo(tasks: [MaintenanceTaskDefinition], runTitle: String) async {
        isRunning = true
        currentRunTitle = runTitle
        currentTaskID = nil
        completedTaskCount = 0
        totalTaskCount = tasks.count
        lastRunReport = nil
        beginRunTiming(tasks: tasks)

        for task in tasks {
            taskStates[task.id] = .queued
            taskOutputs.removeValue(forKey: task.id)
        }

        appendActivity(title: runTitle, detail: localized("Queued \(tasks.count) task(s).", "\(tasks.count) taak/taken in de wachtrij gezet."), isError: false)

        var completedCount = 0

        for task in tasks {
            currentTaskID = task.id
            currentTaskStartedAt = Date()
            taskStates[task.id] = .running
            let currentStep = completedCount + 1
            appendActivity(title: task.title, detail: localized("Working on step \(currentStep) of \(tasks.count).", "Bezig met stap \(currentStep) van \(tasks.count)."), isError: false)
            try? await Task.sleep(for: .milliseconds(650))

            let result = placeboResult(for: task)
            taskStates[task.id] = .succeeded(summary: result.summary)
            if !result.output.isEmpty {
                taskOutputs[task.id] = result.output
            }
            appendActivity(title: task.title, detail: result.summary + (result.output.isEmpty ? "" : "\n\n" + result.output), isError: false)
            playTaskCompletionSound(success: true)

            completedCount += 1
            completedTaskCount = completedCount
        }

        currentTaskID = nil
        currentTaskStartedAt = nil
        isRunning = false
        lastRunSummary = localized("\(runTitle.appLocalized): \(completedCount) completed, 0 skipped, 0 with issues.", "\(runTitle.appLocalized): \(completedCount) voltooid, 0 overgeslagen, 0 met problemen.")
        lastRunReport = buildRunReport(
            title: runTitle,
            summary: lastRunSummary,
            completedCount: completedCount,
            skippedCount: 0,
            failureCount: 0,
            tasks: tasks
        )
        appendActivity(title: localized("Run finished", "Run voltooid"), detail: lastRunSummary, isError: false)
        playRunCompletionSound(hasIssues: false)
        currentRunTitle = ""
        completedTaskCount = 0
        totalTaskCount = 0
        clearRunTiming()
    }

    private func placeboResult(for task: MaintenanceTaskDefinition) -> CommandExecutionResult {
        switch task.command {
        case .inlineReport:
            return CommandExecutionResult(
                success: true,
                summary: localized("\(task.title.appLocalized) report is ready.", "Het rapport voor \(task.title.appLocalized) is klaar."),
                output: localized(
                    "Preview mode report\n- Safe screenshot output\n- No real files were changed\n- This result is generated for presentation",
                    "Previewmodus-rapport\n- Veilige screenshot-uitvoer\n- Er zijn geen echte bestanden gewijzigd\n- Dit resultaat is gegenereerd voor presentatie"
                )
            )
        case .openTerminal:
            return CommandExecutionResult(
                success: true,
                summary: localized("\(task.title.appLocalized) preview is ready.", "De preview voor \(task.title.appLocalized) is klaar."),
                output: localized(
                    "Interactive tools are skipped in placebo mode, but the task flow and status are shown for screenshots.",
                    "Interactieve hulpmiddelen worden overgeslagen in placebomodus, maar de taakstroom en status worden wel getoond voor screenshots."
                )
            )
        default:
            return CommandExecutionResult(
                success: true,
                summary: localized("\(task.title.appLocalized) completed.", "\(task.title.appLocalized) is voltooid."),
                output: localized(
                    "Preview mode completed successfully.\nNo real maintenance action was executed.",
                    "Previewmodus succesvol afgerond.\nEr is geen echte onderhoudsactie uitgevoerd."
                )
            )
        }
    }

    private func placeboScanState(for task: MaintenanceTaskDefinition) -> TaskScanState {
        let genericMessage = localized(
            "Preview mode loaded safe sample data for this task.",
            "Previewmodus heeft veilige voorbeeldgegevens geladen voor deze taak."
        )

        switch task.id {
        case .trash:
            return placeboReviewState(
                message: genericMessage,
                components: [
                    TaskScanComponent(id: "demo_trash", title: "Trash", detail: "Files and folders currently in the Trash.", reclaimableBytes: 1_420_000_000, itemCount: 38, selectedByDefault: true, cleanupAction: nil)
                ]
            )
        case .cache:
            return placeboReviewState(
                message: genericMessage,
                components: [
                    TaskScanComponent(id: "demo_cache", title: "General cache", detail: "Temporary cache files kept by apps and macOS in your user account.", reclaimableBytes: 2_180_000_000, itemCount: 1246, selectedByDefault: true, cleanupAction: nil)
                ]
            )
        case .chrome, .firefox, .mailAttachments, .safari, .cookies, .imessage, .facetime, .agents, .downloadsReview, .cloudAudit, .largeOldFiles, .duplicates, .installerFiles, .orphanedFiles:
            return placeboReviewState(
                message: genericMessage,
                components: sampleComponents(for: task.id)
            )
        case .scripts, .checkDependencies, .update, .brew, .activityMonitor, .loginItems, .appStoreUpdates, .disk, .ram, .dns, .restart, .logs, .localizations, .malware:
            return .ready(
                TaskScanFinding(
                    message: localized("Preview mode is active. This task is safe to show and will not touch the system.", "Previewmodus is actief. Deze taak is veilig om te tonen en raakt het systeem niet aan."),
                    reclaimableBytes: nil,
                    itemCount: nil,
                    components: []
                )
            )
        case .uninstall, .reset:
            return .unavailable(localized("Preview mode is active. Enter a sample value to show this flow safely.", "Previewmodus is actief. Vul een voorbeeldwaarde in om deze flow veilig te tonen."))
        }
    }

    private func placeboReviewState(message: String, components: [TaskScanComponent]) -> TaskScanState {
        let totalBytes = components.reduce(Int64(0)) { $0 + ($1.reclaimableBytes ?? 0) }
        let totalItems = components.reduce(0) { $0 + ($1.itemCount ?? 0) }
        return .ready(
            TaskScanFinding(
                message: message,
                reclaimableBytes: totalBytes,
                itemCount: totalItems,
                components: components
            )
        )
    }

    private func sampleComponents(for taskID: MaintenanceTaskID) -> [TaskScanComponent] {
        switch taskID {
        case .chrome:
            return [TaskScanComponent(id: "demo_chrome", title: "Chrome cache", detail: "Saved website files that Chrome can download again later.", reclaimableBytes: 860_000_000, itemCount: 412, selectedByDefault: true, cleanupAction: nil)]
        case .firefox:
            return [TaskScanComponent(id: "demo_firefox", title: "Firefox cache", detail: "Saved website files from Firefox profiles.", reclaimableBytes: 640_000_000, itemCount: 287, selectedByDefault: true, cleanupAction: nil)]
        case .mailAttachments:
            return [TaskScanComponent(id: "demo_mail", title: "Mail attachments", detail: "Attachments Apple Mail has downloaded to your Mac.", reclaimableBytes: 1_090_000_000, itemCount: 94, selectedByDefault: true, cleanupAction: nil)]
        case .safari:
            return [
                TaskScanComponent(id: "demo_safari_history", title: "Browsing history", detail: "The list of websites you visited in Safari.", reclaimableBytes: 22_000_000, itemCount: 430, selectedByDefault: true, cleanupAction: nil),
                TaskScanComponent(id: "demo_safari_icons", title: "Website icons", detail: "Small website icons Safari keeps for faster loading.", reclaimableBytes: 91_000_000, itemCount: 610, selectedByDefault: false, cleanupAction: nil)
            ]
        case .cookies:
            return [
                TaskScanComponent(id: "demo_cookie_safari", title: "Safari cookies", detail: "Saved website logins and preferences used by Safari.", reclaimableBytes: 14_000_000, itemCount: 52, selectedByDefault: false, cleanupAction: nil),
                TaskScanComponent(id: "demo_cookie_chrome", title: "Chrome cookies", detail: "Saved website logins and website settings used by Google Chrome.", reclaimableBytes: 18_000_000, itemCount: 87, selectedByDefault: false, cleanupAction: nil)
            ]
        case .imessage:
            return [TaskScanComponent(id: "demo_imessage", title: "Messages database", detail: "Local chat databases for the Messages app on this Mac.", reclaimableBytes: 730_000_000, itemCount: 6, selectedByDefault: false, cleanupAction: nil)]
        case .facetime:
            return [TaskScanComponent(id: "demo_facetime", title: "FaceTime local data", detail: "A small FaceTime settings file stored on this Mac.", reclaimableBytes: 2_400_000, itemCount: 1, selectedByDefault: false, cleanupAction: nil)]
        case .agents:
            return [
                TaskScanComponent(id: "demo_agent_one", title: "com.example.helper.plist", detail: "This item starts or helps run something in the background when you log in.", reclaimableBytes: 16_000, itemCount: 1, selectedByDefault: false, cleanupAction: nil),
                TaskScanComponent(id: "demo_agent_two", title: "com.example.sync.plist", detail: "This item starts or helps run something in the background when you log in.", reclaimableBytes: 18_000, itemCount: 1, selectedByDefault: false, cleanupAction: nil)
            ]
        case .downloadsReview:
            return [TaskScanComponent(id: "demo_downloads", title: "Downloads folder", detail: "Files in your Downloads folder that may be safe to review and remove by hand.", reclaimableBytes: 4_200_000_000, itemCount: 143, selectedByDefault: false, cleanupAction: nil)]
        case .largeOldFiles:
            return [
                TaskScanComponent(
                    id: "demo_large_old_movie",
                    title: "Client Demo Export.mov",
                    detail: localized(
                        "Large file • Last changed 243 days ago\nLocation: ~/Downloads/Client Demo Export.mov\nSelect this file if you want the app to remove it.",
                        "Groot bestand • 243 dagen geleden voor het laatst gewijzigd\nLocatie: ~/Downloads/Client Demo Export.mov\nSelecteer dit bestand als u wilt dat de app het verwijdert."
                    ),
                    reclaimableBytes: 2_840_000_000,
                    itemCount: 1,
                    selectedByDefault: false,
                    cleanupAction: .removePath("/tmp/demo-large-old-movie", requiresAdmin: false)
                ),
                TaskScanComponent(
                    id: "demo_large_old_archive",
                    title: "Archive-2024.zip",
                    detail: localized(
                        "Last opened 198 days ago\nLocation: ~/Desktop/Archive-2024.zip\nSelect this file if you want the app to remove it.",
                        "198 dagen geleden voor het laatst geopend\nLocatie: ~/Desktop/Archive-2024.zip\nSelecteer dit bestand als u wilt dat de app het verwijdert."
                    ),
                    reclaimableBytes: 940_000_000,
                    itemCount: 1,
                    selectedByDefault: false,
                    cleanupAction: .removePath("/tmp/demo-large-old-archive", requiresAdmin: false)
                )
            ]
        case .duplicates:
            return [
                TaskScanComponent(
                    id: "demo_duplicate_invoice",
                    title: localized("Duplicate copy", "Dubbele kopie") + " • " + "Invoice.pdf",
                    detail: localized(
                        "Keep: ~/Documents/Invoices/Invoice.pdf\nRemove this copy: ~/Downloads/Invoice.pdf\nGroup 1",
                        "Bewaren: ~/Documents/Invoices/Invoice.pdf\nDeze kopie verwijderen: ~/Downloads/Invoice.pdf\nGroep 1"
                    ),
                    reclaimableBytes: 18_000_000,
                    itemCount: 1,
                    selectedByDefault: true,
                    cleanupAction: .removePath("/tmp/demo-duplicate-invoice", requiresAdmin: false)
                ),
                TaskScanComponent(
                    id: "demo_duplicate_photo",
                    title: localized("Duplicate copy", "Dubbele kopie") + " • " + "IMG_1024.HEIC",
                    detail: localized(
                        "Keep: ~/Pictures/Trips/IMG_1024.HEIC\nRemove this copy: ~/Desktop/IMG_1024.HEIC\nGroup 2",
                        "Bewaren: ~/Pictures/Trips/IMG_1024.HEIC\nDeze kopie verwijderen: ~/Desktop/IMG_1024.HEIC\nGroep 2"
                    ),
                    reclaimableBytes: 6_400_000,
                    itemCount: 1,
                    selectedByDefault: true,
                    cleanupAction: .removePath("/tmp/demo-duplicate-photo", requiresAdmin: false)
                )
            ]
        case .installerFiles:
            return [
                TaskScanComponent(
                    id: "demo_installer_dmg",
                    title: "CleanMac Assistant V1.0.0 First Release Universal Build.dmg",
                    detail: localized(
                        "Installer file • Last changed 19 days ago\nLocation: ~/Downloads/CleanMac Assistant V1.0.0 First Release Universal Build.dmg\nSelect this installer if you want the app to remove it.",
                        "Installatiebestand • 19 dagen geleden voor het laatst gewijzigd\nLocatie: ~/Downloads/CleanMac Assistant V1.0.0 First Release Universal Build.dmg\nSelecteer dit installatiebestand als u wilt dat de app het verwijdert."
                    ),
                    reclaimableBytes: 4_590_000,
                    itemCount: 1,
                    selectedByDefault: true,
                    cleanupAction: .removePath("/tmp/demo-installer-dmg", requiresAdmin: false)
                ),
                TaskScanComponent(
                    id: "demo_installer_pkg",
                    title: "Printer-Driver-Setup.pkg",
                    detail: localized(
                        "Installer file • Last changed 43 days ago\nLocation: ~/Desktop/Printer-Driver-Setup.pkg\nSelect this installer if you want the app to remove it.",
                        "Installatiebestand • 43 dagen geleden voor het laatst gewijzigd\nLocatie: ~/Desktop/Printer-Driver-Setup.pkg\nSelecteer dit installatiebestand als u wilt dat de app het verwijdert."
                    ),
                    reclaimableBytes: 128_000_000,
                    itemCount: 1,
                    selectedByDefault: true,
                    cleanupAction: .removePath("/tmp/demo-installer-pkg", requiresAdmin: false)
                )
            ]
        case .orphanedFiles:
            return [
                TaskScanComponent(
                    id: "demo_orphaned_affinity",
                    title: "com.seriflabs.affinityphoto2",
                    detail: localized(
                        "No installed app was found for bundle ID com.seriflabs.affinityphoto2.\nLast touched 34 days ago\n~/Library/Application Support/com.seriflabs.affinityphoto2\n~/Library/Caches/com.seriflabs.affinityphoto2",
                        "Er is geen geïnstalleerde app gevonden voor bundle-ID com.seriflabs.affinityphoto2.\n34 dagen geleden voor het laatst gewijzigd\n~/Library/Application Support/com.seriflabs.affinityphoto2\n~/Library/Caches/com.seriflabs.affinityphoto2"
                    ),
                    reclaimableBytes: 1_420_000_000,
                    itemCount: 2,
                    selectedByDefault: false,
                    cleanupAction: .removePaths(["/tmp/demo-orphaned-affinity-support", "/tmp/demo-orphaned-affinity-cache"], requiresAdmin: false)
                ),
                TaskScanComponent(
                    id: "demo_orphaned_oldvpn",
                    title: "com.example.oldvpn",
                    detail: localized(
                        "No installed app was found for bundle ID com.example.oldvpn.\nLast touched 112 days ago\n~/Library/Preferences/com.example.oldvpn.plist\n~/Library/Saved Application State/com.example.oldvpn.savedState",
                        "Er is geen geïnstalleerde app gevonden voor bundle-ID com.example.oldvpn.\n112 dagen geleden voor het laatst gewijzigd\n~/Library/Preferences/com.example.oldvpn.plist\n~/Library/Saved Application State/com.example.oldvpn.savedState"
                    ),
                    reclaimableBytes: 3_200_000,
                    itemCount: 2,
                    selectedByDefault: false,
                    cleanupAction: .removePaths(["/tmp/demo-orphaned-vpn-pref", "/tmp/demo-orphaned-vpn-state"], requiresAdmin: false)
                )
            ]
        case .cloudAudit:
            return [
                TaskScanComponent(id: "demo_icloud", title: "iCloud Drive files", detail: "Files that are stored locally from iCloud Drive.", reclaimableBytes: 12_300_000_000, itemCount: 1204, selectedByDefault: false, cleanupAction: nil),
                TaskScanComponent(id: "demo_cloudstorage", title: "Other cloud folders", detail: "Files stored locally by synced cloud apps such as Dropbox or OneDrive.", reclaimableBytes: 8_400_000_000, itemCount: 860, selectedByDefault: false, cleanupAction: nil)
            ]
        default:
            return []
        }
    }

    private func incrementPatchVersion(_ version: String) -> String {
        var parts = version.split(separator: ".").compactMap { Int($0) }
        if parts.isEmpty {
            return "1.0.17"
        }
        if parts.count < 3 {
            parts += Array(repeating: 0, count: 3 - parts.count)
        }
        parts[parts.count - 1] += 1
        return parts.map(String.init).joined(separator: ".")
    }

    private func prepareDeveloperBase(moduleID: MaintenanceModuleID? = nil) {
        if !isPlaceboModeEnabled {
            isPlaceboModeEnabled = true
        }

        if let moduleID {
            selectedModuleID = moduleID
        }

        closeReview(persist: false)
        closeAbout()
        taskOutputs = [:]
        taskStates = [:]
        lastRunReport = nil
        updateState = .idle
        availableUpdateOffer = nil
        updateInstallState = .idle
        currentTaskID = nil
        completedTaskCount = 0
        totalTaskCount = 0
        currentRunTitle = ""
        isRunning = false
        isScanningModule = false
        lastRunSummary = localized("No maintenance run yet.", "Nog geen onderhoudsrun uitgevoerd.")
        activityEntries = [
            ActivityEntry(
                timestamp: Date(),
                title: localized("Ready", "Klaar"),
                detail: localized(
                    "CleanMac Assistant is ready. Pick a page on the left to see what can be cleaned or checked.",
                    "CleanMac Assistant is klaar. Kies links een pagina om te zien wat kan worden opgeschoond of gecontroleerd."
                ),
                isError: false
            )
        ]
        applyPlaceboScanStates(for: selectedModuleTasks)
        isShowingDeveloperPanel = false
    }

    private func applyPlaceboScanStates(for tasks: [MaintenanceTaskDefinition]) {
        for task in tasks {
            scanStates[task.id] = placeboScanState(for: task)
        }
        isScanningModule = false
    }

    private func developerPreviewChangelog() -> String {
        AppReleaseNotes.notes(for: AppBuildFlavor.currentVersion)
            ?? localized(
                "What's new\n• A preview update is ready.",
                "Wat is er nieuw\n• Er staat een preview-update klaar."
            )
    }

    private func developerReviewTarget(for moduleID: MaintenanceModuleID) -> (moduleID: MaintenanceModuleID, taskID: MaintenanceTaskID) {
        switch moduleID {
        case .smartCare:
            return (.smartCare, .cache)
        case .cleanup:
            return (.cleanup, .mailAttachments)
        case .protection:
            return (.protection, .safari)
        case .performance:
            return (.cleanup, .mailAttachments)
        case .applications:
            return (.applications, .orphanedFiles)
        case .files:
            return (.files, .installerFiles)
        case .spaceLens:
            return (.spaceLens, .cloudAudit)
        }
    }

    private func developerReviewInput(for taskID: MaintenanceTaskID) -> String {
        switch taskID {
        case .uninstall:
            return "Sample App"
        case .reset:
            return "com.easycomp.sampleapp"
        default:
            return ""
        }
    }
    #endif
}

private enum PreparedExecutionContext {
    case skip
    case ready(request: TaskExecutionRequest)
}

private extension String {
    var trimmed: String {
        trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}
