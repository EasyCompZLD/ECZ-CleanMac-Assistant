import Foundation

private func emitMaintenanceProgressLine(_ line: String, taskID: MaintenanceTaskID) {
    NotificationCenter.default.post(
        name: MaintenanceProgressNotification.name,
        object: nil,
        userInfo: [
            MaintenanceProgressNotification.taskIDKey: taskID.rawValue,
            MaintenanceProgressNotification.lineKey: line
        ]
    )
}

struct TaskExecutionRequest {
    let input: String?
    let selectedComponents: [TaskScanComponent]
    let selectedReviewComponents: [TaskScanComponent]
}

struct CommandExecutionResult {
    let success: Bool
    let summary: String
    let output: String
    let malwareOutcome: MalwareScanOutcome?

    init(success: Bool, summary: String, output: String, malwareOutcome: MalwareScanOutcome? = nil) {
        self.success = success
        self.summary = summary
        self.output = output
        self.malwareOutcome = malwareOutcome
    }
}

private struct ProcessOutput {
    let exitCode: Int32
    let stdout: String
    let stderr: String

    var combined: String {
        [stdout.trimmingCharacters(in: .whitespacesAndNewlines), stderr.trimmingCharacters(in: .whitespacesAndNewlines)]
            .filter { !$0.isEmpty }
            .joined(separator: "\n")
    }

    var isSuccess: Bool {
        exitCode == 0
    }
}

private final class StreamingProcessCollector: @unchecked Sendable {
    private let queue = DispatchQueue(label: "MaintenanceCommandExecutor.streaming")
    private var stdoutData = Data()
    private var stderrData = Data()
    private var stdoutBuffer = Data()
    private var stderrBuffer = Data()

    func append(_ newData: Data, isStdout: Bool) -> [String] {
        guard !newData.isEmpty else { return [] }

        return queue.sync {
            if isStdout {
                stdoutData.append(newData)
                stdoutBuffer.append(newData)
                return Self.extractLines(from: &stdoutBuffer)
            } else {
                stderrData.append(newData)
                stderrBuffer.append(newData)
                return Self.extractLines(from: &stderrBuffer)
            }
        }
    }

    func flushRemainder(isStdout: Bool) -> [String] {
        queue.sync {
            let buffer = isStdout ? stdoutBuffer : stderrBuffer
            guard !buffer.isEmpty else { return [] }

            let line = String(data: buffer, encoding: .utf8)?
                .replacingOccurrences(of: "\r", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)

            if isStdout {
                stdoutBuffer.removeAll(keepingCapacity: false)
            } else {
                stderrBuffer.removeAll(keepingCapacity: false)
            }

            guard let line, !line.isEmpty else { return [] }
            return [line]
        }
    }

    func outputs() -> (stdout: String, stderr: String) {
        queue.sync {
            (
                String(data: stdoutData, encoding: .utf8) ?? "",
                String(data: stderrData, encoding: .utf8) ?? ""
            )
        }
    }

    private static func extractLines(from buffer: inout Data) -> [String] {
        var lines: [String] = []

        while let newlineIndex = buffer.firstIndex(of: 0x0A) {
            let lineData = buffer.subdata(in: 0..<newlineIndex)
            buffer.removeSubrange(0...newlineIndex)

            if let line = String(data: lineData, encoding: .utf8)?
                .replacingOccurrences(of: "\r", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines),
               !line.isEmpty
            {
                lines.append(line)
            }
        }

        return lines
    }
}

private struct ClamDatabasePreparation {
    let databaseDirectory: String
    let output: String
}

private enum ClamDatabasePreparationResult {
    case ready(ClamDatabasePreparation)
    case failed(CommandExecutionResult)
}

private enum ComponentCleanupStatus {
    case success(String)
    case warning(String)
    case failure(String)

    var message: String {
        switch self {
        case let .success(message), let .warning(message), let .failure(message):
            return message
        }
    }

    var isFailure: Bool {
        if case .failure = self {
            return true
        }
        return false
    }

    var isWarning: Bool {
        if case .warning = self {
            return true
        }
        return false
    }
}

private struct FileRemovalReport {
    var removedCount = 0
    var protectedPaths: [String] = []
    var missingPaths: [String] = []
    var failures: [String] = []
}

private enum ProtectedResourceArea {
    case trash
    case safari
    case messages
    case mail
    case cookies
    case caches
    case generic
}

actor MaintenanceCommandExecutor {
    private let fileManager = FileManager.default
    private let shellBootstrap = "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH; "
    private let clamDatabaseRefreshInterval: TimeInterval = 60 * 60 * 24 * 3
    private let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useKB, .useMB, .useGB, .useTB]
        formatter.countStyle = .file
        formatter.isAdaptive = true
        return formatter
    }()

    func run(task: MaintenanceTaskDefinition, request: TaskExecutionRequest) async -> CommandExecutionResult {
        if !request.selectedComponents.isEmpty {
            return await runSelectedComponents(request.selectedComponents, task: task)
        }

        switch task.command {
        case .dependencyCheck:
            return await runDependencyCheck()

        case let .shell(command, requiresAdmin):
            return await runMappedShellCommand(command, task: task, request: request, requiresAdmin: requiresAdmin)

        case let .inlineReport(command):
            return await runInlineReport(command, task: task)

        case let .openTerminal(command):
            return await runTerminalCommand(command, task: task)

        case .uninstallApplication:
            guard let input = request.input, !input.isEmpty else {
                return CommandExecutionResult(success: false, summary: localized("No app name was entered.", "Er is geen appnaam ingevuld."), output: "")
            }
            return await uninstallApplication(named: input)

        case .resetPreferences:
            guard let input = request.input, !input.isEmpty else {
                return CommandExecutionResult(success: false, summary: localized("No bundle identifier was entered.", "Er is geen bundle-identifier ingevuld."), output: "")
            }
            let result = await runShell("defaults delete \(shellQuote(input))", requiresAdmin: false)
            return translate(result, success: localized("Preferences for \(input) were reset.", "De voorkeuren voor \(input) zijn gereset."), failure: localized("Failed to reset preferences for \(input).", "Het resetten van de voorkeuren voor \(input) is mislukt."))
        }
    }

    private func runSelectedComponents(_ components: [TaskScanComponent], task: MaintenanceTaskDefinition) async -> CommandExecutionResult {
        var outputs: [String] = []
        var failures = 0
        var warnings = 0

        for component in components {
            guard let action = component.cleanupAction else { continue }

            let status: ComponentCleanupStatus
            switch action {
            case let .removePath(path, requiresAdmin):
                status = await removalStatus(
                    for: component,
                    report: removePaths([path], requiresAdmin: requiresAdmin),
                    area: protectedResourceArea(for: [path])
                )
            case let .removePaths(paths, requiresAdmin):
                status = await removalStatus(
                    for: component,
                    report: removePaths(paths, requiresAdmin: requiresAdmin),
                    area: protectedResourceArea(for: paths)
                )
            case let .removeDirectoryContents(path, requiresAdmin):
                status = await removalStatus(
                    for: component,
                    report: removeDirectoryContents(at: path, requiresAdmin: requiresAdmin),
                    area: protectedResourceArea(for: [path])
                )
            case let .shell(command, requiresAdmin):
                let result = await runShell(command, requiresAdmin: requiresAdmin)
                status = cleanupStatus(
                    for: result,
                    component: component,
                    protectedArea: protectedResourceArea(forCommand: command)
                )
            case let .sqlite(databasePath, statement):
                let command = "sqlite3 \(shellQuote(databasePath)) \(shellQuote(statement))"
                let result = await runShell(command, requiresAdmin: false)
                status = cleanupStatus(
                    for: result,
                    component: component,
                    protectedArea: protectedResourceArea(for: [databasePath])
                )
            }

            outputs.append(status.message)
            if status.isFailure {
                failures += 1
            } else if status.isWarning {
                warnings += 1
            }
        }

        if failures == 0 && warnings == 0 {
            return CommandExecutionResult(
                success: true,
                summary: localized("\(task.title.appLocalized) finished for the selected parts.", "\(task.title.appLocalized) is afgerond voor de geselecteerde onderdelen."),
                output: outputs.joined(separator: "\n\n")
            )
        }

        if failures == 0 {
            return CommandExecutionResult(
                success: true,
                summary: localized("\(task.title.appLocalized) finished, but some protected items were skipped.", "\(task.title.appLocalized) is afgerond, maar enkele beschermde onderdelen zijn overgeslagen."),
                output: outputs.joined(separator: "\n\n")
            )
        }

        return CommandExecutionResult(
            success: false,
            summary: localized("\(task.title.appLocalized) finished with issues in one or more selected parts.", "\(task.title.appLocalized) is afgerond met problemen in een of meer geselecteerde onderdelen."),
            output: outputs.joined(separator: "\n\n")
        )
    }

    private func runDependencyCheck() async -> CommandExecutionResult {
        guard let brewPath = await resolveCommandPath("brew") else {
            return CommandExecutionResult(
                success: false,
                summary: localized("Homebrew is not installed.", "Homebrew is niet geïnstalleerd."),
                output: localized("Install Homebrew from brew.sh before running dependency setup.", "Installeer eerst Homebrew via brew.sh voordat u de afhankelijkheden controleert.")
            )
        }

        var notes: [String] = [localized("Using Homebrew at \(brewPath).", "Homebrew wordt gebruikt vanaf \(brewPath).")]

        let clamResult = await ensureCommand(toolName: "clamscan", formulaName: "clamav", brewPath: brewPath, friendlyName: "ClamAV")
        notes.append(claimer(for: "ClamAV", result: clamResult))
        if !clamResult.success {
            return CommandExecutionResult(success: false, summary: localized("Dependency setup did not finish cleanly.", "De voorbereiding van afhankelijkheden is niet netjes afgerond."), output: notes.joined(separator: "\n\n") + "\n\n" + clamResult.output)
        }

        let ncduResult = await ensureCommand(toolName: "ncdu", formulaName: "ncdu", brewPath: brewPath, friendlyName: "ncdu")
        notes.append(claimer(for: "ncdu", result: ncduResult))
        if !ncduResult.success {
            return CommandExecutionResult(success: false, summary: localized("Dependency setup did not finish cleanly.", "De voorbereiding van afhankelijkheden is niet netjes afgerond."), output: notes.joined(separator: "\n\n") + "\n\n" + ncduResult.output)
        }

        let jdupesResult = await ensureCommand(toolName: "jdupes", formulaName: "jdupes", brewPath: brewPath, friendlyName: "jdupes")
        notes.append(claimer(for: "jdupes", result: jdupesResult))
        if !jdupesResult.success {
            return CommandExecutionResult(success: false, summary: localized("Dependency setup did not finish cleanly.", "De voorbereiding van afhankelijkheden is niet netjes afgerond."), output: notes.joined(separator: "\n\n") + "\n\n" + jdupesResult.output)
        }

        return CommandExecutionResult(success: true, summary: localized("Homebrew, ClamAV, ncdu, and jdupes are ready.", "Homebrew, ClamAV, ncdu en jdupes zijn klaar."), output: notes.joined(separator: "\n"))
    }

    private func runMappedShellCommand(_ command: String, task: MaintenanceTaskDefinition, request: TaskExecutionRequest, requiresAdmin: Bool) async -> CommandExecutionResult {
        switch command {
        case "__BREW_UPDATE__":
            guard let brewPath = await resolveCommandPath("brew") else {
                return CommandExecutionResult(success: false, summary: localized("Homebrew is not installed.", "Homebrew is niet geïnstalleerd."), output: localized("Install Homebrew first, then try again.", "Installeer eerst Homebrew en probeer het daarna opnieuw."))
            }
            let brewQuoted = shellQuote(brewPath)
            let doctor = await runShell("\(brewQuoted) doctor", requiresAdmin: false)
            if !doctor.isSuccess {
                return translate(doctor, success: localized("Homebrew doctor completed.", "Homebrew doctor is voltooid."), failure: localized("brew doctor reported issues.", "brew doctor meldde problemen."))
            }

            let update = await runShell("\(brewQuoted) update --verbose && \(brewQuoted) upgrade --verbose", requiresAdmin: false)
            return translate(update, success: localized("Homebrew packages were updated.", "Homebrew-pakketten zijn bijgewerkt."), failure: localized("Homebrew update did not finish cleanly.", "De Homebrew-update is niet netjes afgerond."))

        case "__CLAM_SCAN__":
            let dependencyResult = await ensureDependencyOnly(toolName: "clamscan", formulaName: "clamav", friendlyName: "ClamAV")
            guard dependencyResult.success else {
                return dependencyResult
            }
            guard let clamscanPath = await resolveCommandPath("clamscan") else {
                return CommandExecutionResult(success: false, summary: localized("ClamAV is still unavailable.", "ClamAV is nog steeds niet beschikbaar."), output: "")
            }
            switch await prepareClamDatabase(for: task.id) {
            case let .failed(result):
                return result
            case let .ready(preparation):
                let selectedTargetComponents = request.selectedReviewComponents.filter { $0.role == .scanTarget }
                let scanTargets = clamScanTargets(from: selectedTargetComponents)
                guard !scanTargets.isEmpty else {
                    return CommandExecutionResult(
                        success: false,
                        summary: localized("No scan locations are available.", "Er zijn geen scanlocaties beschikbaar."),
                        output: localized(
                            "CleanMac Assistant could not find any accessible app or user folders to scan with ClamAV.",
                            "CleanMac Assistant kon geen toegankelijke app- of gebruikersmappen vinden om met ClamAV te scannen."
                        )
                    )
                }

                emitMaintenanceProgressLine("__ECZ_SCAN_PREPARING_SCOPE__", taskID: task.id)
                let estimatedFileCount = estimatedClamScanFileCount(in: scanTargets)
                if estimatedFileCount > 0 {
                    emitMaintenanceProgressLine("__ECZ_SCAN_TOTAL_FILES__:\(estimatedFileCount)", taskID: task.id)
                }

                let targetList = scanTargets.map(shellQuote).joined(separator: " ")
                let result = await runStreamingShell(
                    "\(shellQuote(clamscanPath)) --database=\(shellQuote(preparation.databaseDirectory)) --recursive --verbose --stdout \(targetList)",
                    progressTaskID: task.id
                )
                let malwareOutcome = parseMalwareScanOutcome(
                    from: result.combined,
                    targetTitles: selectedTargetComponents.map { $0.title.appLocalized }
                )
                let success = result.exitCode == 0 || (result.exitCode == 1 && !malwareOutcome.threats.isEmpty)
                let summary: String
                if !success {
                    summary = localized("Malware scan failed.", "Malwarescan is mislukt.")
                } else if malwareOutcome.threats.isEmpty {
                    summary = localized("Malware scan finished. No threats were found.", "Malwarescan is afgerond. Er zijn geen dreigingen gevonden.")
                } else {
                    let count = malwareOutcome.threats.count
                    summary = localized(
                        "Malware scan finished. \(count) potential threat(s) need your decision.",
                        "Malwarescan is afgerond. \(count) mogelijke dreiging(en) wachten op uw keuze."
                    )
                }
                let targetTitleSummary = selectedTargetComponents.map { $0.title.appLocalized }
                let targetSummary: String
                if targetTitleSummary.isEmpty {
                    targetSummary = localized(
                        "Scanning \(scanTargets.count) focused app, launch, and user locations instead of blindly crawling the full disk, so progress can stay visible and the sweep stays relevant.",
                        "Scant \(scanTargets.count) gerichte app-, opstart- en gebruikerslocaties in plaats van blind de hele schijf af te lopen, zodat de voortgang zichtbaar blijft en de controle relevant blijft."
                    )
                } else {
                    let joinedTitles = targetTitleSummary.joined(separator: ", ")
                    targetSummary = localized(
                        "Scanning the areas you selected: \(joinedTitles).",
                        "Scant alleen de gebieden die u hebt geselecteerd: \(joinedTitles)."
                    )
                }
                let combinedOutput = [preparation.output, targetSummary, condensedClamOutput(result.combined)]
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
                    .joined(separator: "\n\n")
                return CommandExecutionResult(success: success, summary: summary, output: combinedOutput, malwareOutcome: malwareOutcome)
            }

        default:
            let result = await runShell(command, requiresAdmin: requiresAdmin)
            return translate(result, success: localized("\(task.title.appLocalized) completed.", "\(task.title.appLocalized) is voltooid."), failure: localized("\(task.title.appLocalized) failed.", "\(task.title.appLocalized) is mislukt."))
        }
    }

    private func runInlineReport(_ command: String, task: MaintenanceTaskDefinition) async -> CommandExecutionResult {
        let resolvedCommand: String

        switch command {
        case "__DUPLICATE_SCAN__":
            let dependencyResult = await ensureDependencyOnly(toolName: "jdupes", formulaName: "jdupes", friendlyName: "jdupes")
            guard dependencyResult.success else {
                return dependencyResult
            }
            guard let jdupesPath = await resolveCommandPath("jdupes") else {
                return CommandExecutionResult(success: false, summary: localized("jdupes is not available.", "jdupes is niet beschikbaar."), output: "")
            }
            resolvedCommand = """
            echo '\(localized("Duplicate file candidates in Desktop, Documents, and Downloads", "Mogelijke dubbele bestanden in Bureaublad, Documenten en Downloads"))'
            echo '-------------------------------------------------------------'
            \(shellQuote(jdupesPath)) -r ~/Desktop ~/Documents ~/Downloads 2>/dev/null
            """

        case "__LARGE_OLD_FILES__":
            resolvedCommand = """
            echo '\(localized("Large files over 500 MB in Desktop, Documents, and Downloads", "Grote bestanden boven 500 MB in Bureaublad, Documenten en Downloads"))'
            echo '-----------------------------------------------------------'
            find ~/Desktop ~/Documents ~/Downloads -type f -size +500M 2>/dev/null | head -200
            echo ''
            echo '\(localized("Files older than 180 days in Desktop, Documents, and Downloads", "Bestanden ouder dan 180 dagen in Bureaublad, Documenten en Downloads"))'
            echo '---------------------------------------------------------------'
            find ~/Desktop ~/Documents ~/Downloads -type f -mtime +180 2>/dev/null | head -200
            """

        case "__INSTALLER_REVIEW__":
            resolvedCommand = """
            echo '\(localized("Installer files in Downloads, Desktop, and Homebrew cache", "Installatiebestanden in Downloads, Bureaublad en Homebrew-cache"))'
            echo '--------------------------------------------------------------'
            find ~/Downloads ~/Desktop ~/Library/Caches/Homebrew -type f \\( -iname '*.dmg' -o -iname '*.pkg' -o -iname '*.mpkg' -o -iname '*.xip' -o -iname '*.iso' \\) 2>/dev/null | head -200
            """

        case "__CLOUD_AUDIT__":
            resolvedCommand = """
            echo '\(localized("Cloud storage overview", "Overzicht van cloudopslag"))'
            echo '----------------------'
            du -sh ~/Library/CloudStorage/* 2>/dev/null | sort -h
            echo ''
            du -sh ~/Library/Mobile\\ Documents/* 2>/dev/null | sort -h
            echo ''
            echo '\(localized("Large synced files over 250 MB", "Grote gesynchroniseerde bestanden boven 250 MB"))'
            echo '------------------------------'
            find ~/Library/CloudStorage ~/Library/Mobile\\ Documents -type f -size +250M 2>/dev/null | head -120
            """

        case "__SYSTEM_MAINTENANCE_STATUS__":
            resolvedCommand = """
            echo '\(localized("macOS background maintenance status", "Status van macOS-achtergrondonderhoud"))'
            echo '----------------------------------'
            launchctl print system/com.apple.systemstats.daily 2>/dev/null | sed -n '1,40p'
            echo ''
            echo '\(localized("Periodic CLI status", "Status van de oude periodic-CLI"))'
            echo '-------------------'
            if command -v periodic >/dev/null 2>&1; then
              command -v periodic
            else
              echo '\(localized("The legacy periodic command is not present on this macOS version.", "Het oude periodic-commando is op deze macOS-versie niet aanwezig."))'
            fi
            """

        default:
            resolvedCommand = command
        }

        let result = await runShell(resolvedCommand, requiresAdmin: false)
        let output = result.combined.trimmingCharacters(in: .whitespacesAndNewlines)
        return CommandExecutionResult(
            success: result.isSuccess,
            summary: result.isSuccess ? localized("\(task.title.appLocalized) report is ready.", "Het rapport voor \(task.title.appLocalized) is klaar.") : localized("\(task.title.appLocalized) report failed.", "Het rapport voor \(task.title.appLocalized) is mislukt."),
            output: output
        )
    }

    private func runTerminalCommand(_ command: String, task: MaintenanceTaskDefinition) async -> CommandExecutionResult {
        let resolvedCommand: String
        if command == "__NCDU_COMMAND__" {
            let dependencyResult = await ensureDependencyOnly(toolName: "ncdu", formulaName: "ncdu", friendlyName: "ncdu")
            guard dependencyResult.success else {
                return dependencyResult
            }
            guard let ncduPath = await resolveCommandPath("ncdu") else {
                return CommandExecutionResult(success: false, summary: localized("ncdu is not available.", "ncdu is niet beschikbaar."), output: "")
            }
            resolvedCommand = "\(shellQuote(ncduPath)) /"
        } else if command == "__DUPLICATE_SCAN__" {
            let dependencyResult = await ensureDependencyOnly(toolName: "jdupes", formulaName: "jdupes", friendlyName: "jdupes")
            guard dependencyResult.success else {
                return dependencyResult
            }
            guard let jdupesPath = await resolveCommandPath("jdupes") else {
                return CommandExecutionResult(success: false, summary: localized("jdupes is not available.", "jdupes is niet beschikbaar."), output: "")
            }
            resolvedCommand = """
            clear
            echo 'Scanning Desktop, Documents, and Downloads for duplicate files...'
            echo ''
            \(shellQuote(jdupesPath)) -r ~/Desktop ~/Documents ~/Downloads 2>/dev/null
            echo ''
            echo 'Read-only scan complete.'
            """
        } else if command == "__LARGE_OLD_FILES__" {
            resolvedCommand = """
            clear
            echo 'Large files over 500 MB in Desktop, Documents, and Downloads'
            echo '-----------------------------------------------------------'
            find ~/Desktop ~/Documents ~/Downloads -type f -size +500M 2>/dev/null | head -200
            echo ''
            echo 'Files older than 180 days in Desktop, Documents, and Downloads'
            echo '---------------------------------------------------------------'
            find ~/Desktop ~/Documents ~/Downloads -type f -mtime +180 2>/dev/null | head -200
            echo ''
            echo 'Read-only scan complete.'
            """
        } else if command == "__CLOUD_AUDIT__" {
            resolvedCommand = """
            clear
            echo 'Cloud storage overview'
            echo '----------------------'
            du -sh ~/Library/CloudStorage/* 2>/dev/null | sort -h
            echo ''
            du -sh ~/Library/Mobile\\ Documents/* 2>/dev/null | sort -h
            echo ''
            echo 'Large synced files over 250 MB'
            echo '------------------------------'
            find ~/Library/CloudStorage ~/Library/Mobile\\ Documents -type f -size +250M 2>/dev/null | head -120
            """
        } else {
            resolvedCommand = command
        }

        let script = """
        tell application "Terminal"
            activate
            do script "\(appleScriptEscape(shellBootstrap + resolvedCommand))"
        end tell
        """
        let result = await runAppleScript(script)
        return translate(result, success: localized("\(task.title.appLocalized) opened in Terminal.", "\(task.title.appLocalized) is geopend in Terminal."), failure: localized("Failed to open Terminal for \(task.title.appLocalized).", "Het openen van Terminal voor \(task.title.appLocalized) is mislukt."))
    }

    private func ensureDependencyOnly(toolName: String, formulaName: String, friendlyName: String) async -> CommandExecutionResult {
        guard let brewPath = await resolveCommandPath("brew") else {
            return CommandExecutionResult(success: false, summary: localized("Homebrew is not installed.", "Homebrew is niet geïnstalleerd."), output: localized("Install Homebrew from brew.sh before running dependency setup.", "Installeer eerst Homebrew via brew.sh voordat u de afhankelijkheden controleert."))
        }
        return await ensureCommand(toolName: toolName, formulaName: formulaName, brewPath: brewPath, friendlyName: friendlyName)
    }

    private func ensureCommand(toolName: String, formulaName: String, brewPath: String, friendlyName: String) async -> CommandExecutionResult {
        if let existing = await resolveCommandPath(toolName), !existing.isEmpty {
            return CommandExecutionResult(success: true, summary: localized("\(friendlyName) is already available.", "\(friendlyName) is al beschikbaar."), output: existing)
        }

        let install = await runShell("\(shellQuote(brewPath)) install \(shellQuote(formulaName))", requiresAdmin: false)
        return translate(install, success: localized("\(friendlyName) was installed.", "\(friendlyName) is geïnstalleerd."), failure: localized("Failed to install \(friendlyName).", "Het installeren van \(friendlyName) is mislukt."))
    }

    private func resolveCommandPath(_ toolName: String) async -> String? {
        let result = await runShell("command -v \(toolName)", requiresAdmin: false)
        guard result.isSuccess else { return nil }
        let path = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return path.isEmpty ? nil : path
    }

    private func prepareClamDatabase(for taskID: MaintenanceTaskID) async -> ClamDatabasePreparationResult {
        guard let freshclamPath = await resolveCommandPath("freshclam") else {
            return .failed(
                CommandExecutionResult(
                    success: false,
                    summary: localized("ClamAV updater is not available.", "De ClamAV-updater is niet beschikbaar."),
                    output: localized(
                        "Install or reinstall the Homebrew clamav package so freshclam can download the malware signatures before scanning.",
                        "Installeer of herinstalleer het Homebrew-pakket clamav zodat freshclam de malwaresignatures kan downloaden voordat er wordt gescand."
                    )
                )
            )
        }

        let databaseDirectoryURL: URL
        let freshclamConfigURL: URL
        do {
            databaseDirectoryURL = try clamDatabaseDirectory()
            try fileManager.createDirectory(at: databaseDirectoryURL, withIntermediateDirectories: true)
            freshclamConfigURL = try ensureFreshclamConfig(for: databaseDirectoryURL)
        } catch {
            return .failed(
                CommandExecutionResult(
                    success: false,
                    summary: localized("ClamAV signatures could not be prepared.", "De ClamAV-signatures konden niet worden voorbereid."),
                    output: error.localizedDescription
                )
            )
        }

        let databaseDirectory = databaseDirectoryURL.path
        let hadDatabaseBeforeRefresh = clamDatabaseExists(in: databaseDirectoryURL)
        let needsRefresh = !hadDatabaseBeforeRefresh || clamDatabaseNeedsRefresh(in: databaseDirectoryURL)
        var notes: [String] = [
            localized(
                "Using a local ClamAV signature store at \(databaseDirectory).",
                "Gebruikt een lokale ClamAV-signaturemap op \(databaseDirectory)."
            ),
            localized(
                "Using an app-local freshclam configuration so Homebrew's missing default config does not block signature updates.",
                "Gebruikt een app-lokale freshclam-configuratie zodat de ontbrekende standaardconfig van Homebrew updates van signatures niet blokkeert."
            )
        ]

        if needsRefresh {
            let refresh = await runStreamingShell(
                "\(shellQuote(freshclamPath)) --config-file=\(shellQuote(freshclamConfigURL.path)) --datadir=\(shellQuote(databaseDirectory)) --stdout",
                progressTaskID: taskID
            )

            if refresh.isSuccess {
                notes.append(
                    hadDatabaseBeforeRefresh
                        ? localized("ClamAV signatures were refreshed before scanning.", "ClamAV-signatures zijn vernieuwd voordat de scan begon.")
                        : localized("ClamAV signatures were downloaded before scanning.", "ClamAV-signatures zijn gedownload voordat de scan begon.")
                )
                let refreshOutput = refresh.combined.trimmingCharacters(in: .whitespacesAndNewlines)
                if !refreshOutput.isEmpty {
                    notes.append(refreshOutput)
                }
            } else if clamDatabaseExists(in: databaseDirectoryURL) {
                notes.append(
                    localized(
                        "ClamAV could not refresh the signatures right now, so the scan continues with the existing local database.",
                        "ClamAV kon de signatures nu niet verversen, dus de scan gaat verder met de bestaande lokale database."
                    )
                )
                let refreshOutput = refresh.combined.trimmingCharacters(in: .whitespacesAndNewlines)
                if !refreshOutput.isEmpty {
                    notes.append(refreshOutput)
                }
            } else {
                let refreshOutput = refresh.combined.trimmingCharacters(in: .whitespacesAndNewlines)
                return .failed(
                    CommandExecutionResult(
                        success: false,
                        summary: localized("ClamAV has no signatures yet.", "ClamAV heeft nog geen signatures."),
                        output: localized(
                            "The malware scanner could not download its virus database. Please check your internet connection and try the scan again.",
                            "De malwarescanner kon de virusdatabase niet downloaden. Controleer uw internetverbinding en probeer de scan opnieuw."
                        ) + (refreshOutput.isEmpty ? "" : "\n\n" + refreshOutput)
                    )
                )
            }
        } else {
            notes.append(
                localized(
                    "The local ClamAV signature database is already available, so the scan can start immediately.",
                    "De lokale ClamAV-signaturedatabase is al beschikbaar, dus de scan kan meteen starten."
                )
            )
        }

        guard clamDatabaseExists(in: databaseDirectoryURL) else {
            return .failed(
                CommandExecutionResult(
                    success: false,
                    summary: localized("ClamAV has no signatures yet.", "ClamAV heeft nog geen signatures."),
                    output: localized(
                        "No supported ClamAV database files were found after preparation. Try reinstalling clamav with Homebrew and run the scan again.",
                        "Na de voorbereiding zijn er geen ondersteunde ClamAV-databasebestanden gevonden. Probeer clamav opnieuw te installeren met Homebrew en voer de scan daarna opnieuw uit."
                    )
                )
            )
        }

        return .ready(
            ClamDatabasePreparation(
                databaseDirectory: databaseDirectory,
                output: notes.joined(separator: "\n")
            )
        )
    }

    private func clamDatabaseDirectory() throws -> URL {
        let appSupport = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )

        return appSupport
            .appendingPathComponent(AppBuildFlavor.appName, isDirectory: true)
            .appendingPathComponent("ClamAV", isDirectory: true)
            .appendingPathComponent("database", isDirectory: true)
    }

    private func ensureFreshclamConfig(for databaseDirectory: URL) throws -> URL {
        let supportDirectory = databaseDirectory.deletingLastPathComponent()
        try fileManager.createDirectory(at: supportDirectory, withIntermediateDirectories: true)

        let configURL = supportDirectory.appendingPathComponent("freshclam.conf")
        var lines = [
            "DatabaseDirectory \(databaseDirectory.path)",
            "DatabaseMirror database.clamav.net",
            "Checks 1",
            "Foreground yes"
        ]

        let username = NSUserName().trimmingCharacters(in: .whitespacesAndNewlines)
        if !username.isEmpty {
            lines.append("DatabaseOwner \(username)")
        }

        let config = lines.joined(separator: "\n") + "\n"
        try config.write(to: configURL, atomically: true, encoding: .utf8)
        return configURL
    }

    private func clamDatabaseExists(in directory: URL) -> Bool {
        !clamDatabaseFiles(in: directory).isEmpty
    }

    private func clamDatabaseNeedsRefresh(in directory: URL) -> Bool {
        let files = clamDatabaseFiles(in: directory)
        guard let newestDate = files
            .compactMap({ try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate })
            .max()
        else {
            return true
        }

        return Date().timeIntervalSince(newestDate) > clamDatabaseRefreshInterval
    }

    private func clamDatabaseFiles(in directory: URL) -> [URL] {
        let contents = (try? fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        )) ?? []

        return contents.filter { file in
            ["cvd", "cld", "cud"].contains(file.pathExtension.lowercased())
        }
    }

    private func clamScanTargets(from selectedComponents: [TaskScanComponent]) -> [String] {
        let explicitTargets = selectedComponents
            .flatMap(\.executionPaths)
            .filter { fileManager.fileExists(atPath: $0) }

        if !selectedComponents.isEmpty {
            return Array(NSOrderedSet(array: explicitTargets)) as? [String] ?? explicitTargets
        }

        let home = fileManager.homeDirectoryForCurrentUser.path
        let fallbackTargets = [
            "/Applications",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "\(home)/Applications",
            "\(home)/Downloads",
            "\(home)/Desktop",
            "\(home)/Library/Application Support",
            "\(home)/Library/LaunchAgents",
            "\(home)/Library/Preferences"
        ]

        return fallbackTargets.filter { fileManager.fileExists(atPath: $0) }
    }

    private func estimatedClamScanFileCount(in targets: [String]) -> Int {
        let uniqueTargets = Array(NSOrderedSet(array: targets)) as? [String] ?? targets
        var total = 0

        for target in uniqueTargets {
            let targetURL = URL(fileURLWithPath: target)
            let targetValues = try? targetURL.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey])

            if targetValues?.isSymbolicLink == true {
                continue
            }

            if targetValues?.isRegularFile == true {
                total += 1
                continue
            }

            guard targetValues?.isDirectory == true,
                  let enumerator = fileManager.enumerator(
                    at: targetURL,
                    includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey],
                    options: [],
                    errorHandler: { _, _ in true }
                  )
            else {
                continue
            }

            for case let fileURL as URL in enumerator {
                let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey])
                if values?.isSymbolicLink == true {
                    continue
                }
                if values?.isRegularFile == true {
                    total += 1
                }
            }
        }

        return total
    }

    private func condensedClamOutput(_ output: String) -> String {
        let lines = output
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        guard !lines.isEmpty else { return "" }

        let findings = lines.filter { $0.localizedCaseInsensitiveContains(" FOUND") || $0.localizedCaseInsensitiveContains(" ERROR") }
        let summaryIndex = lines.firstIndex { $0.localizedCaseInsensitiveContains("scan summary") }
        let summaryLines = summaryIndex.map { Array(lines[$0...]) } ?? []

        var sections: [String] = []
        if !findings.isEmpty {
            sections.append(findings.prefix(20).joined(separator: "\n"))
        }
        if !summaryLines.isEmpty {
            sections.append(summaryLines.joined(separator: "\n"))
        }

        if sections.isEmpty {
            return lines.suffix(12).joined(separator: "\n")
        }

        return sections.joined(separator: "\n\n")
    }

    private func parseMalwareScanOutcome(from output: String, targetTitles: [String]) -> MalwareScanOutcome {
        let threats = output
            .components(separatedBy: .newlines)
            .compactMap(parseMalwareThreat)

        let checkedFileCount = output
            .components(separatedBy: .newlines)
            .compactMap { line in
                trailingInteger(in: line.trimmingCharacters(in: .whitespacesAndNewlines), afterPrefix: "Scanned files:")
            }
            .last

        return MalwareScanOutcome(
            threats: uniqueThreats(threats),
            targetTitles: targetTitles,
            checkedFileCount: checkedFileCount
        )
    }

    private func parseMalwareThreat(_ rawLine: String) -> MalwareThreat? {
        let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
        guard line.localizedCaseInsensitiveContains(" FOUND"),
              let separator = line.firstIndex(of: ":")
        else {
            return nil
        }

        let path = String(line[..<separator]).trimmingCharacters(in: .whitespacesAndNewlines)
        let detail = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespacesAndNewlines)
        let signature = detail
            .replacingOccurrences(of: "FOUND", with: "", options: [.caseInsensitive])
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard !path.isEmpty, !signature.isEmpty else { return nil }

        return MalwareThreat(
            id: malwareThreatID(path: path, signature: signature),
            path: path,
            signature: signature
        )
    }

    private func malwareThreatID(path: String, signature: String) -> String {
        "\(path)|\(signature)"
    }

    private func uniqueThreats(_ threats: [MalwareThreat]) -> [MalwareThreat] {
        var seen = Set<String>()
        var ordered: [MalwareThreat] = []

        for threat in threats where seen.insert(threat.id).inserted {
            ordered.append(threat)
        }

        return ordered
    }

    private func trailingInteger(in line: String, afterPrefix prefix: String) -> Int? {
        guard line.hasPrefix(prefix) else { return nil }
        let remainder = line.dropFirst(prefix.count).trimmingCharacters(in: .whitespacesAndNewlines)
        let digits = remainder.components(separatedBy: CharacterSet.decimalDigits.inverted).joined()
        return Int(digits)
    }

    private func runShell(_ command: String, requiresAdmin: Bool) async -> ProcessOutput {
        let prepared = shellBootstrap + command

        if requiresAdmin {
            let source = "do shell script \"\(appleScriptEscape(prepared))\" with administrator privileges"
            return await runProcess(executable: "/usr/bin/osascript", arguments: ["-e", source])
        } else {
            return await runProcess(executable: "/bin/zsh", arguments: ["-c", prepared])
        }
    }

    private func runStreamingShell(_ command: String, progressTaskID: MaintenanceTaskID?) async -> ProcessOutput {
        let prepared = shellBootstrap + command
        return await runStreamingProcess(executable: "/bin/zsh", arguments: ["-c", prepared], progressTaskID: progressTaskID)
    }

    private func runAppleScript(_ script: String) async -> ProcessOutput {
        await runProcess(executable: "/usr/bin/osascript", arguments: ["-e", script])
    }

    private func runProcess(executable: String, arguments: [String]) async -> ProcessOutput {
        await withCheckedContinuation { continuation in
            let process = Process()
            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()

            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            process.standardOutput = stdoutPipe
            process.standardError = stderrPipe

            process.terminationHandler = { process in
                let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
                let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

                let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
                let stderr = String(data: stderrData, encoding: .utf8) ?? ""

                continuation.resume(returning: ProcessOutput(exitCode: process.terminationStatus, stdout: stdout, stderr: stderr))
            }

            do {
                try process.run()
            } catch {
                continuation.resume(returning: ProcessOutput(exitCode: 1, stdout: "", stderr: error.localizedDescription))
            }
        }
    }

    private func runStreamingProcess(executable: String, arguments: [String], progressTaskID: MaintenanceTaskID?) async -> ProcessOutput {
        await withCheckedContinuation { continuation in
            let process = Process()
            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()
            let collector = StreamingProcessCollector()

            let emit: @Sendable ([String]) -> Void = { lines in
                guard let progressTaskID else { return }
                for line in lines where !line.isEmpty {
                    emitMaintenanceProgressLine(line, taskID: progressTaskID)
                }
            }

            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            process.standardOutput = stdoutPipe
            process.standardError = stderrPipe

            stdoutPipe.fileHandleForReading.readabilityHandler = { handle in
                emit(collector.append(handle.availableData, isStdout: true))
            }

            stderrPipe.fileHandleForReading.readabilityHandler = { handle in
                emit(collector.append(handle.availableData, isStdout: false))
            }

            process.terminationHandler = { process in
                stdoutPipe.fileHandleForReading.readabilityHandler = nil
                stderrPipe.fileHandleForReading.readabilityHandler = nil

                emit(collector.append(stdoutPipe.fileHandleForReading.readDataToEndOfFile(), isStdout: true))
                emit(collector.append(stderrPipe.fileHandleForReading.readDataToEndOfFile(), isStdout: false))
                emit(collector.flushRemainder(isStdout: true))
                emit(collector.flushRemainder(isStdout: false))

                let outputs = collector.outputs()
                continuation.resume(returning: ProcessOutput(exitCode: process.terminationStatus, stdout: outputs.stdout, stderr: outputs.stderr))
            }

            do {
                try process.run()
            } catch {
                continuation.resume(returning: ProcessOutput(exitCode: 1, stdout: "", stderr: error.localizedDescription))
            }
        }
    }

    private func translate(_ result: ProcessOutput, success: String, failure: String) -> CommandExecutionResult {
        if isAdministratorPromptCancelled(result) {
            return CommandExecutionResult(
                success: false,
                summary: localized("Administrator access was cancelled.", "Beheerdersrechten zijn geannuleerd."),
                output: result.combined
            )
        }

        if isAutomationPermissionIssue(result) {
            return CommandExecutionResult(
                success: false,
                summary: localized("macOS blocked app automation for this step.", "macOS heeft app-automatisering voor deze stap geblokkeerd."),
                output: localized(
                    "Allow CleanMac Assistant to control the requested app in System Settings > Privacy & Security > Automation, then try again.",
                    "Sta CleanMac Assistant toe om de gevraagde app te bedienen via Systeeminstellingen > Privacy en beveiliging > Automatisering en probeer het daarna opnieuw."
                ) + (result.combined.isEmpty ? "" : "\n\n" + result.combined)
            )
        }

        return CommandExecutionResult(
            success: result.isSuccess,
            summary: result.isSuccess ? success : failure,
            output: result.combined
        )
    }

    private func claimer(for friendlyName: String, result: CommandExecutionResult) -> String {
        if result.success {
            return "\(friendlyName): \(result.summary)"
        } else {
            return "\(friendlyName): \(result.summary)\n\(result.output)"
        }
    }

    func resolveMalwareThreats(_ threats: [MalwareThreat], actions: [String: MalwareThreatActionChoice]) async -> [String: MalwareThreatResolution] {
        var results: [String: MalwareThreatResolution] = [:]

        for threat in threats {
            let action = actions[threat.id] ?? .quarantine
            results[threat.id] = await resolveMalwareThreat(threat, action: action)
        }

        return results
    }

    private func resolveMalwareThreat(_ threat: MalwareThreat, action: MalwareThreatActionChoice) async -> MalwareThreatResolution {
        switch action {
        case .ignore:
            return .ignored
        case .quarantine:
            return await quarantineMalwareThreat(threat)
        case .delete:
            return await deleteMalwareThreat(threat)
        }
    }

    private func quarantineMalwareThreat(_ threat: MalwareThreat) async -> MalwareThreatResolution {
        let sourceURL = URL(fileURLWithPath: threat.path)
        guard fileManager.fileExists(atPath: sourceURL.path) else {
            return .failed(message: localized("The file is no longer available at this path.", "Het bestand is niet langer beschikbaar op dit pad."))
        }

        do {
            let quarantineDirectory = try malwareQuarantineDirectory()
            try fileManager.createDirectory(at: quarantineDirectory, withIntermediateDirectories: true)

            let destinationURL = uniqueQuarantineDestination(for: sourceURL, in: quarantineDirectory)

            do {
                try fileManager.moveItem(at: sourceURL, to: destinationURL)
                return .quarantined(destination: destinationURL.path)
            } catch {
                if isPermissionError(error) {
                    let result = await runShell(
                        "mkdir -p \(shellQuote(quarantineDirectory.path)) && mv \(shellQuote(sourceURL.path)) \(shellQuote(destinationURL.path))",
                        requiresAdmin: true
                    )
                    if result.isSuccess {
                        return .quarantined(destination: destinationURL.path)
                    }
                    let message = result.combined.trimmingCharacters(in: .whitespacesAndNewlines)
                    return .failed(message: message.isEmpty ? localized("The file could not be moved to quarantine.", "Het bestand kon niet naar quarantaine worden verplaatst.") : message)
                }

                return .failed(message: error.localizedDescription)
            }
        } catch {
            return .failed(message: error.localizedDescription)
        }
    }

    private func deleteMalwareThreat(_ threat: MalwareThreat) async -> MalwareThreatResolution {
        let sourceURL = URL(fileURLWithPath: threat.path)
        guard fileManager.fileExists(atPath: sourceURL.path) else {
            return .failed(message: localized("The file is no longer available at this path.", "Het bestand is niet langer beschikbaar op dit pad."))
        }

        do {
            try fileManager.removeItem(at: sourceURL)
            return .deleted
        } catch {
            if isPermissionError(error) {
                let result = await runShell("rm -rf \(shellQuote(sourceURL.path))", requiresAdmin: true)
                let message = result.combined.trimmingCharacters(in: .whitespacesAndNewlines)
                return result.isSuccess
                    ? .deleted
                    : .failed(message: message.isEmpty ? localized("The threat could not be deleted.", "De dreiging kon niet worden verwijderd.") : message)
            }

            return .failed(message: error.localizedDescription)
        }
    }

    private func malwareQuarantineDirectory() throws -> URL {
        let appSupport = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )

        return appSupport
            .appendingPathComponent(AppBuildFlavor.appName, isDirectory: true)
            .appendingPathComponent("Quarantine", isDirectory: true)
    }

    private func uniqueQuarantineDestination(for sourceURL: URL, in quarantineDirectory: URL) -> URL {
        let baseName = sourceURL.deletingPathExtension().lastPathComponent
        let pathExtension = sourceURL.pathExtension
        var candidate = quarantineDirectory.appendingPathComponent(sourceURL.lastPathComponent)
        var counter = 2

        while fileManager.fileExists(atPath: candidate.path) {
            let numberedName = "\(baseName)-\(counter)"
            candidate = pathExtension.isEmpty
                ? quarantineDirectory.appendingPathComponent(numberedName)
                : quarantineDirectory.appendingPathComponent(numberedName).appendingPathExtension(pathExtension)
            counter += 1
        }

        return candidate
    }

    private func uninstallApplication(named rawName: String) async -> CommandExecutionResult {
        let trimmedInput = rawName.trimmingCharacters(in: .whitespacesAndNewlines)

        guard let appURL = locateInstalledApplication(named: trimmedInput) else {
            return CommandExecutionResult(
                success: false,
                summary: localized("The selected app could not be found on this Mac.", "De geselecteerde app kon niet op deze Mac worden gevonden."),
                output: ""
            )
        }

        let bundle = Bundle(url: appURL)
        let displayName = resolvedDisplayName(for: appURL, bundle: bundle)
        let bundleIdentifier = bundle?.bundleIdentifier
        let providedName = appURL.deletingPathExtension().lastPathComponent
        let leftoverPaths = commonLeftoverPaths(
            appNameVariants: appNameVariants(for: appURL, bundle: bundle, providedName: providedName),
            bundleIdentifier: bundleIdentifier
        )

        var outputLines: [String] = [
            localized("App bundle: \(appURL.lastPathComponent)", "Appbundle: \(appURL.lastPathComponent)")
        ]

        if let bundleIdentifier {
            outputLines.append(localized("Bundle ID: \(bundleIdentifier)", "Bundle-ID: \(bundleIdentifier)"))
        }

        do {
            try fileManager.removeItem(at: appURL)
            outputLines.append(
                localized(
                    "Removed the app bundle from Applications without administrator access.",
                    "De appbundle is zonder beheerdersrechten uit Applications verwijderd."
                )
            )
        } catch {
            if isPermissionError(error) {
                let result = await runShell("rm -rf \(shellQuote(appURL.path))", requiresAdmin: true)

                if isAdministratorPromptCancelled(result) {
                    return CommandExecutionResult(
                        success: false,
                        summary: localized("Administrator access was cancelled.", "Beheerdersrechten zijn geannuleerd."),
                        output: result.combined
                    )
                }

                guard result.isSuccess else {
                    return CommandExecutionResult(
                        success: false,
                        summary: localized("Failed to remove \(displayName).", "Het verwijderen van \(displayName) is mislukt."),
                        output: result.combined
                    )
                }

                outputLines.append(
                    localized(
                        "Removed the app bundle from Applications after requesting administrator access.",
                        "De appbundle is uit Applications verwijderd na het vragen om beheerdersrechten."
                    )
                )
            } else {
                return CommandExecutionResult(
                    success: false,
                    summary: localized("Failed to remove \(displayName).", "Het verwijderen van \(displayName) is mislukt."),
                    output: error.localizedDescription
                )
            }
        }

        let leftoversReport = removePaths(leftoverPaths, requiresAdmin: false)
        let removedLeftoverCount = leftoversReport.removedCount
        let protectedLeftoverCount = leftoversReport.protectedPaths.count
        let failedLeftoverCount = leftoversReport.failures.count

        if leftoverPaths.isEmpty || removedLeftoverCount == 0 && leftoversReport.missingPaths.count == leftoverPaths.count {
            outputLines.append(
                localized(
                    "No common leftover files were found in your user Library.",
                    "Er zijn geen gebruikelijke restbestanden gevonden in uw gebruikersbibliotheek."
                )
            )
        } else if removedLeftoverCount > 0 {
            outputLines.append(
                localized(
                    "Removed \(removedLeftoverCount) common leftover item(s) from your user Library.",
                    "\(removedLeftoverCount) gebruikelijke restbestand(en) uit uw gebruikersbibliotheek verwijderd."
                )
            )
        }

        if protectedLeftoverCount > 0 {
            outputLines.append(
                localized(
                    "Some leftovers were skipped because macOS protects those locations.",
                    "Sommige restbestanden zijn overgeslagen omdat macOS die locaties beschermt."
                )
            )
            outputLines.append(permissionGuidance(for: .generic))
            outputLines.append(contentsOf: abbreviatedProtectedPathLines(leftoversReport.protectedPaths))
        }

        if failedLeftoverCount > 0 {
            outputLines.append(localized("Some leftovers still need manual cleanup:", "Sommige restbestanden moeten nog handmatig worden opgeschoond:"))
            outputLines.append(contentsOf: leftoversReport.failures.prefix(6))
        }

        let summary: String
        if failedLeftoverCount > 0 {
            summary = localized(
                "\(displayName) was removed, but some leftovers still need attention.",
                "\(displayName) is verwijderd, maar sommige restbestanden vragen nog aandacht."
            )
        } else if protectedLeftoverCount > 0 {
            summary = localized(
                "\(displayName) was removed, but some protected leftovers were skipped.",
                "\(displayName) is verwijderd, maar sommige beschermde restbestanden zijn overgeslagen."
            )
        } else if removedLeftoverCount > 0 {
            summary = localized(
                "\(displayName) and common leftovers were removed.",
                "\(displayName) en gebruikelijke restbestanden zijn verwijderd."
            )
        } else {
            summary = localized(
                "\(displayName) was removed.",
                "\(displayName) is verwijderd."
            )
        }

        return CommandExecutionResult(
            success: failedLeftoverCount == 0,
            summary: summary,
            output: outputLines.joined(separator: "\n")
        )
    }

    private func locateInstalledApplication(named rawName: String) -> URL? {
        let trimmed = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("/") {
            let directURL = URL(fileURLWithPath: trimmed, isDirectory: true)
            if fileManager.fileExists(atPath: directURL.path), directURL.pathExtension == "app" {
                return directURL
            }
        }

        let normalizedName = normalizedApplicationName(trimmed)
        let applicationRoots = [
            URL(fileURLWithPath: "/Applications", isDirectory: true),
            fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Applications", isDirectory: true)
        ]

        for root in applicationRoots where fileManager.fileExists(atPath: root.path) {
            let exactURL = root.appendingPathComponent(normalizedName + ".app", isDirectory: true)
            if fileManager.fileExists(atPath: exactURL.path) {
                return exactURL
            }

            let contents = (try? fileManager.contentsOfDirectory(at: root, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles])) ?? []
            if let match = contents.first(where: { candidate in
                candidate.pathExtension == "app"
                    && candidate.deletingPathExtension().lastPathComponent.compare(normalizedName, options: [.caseInsensitive, .diacriticInsensitive]) == .orderedSame
            }) {
                return match
            }
        }

        return nil
    }

    private func normalizedApplicationName(_ rawName: String) -> String {
        let trimmed = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasSuffix(".app") {
            return String(trimmed.dropLast(4))
        }
        return trimmed
    }

    private func resolvedDisplayName(for appURL: URL, bundle: Bundle?) -> String {
        (bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
            ?? (bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String)
            ?? appURL.deletingPathExtension().lastPathComponent
    }

    private func appNameVariants(for appURL: URL, bundle: Bundle?, providedName: String) -> [String] {
        let candidates = [
            normalizedApplicationName(providedName),
            appURL.deletingPathExtension().lastPathComponent,
            bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String,
            bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String
        ]

        var ordered: [String] = []
        var seen = Set<String>()

        for name in candidates
            .compactMap({ $0?.trimmingCharacters(in: .whitespacesAndNewlines) })
            .filter({ !$0.isEmpty })
        {
            let key = name.lowercased()
            if seen.insert(key).inserted {
                ordered.append(name)
            }
        }

        return ordered
    }

    private func commonLeftoverPaths(appNameVariants: [String], bundleIdentifier: String?) -> [String] {
        let homeURL = fileManager.homeDirectoryForCurrentUser
        var paths = Set<String>()

        let namedRoots = [
            homeURL.appendingPathComponent("Library/Application Support", isDirectory: true),
            homeURL.appendingPathComponent("Library/Caches", isDirectory: true),
            homeURL.appendingPathComponent("Library/Logs", isDirectory: true)
        ]

        for root in namedRoots {
            exactMatches(in: root, candidateNames: appNameVariants).forEach { paths.insert($0) }
        }

        let preferencesURL = homeURL.appendingPathComponent("Library/Preferences", isDirectory: true)
        exactMatches(in: preferencesURL, candidateNames: appNameVariants).forEach { paths.insert($0) }

        if let bundleIdentifier {
            let exactRelativePaths = [
                "Library/Application Support/\(bundleIdentifier)",
                "Library/Caches/\(bundleIdentifier)",
                "Library/Logs/\(bundleIdentifier)",
                "Library/Preferences/\(bundleIdentifier).plist",
                "Library/Saved Application State/\(bundleIdentifier).savedState",
                "Library/Containers/\(bundleIdentifier)",
                "Library/WebKit/\(bundleIdentifier)",
                "Library/HTTPStorages/\(bundleIdentifier)"
            ]

            for relativePath in exactRelativePaths {
                let url = homeURL.appendingPathComponent(relativePath)
                if fileManager.fileExists(atPath: url.path) {
                    paths.insert(url.path)
                }
            }

            let byHostPreferencesURL = homeURL.appendingPathComponent("Library/Preferences/ByHost", isDirectory: true)
            prefixMatches(in: byHostPreferencesURL, prefix: bundleIdentifier + ".").forEach { paths.insert($0) }
        }

        return paths.sorted()
    }

    private func exactMatches(in directory: URL, candidateNames: [String]) -> [String] {
        let loweredNames = Set(candidateNames.map { $0.lowercased() })
        guard !loweredNames.isEmpty else { return [] }

        let children = (try? fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles])) ?? []
        return children.compactMap { child in
            let lastPathComponent = child.lastPathComponent.lowercased()
            let stem = child.deletingPathExtension().lastPathComponent.lowercased()
            if loweredNames.contains(lastPathComponent) || loweredNames.contains(stem) {
                return child.path
            }
            return nil
        }
    }

    private func prefixMatches(in directory: URL, prefix: String) -> [String] {
        let loweredPrefix = prefix.lowercased()
        let children = (try? fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles])) ?? []
        return children.compactMap { child in
            child.lastPathComponent.lowercased().hasPrefix(loweredPrefix) ? child.path : nil
        }
    }

    private func cleanupScope(for component: TaskScanComponent) -> String {
        var details: [String] = []

        if let reclaimableBytes = component.reclaimableBytes, reclaimableBytes > 0 {
            details.append(localized("about \(byteFormatter.string(fromByteCount: reclaimableBytes))", "ongeveer \(byteFormatter.string(fromByteCount: reclaimableBytes))"))
        }

        if let itemCount = component.itemCount, itemCount > 0 {
            let itemLabel = itemCount == 1 ? localized("1 item", "1 item") : localized("\(itemCount) items", "\(itemCount) items")
            details.append(itemLabel)
        }

        guard !details.isEmpty else {
            return localized("for the selected part", "voor het geselecteerde onderdeel")
        }

        return localized("for ", "voor ") + details.joined(separator: localized(" across ", " verdeeld over "))
    }

    private func shellQuote(_ raw: String) -> String {
        "'" + raw.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    private func appleScriptEscape(_ raw: String) -> String {
        raw
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }

    private func removePaths(_ paths: [String], requiresAdmin: Bool) -> FileRemovalReport {
        guard !requiresAdmin else {
            return FileRemovalReport(failures: [localized("This cleanup path still expects administrator access.", "Dit opschoonpad verwacht nog steeds beheerdersrechten.")])
        }

        var report = FileRemovalReport()
        for path in paths {
            removeSinglePath(path, report: &report)
        }
        return report
    }

    private func removeDirectoryContents(at path: String, requiresAdmin: Bool) -> FileRemovalReport {
        guard !requiresAdmin else {
            return FileRemovalReport(failures: [localized("This cleanup path still expects administrator access.", "Dit opschoonpad verwacht nog steeds beheerdersrechten.")])
        }

        var report = FileRemovalReport()
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory), isDirectory.boolValue else {
            report.missingPaths.append(path)
            return report
        }

        do {
            let children = try fileManager.contentsOfDirectory(atPath: path)
            if children.isEmpty {
                return report
            }

            for child in children {
                let childPath = URL(fileURLWithPath: path).appendingPathComponent(child).path
                removeSinglePath(childPath, report: &report)
            }
        } catch {
            if isPermissionError(error) {
                report.protectedPaths.append(path)
            } else {
                report.failures.append("\(path): \(error.localizedDescription)")
            }
        }

        return report
    }

    private func removeSinglePath(_ path: String, report: inout FileRemovalReport) {
        guard fileManager.fileExists(atPath: path) else {
            report.missingPaths.append(path)
            return
        }

        do {
            try fileManager.removeItem(atPath: path)
            report.removedCount += 1
        } catch {
            if isPermissionError(error) {
                report.protectedPaths.append(path)
            } else {
                report.failures.append("\(path): \(error.localizedDescription)")
            }
        }
    }

    private func removalStatus(for component: TaskScanComponent, report: FileRemovalReport, area: ProtectedResourceArea) async -> ComponentCleanupStatus {
        if !report.failures.isEmpty {
            let failureList = report.failures.prefix(6).joined(separator: "\n")
            return .failure(
                "\(component.title.appLocalized): \(localized("failed", "mislukt")).\n\(failureList)"
            )
        }

        let protectedCount = report.protectedPaths.count
        let removedCount = report.removedCount

        if protectedCount > 0 && removedCount > 0 {
            var lines: [String] = [
                "\(component.title.appLocalized): \(localized("partially cleaned", "gedeeltelijk opgeschoond")) \(cleanupScope(for: component)).",
                localized("Removed \(removedCount) item(s).", "\(removedCount) item(s) verwijderd."),
                localized("Skipped \(protectedCount) protected item(s).", "\(protectedCount) beschermd(e) item(s) overgeslagen."),
                permissionGuidance(for: area)
            ]
            lines.append(contentsOf: abbreviatedProtectedPathLines(report.protectedPaths))
            return .warning(lines.joined(separator: "\n"))
        }

        if protectedCount > 0 {
            var lines: [String] = [
                "\(component.title.appLocalized): \(localized("access needed", "toegang nodig")).",
                localized("No changes were made because macOS protected this area.", "Er zijn geen wijzigingen gedaan omdat macOS dit gebied beschermt."),
                permissionGuidance(for: area)
            ]
            lines.append(contentsOf: abbreviatedProtectedPathLines(report.protectedPaths))
            return .failure(lines.joined(separator: "\n"))
        }

        if removedCount == 0 && !report.missingPaths.isEmpty {
            return .success(
                "\(component.title.appLocalized): \(localized("was already clear.", "was al leeg."))"
            )
        }

        return .success(
            "\(component.title.appLocalized): \(localized("cleaned", "opgeschoond")) \(cleanupScope(for: component))."
        )
    }

    private func cleanupStatus(for result: ProcessOutput, component: TaskScanComponent, protectedArea: ProtectedResourceArea?) -> ComponentCleanupStatus {
        if result.isSuccess {
            return .success(
                "\(component.title.appLocalized): \(localized("cleaned", "opgeschoond")) \(cleanupScope(for: component))."
            )
        }

        if let protectedArea, isPermissionBlocked(result) {
            var lines: [String] = [
                "\(component.title.appLocalized): \(localized("access needed", "toegang nodig")).",
                permissionGuidance(for: protectedArea)
            ]

            let diagnostics = result.combined.trimmingCharacters(in: .whitespacesAndNewlines)
            if !diagnostics.isEmpty {
                lines.append(diagnostics)
            }

            return .failure(lines.joined(separator: "\n"))
        }

        return .failure(
            "\(component.title.appLocalized): \(localized("failed", "mislukt")).\n\(result.combined)"
        )
    }

    private func protectedResourceArea(for paths: [String]) -> ProtectedResourceArea {
        let joined = paths.joined(separator: "\n").lowercased()
        if joined.contains("/.trash") {
            return .trash
        }
        if joined.contains("/library/safari/") {
            return .safari
        }
        if joined.contains("/library/messages") {
            return .messages
        }
        if joined.contains("com.apple.mail") || joined.contains("/mail downloads") {
            return .mail
        }
        if joined.contains("/library/cookies") || joined.contains("/chrome/default/cookies") || joined.contains("cookies.sqlite") {
            return .cookies
        }
        if joined.contains("/library/caches") {
            return .caches
        }
        return .generic
    }

    private func protectedResourceArea(forCommand command: String) -> ProtectedResourceArea? {
        let lowered = command.lowercased()
        if lowered.contains("messages/chat.db") {
            return .messages
        }
        if lowered.contains("cookies") {
            return .cookies
        }
        if lowered.contains("/library/safari/") {
            return .safari
        }
        return nil
    }

    private func permissionGuidance(for area: ProtectedResourceArea) -> String {
        switch area {
        case .trash:
            return localized(
                "Grant CleanMac Assistant Full Disk Access in System Settings > Privacy & Security > Full Disk Access to let the app empty Trash reliably on newer macOS versions.",
                "Geef CleanMac Assistant volledige schijftoegang via Systeeminstellingen > Privacy en beveiliging > Volledige schijftoegang zodat de app de prullenmand op nieuwere macOS-versies betrouwbaar kan legen."
            )
        case .safari:
            return localized(
                "Safari data is protected by macOS. Grant Full Disk Access to CleanMac Assistant and close Safari before trying again.",
                "Safari-gegevens worden door macOS beschermd. Geef CleanMac Assistant volledige schijftoegang en sluit Safari voordat u het opnieuw probeert."
            )
        case .messages:
            return localized(
                "Messages data is protected by macOS. Grant Full Disk Access to CleanMac Assistant before trying again.",
                "Berichten-gegevens worden door macOS beschermd. Geef CleanMac Assistant volledige schijftoegang voordat u het opnieuw probeert."
            )
        case .mail:
            return localized(
                "Mail data is protected by macOS. Grant Full Disk Access to CleanMac Assistant before trying again.",
                "Mail-gegevens worden door macOS beschermd. Geef CleanMac Assistant volledige schijftoegang voordat u het opnieuw probeert."
            )
        case .cookies:
            return localized(
                "Browser data can be protected by macOS. Grant Full Disk Access to CleanMac Assistant before trying again.",
                "Browsergegevens kunnen door macOS worden beschermd. Geef CleanMac Assistant volledige schijftoegang voordat u het opnieuw probeert."
            )
        case .caches:
            return localized(
                "Some macOS-managed caches are protected. CleanMac Assistant can skip them safely, or you can grant Full Disk Access for deeper cleanup.",
                "Sommige door macOS beheerde caches zijn beschermd. CleanMac Assistant kan ze veilig overslaan, of u kunt volledige schijftoegang geven voor diepere opschoning."
            )
        case .generic:
            return localized(
                "macOS blocked this location. Grant CleanMac Assistant Full Disk Access in System Settings > Privacy & Security > Full Disk Access, then try again.",
                "macOS blokkeerde deze locatie. Geef CleanMac Assistant volledige schijftoegang via Systeeminstellingen > Privacy en beveiliging > Volledige schijftoegang en probeer het daarna opnieuw."
            )
        }
    }

    private func abbreviatedProtectedPathLines(_ paths: [String]) -> [String] {
        guard !paths.isEmpty else { return [] }
        var lines = [localized("Protected items:", "Beschermde items:")]
        lines.append(contentsOf: paths.prefix(5).map { "• \($0)" })
        if paths.count > 5 {
            lines.append(localized("• and more…", "• en meer…"))
        }
        return lines
    }

    private func isPermissionError(_ error: Error) -> Bool {
        let nsError = error as NSError
        if nsError.domain == NSCocoaErrorDomain && (nsError.code == NSFileReadNoPermissionError || nsError.code == NSFileWriteNoPermissionError || nsError.code == 257 || nsError.code == 513) {
            return true
        }
        if nsError.domain == NSPOSIXErrorDomain && (nsError.code == 1 || nsError.code == 13) {
            return true
        }

        let message = nsError.localizedDescription.lowercased()
        return message.contains("operation not permitted") || message.contains("permission denied") || message.contains("not permitted")
    }

    private func isPermissionBlocked(_ result: ProcessOutput) -> Bool {
        let combined = result.combined.lowercased()
        return combined.contains("operation not permitted")
            || combined.contains("permission denied")
            || combined.contains("unable to open database")
    }

    private func isAdministratorPromptCancelled(_ result: ProcessOutput) -> Bool {
        let combined = result.combined.lowercased()
        return combined.contains("user canceled")
    }

    private func isAutomationPermissionIssue(_ result: ProcessOutput) -> Bool {
        let combined = result.combined.lowercased()
        return combined.contains("not authorized to send apple events")
            || combined.contains("not permitted to send keystrokes")
            || combined.contains("automation")
    }
}
