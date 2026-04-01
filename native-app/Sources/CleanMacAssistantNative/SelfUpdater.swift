import Foundation

struct AppUpdateOffer: Identifiable, Equatable {
    let version: String
    let notes: String
    let downloadURL: URL?

    var id: String { version }
}

enum AppUpdateInstallState: Equatable {
    case idle
    case downloading(version: String)
    case preparing(version: String)
    case installing(version: String)
    case failed(version: String, message: String)

    var isPresented: Bool {
        switch self {
        case .idle:
            return false
        case .downloading, .preparing, .installing, .failed:
            return true
        }
    }

    var progressValue: Double {
        switch self {
        case .idle:
            return 0
        case .downloading:
            return 0.32
        case .preparing:
            return 0.68
        case .installing:
            return 0.94
        case .failed:
            return 1
        }
    }

    var version: String? {
        switch self {
        case .idle:
            return nil
        case let .downloading(version),
             let .preparing(version),
             let .installing(version),
             let .failed(version, _):
            return version
        }
    }

    var isFailure: Bool {
        if case .failed = self {
            return true
        }
        return false
    }
}

struct PreparedAppUpdateInstallation {
    let launcherScriptURL: URL

    func launch() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = [
            "-lc",
            "nohup \(shellEscaped(launcherScriptURL.path)) >/dev/null 2>&1 &"
        ]
        try process.run()
    }

    private func shellEscaped(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }
}

struct AppSelfUpdater {
    func prepareInstallation(
        from downloadURL: URL,
        version: String,
        currentAppURL: URL,
        expectedAppName: String
    ) async throws -> PreparedAppUpdateInstallation {
        guard currentAppURL.pathExtension == "app" else {
            throw SelfUpdateError.packagedAppRequired
        }

        if currentAppURL.path.hasPrefix("/Volumes/") {
            throw SelfUpdateError.installedLocationRequired
        }

        let fileManager = FileManager.default
        let workingDirectory = fileManager.temporaryDirectory
            .appendingPathComponent("CleanMacAssistantUpdate-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: workingDirectory, withIntermediateDirectories: true)

        let downloadedArchiveURL = try await downloadArchive(from: downloadURL, into: workingDirectory)
        let archiveExtension = downloadedArchiveURL.pathExtension.lowercased()

        switch archiveExtension {
        case "dmg":
            let mountedVolumeURL = try mountDiskImage(at: downloadedArchiveURL)
            let replacementAppURL = try locateAppBundle(
                in: mountedVolumeURL,
                expectedAppName: expectedAppName
            )
            try verifyAppBundle(at: replacementAppURL)
            let launcherScriptURL = try writeLauncherScript(
                workingDirectory: workingDirectory,
                currentAppURL: currentAppURL,
                replacementAppURL: replacementAppURL,
                mountedVolumeURL: mountedVolumeURL,
                downloadedArchiveURL: downloadedArchiveURL
            )
            return PreparedAppUpdateInstallation(launcherScriptURL: launcherScriptURL)

        case "zip":
            let extractedURL = try extractZip(at: downloadedArchiveURL, into: workingDirectory)
            let replacementAppURL = try locateAppBundle(
                in: extractedURL,
                expectedAppName: expectedAppName
            )
            try verifyAppBundle(at: replacementAppURL)
            let launcherScriptURL = try writeLauncherScript(
                workingDirectory: workingDirectory,
                currentAppURL: currentAppURL,
                replacementAppURL: replacementAppURL,
                mountedVolumeURL: nil,
                downloadedArchiveURL: downloadedArchiveURL
            )
            return PreparedAppUpdateInstallation(launcherScriptURL: launcherScriptURL)

        default:
            throw SelfUpdateError.unsupportedArchiveType
        }
    }

    private func downloadArchive(from remoteURL: URL, into workingDirectory: URL) async throws -> URL {
        let (temporaryURL, response) = try await URLSession.shared.download(from: remoteURL)

        if let httpResponse = response as? HTTPURLResponse, !(200...299).contains(httpResponse.statusCode) {
            throw SelfUpdateError.downloadFailed
        }

        let pathExtension = remoteURL.pathExtension.isEmpty ? "dmg" : remoteURL.pathExtension
        let destinationURL = workingDirectory.appendingPathComponent("update.\(pathExtension)")

        try? FileManager.default.removeItem(at: destinationURL)
        try FileManager.default.moveItem(at: temporaryURL, to: destinationURL)
        return destinationURL
    }

    private func mountDiskImage(at archiveURL: URL) throws -> URL {
        let plistData = try runTool(
            "/usr/bin/hdiutil",
            arguments: ["attach", "-nobrowse", "-readonly", "-plist", archiveURL.path]
        )

        guard
            let plist = try PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any],
            let entities = plist["system-entities"] as? [[String: Any]],
            let mountPath = entities.compactMap({ $0["mount-point"] as? String }).first
        else {
            throw SelfUpdateError.mountFailed
        }

        return URL(fileURLWithPath: mountPath, isDirectory: true)
    }

    private func extractZip(at archiveURL: URL, into workingDirectory: URL) throws -> URL {
        let extractDirectory = workingDirectory.appendingPathComponent("extracted", isDirectory: true)
        try FileManager.default.createDirectory(at: extractDirectory, withIntermediateDirectories: true)
        _ = try runTool(
            "/usr/bin/ditto",
            arguments: ["-x", "-k", archiveURL.path, extractDirectory.path]
        )
        return extractDirectory
    }

    private func locateAppBundle(in rootURL: URL, expectedAppName: String) throws -> URL {
        let fileManager = FileManager.default

        if let enumerator = fileManager.enumerator(at: rootURL, includingPropertiesForKeys: [.isDirectoryKey]) {
            for case let candidateURL as URL in enumerator {
                guard candidateURL.pathExtension == "app" else { continue }

                if candidateURL.deletingPathExtension().lastPathComponent == expectedAppName {
                    return candidateURL
                }
            }
        }

        throw SelfUpdateError.appBundleMissing
    }

    private func verifyAppBundle(at appURL: URL) throws {
        _ = try runTool(
            "/usr/bin/codesign",
            arguments: ["--verify", "--deep", "--strict", appURL.path]
        )
    }

    private func writeLauncherScript(
        workingDirectory: URL,
        currentAppURL: URL,
        replacementAppURL: URL,
        mountedVolumeURL: URL?,
        downloadedArchiveURL: URL
    ) throws -> URL {
        let scriptURL = workingDirectory.appendingPathComponent("install-update.sh")
        let currentPID = ProcessInfo.processInfo.processIdentifier
        let tempInstallURL = currentAppURL.deletingLastPathComponent()
            .appendingPathComponent("\(currentAppURL.lastPathComponent).updating")
        let backupInstallURL = currentAppURL.deletingLastPathComponent()
            .appendingPathComponent("\(currentAppURL.lastPathComponent).backup")

        let mountDetachLine: String
        if let mountedVolumeURL {
            mountDetachLine = "/usr/bin/hdiutil detach \(shellEscaped(mountedVolumeURL.path)) -quiet || true"
        } else {
            mountDetachLine = ":"
        }

        let script = """
        #!/bin/zsh
        set -euo pipefail

        APP_PID=\(currentPID)
        CURRENT_APP=\(shellEscaped(currentAppURL.path))
        REPLACEMENT_APP=\(shellEscaped(replacementAppURL.path))
        TEMP_APP=\(shellEscaped(tempInstallURL.path))
        BACKUP_APP=\(shellEscaped(backupInstallURL.path))
        WORKING_DIR=\(shellEscaped(workingDirectory.path))
        DOWNLOADED_ARCHIVE=\(shellEscaped(downloadedArchiveURL.path))

        for _ in {1..180}; do
          if ! kill -0 "$APP_PID" 2>/dev/null; then
            break
          fi
          sleep 0.5
        done

        /bin/rm -rf "$TEMP_APP"
        /bin/rm -rf "$BACKUP_APP"
        /usr/bin/ditto "$REPLACEMENT_APP" "$TEMP_APP"
        /bin/mv "$CURRENT_APP" "$BACKUP_APP"

        if /bin/mv "$TEMP_APP" "$CURRENT_APP"; then
          /bin/rm -rf "$BACKUP_APP"
        else
          /bin/rm -rf "$CURRENT_APP" 2>/dev/null || true
          /bin/mv "$BACKUP_APP" "$CURRENT_APP" 2>/dev/null || true
          /usr/bin/open "$CURRENT_APP" 2>/dev/null || true
          exit 1
        fi

        /usr/bin/xattr -dr com.apple.quarantine "$CURRENT_APP" 2>/dev/null || true
        \(mountDetachLine)
        /bin/rm -f "$DOWNLOADED_ARCHIVE" 2>/dev/null || true
        /usr/bin/open "$CURRENT_APP"
        /bin/rm -rf "$WORKING_DIR" 2>/dev/null || true
        """

        try script.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: Int16(0o755))],
            ofItemAtPath: scriptURL.path
        )
        return scriptURL
    }

    private func runTool(_ launchPath: String, arguments: [String]) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        try process.run()
        process.waitUntilExit()

        let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

        guard process.terminationStatus == 0 else {
            let errorMessage = String(decoding: errorData.isEmpty ? outputData : errorData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            throw SelfUpdateError.toolFailed(message: errorMessage)
        }

        return outputData
    }

    private func shellEscaped(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }
}

private enum SelfUpdateError: LocalizedError {
    case packagedAppRequired
    case installedLocationRequired
    case downloadFailed
    case mountFailed
    case unsupportedArchiveType
    case appBundleMissing
    case toolFailed(message: String)

    var errorDescription: String? {
        switch self {
        case .packagedAppRequired:
            return localized(
                "Automatic updates only work from the packaged app build.",
                "Automatische updates werken alleen vanuit de verpakte appbuild."
            )
        case .installedLocationRequired:
            return localized(
                "Move CleanMac Assistant out of the mounted disk image and into Applications before using automatic updates.",
                "Verplaats CleanMac Assistant eerst uit de gemounte schijfkopie naar Programma's voordat u automatische updates gebruikt."
            )
        case .downloadFailed:
            return localized(
                "The update download could not be completed.",
                "De updatedownload kon niet worden voltooid."
            )
        case .mountFailed:
            return localized(
                "The downloaded update could not be opened.",
                "De gedownloade update kon niet worden geopend."
            )
        case .unsupportedArchiveType:
            return localized(
                "This update format is not yet supported for hands-off installation.",
                "Dit updateformaat wordt nog niet ondersteund voor handsfree installatie."
            )
        case .appBundleMissing:
            return localized(
                "No app bundle was found inside the downloaded update.",
                "Er is geen appbundle gevonden in de gedownloade update."
            )
        case let .toolFailed(message):
            if message.isEmpty {
                return localized(
                    "The updater helper could not finish the install.",
                    "De updatehulp kon de installatie niet afronden."
                )
            }

            return localized(
                "The updater helper could not finish the install.\n\n\(message)",
                "De updatehulp kon de installatie niet afronden.\n\n\(message)"
            )
        }
    }
}
