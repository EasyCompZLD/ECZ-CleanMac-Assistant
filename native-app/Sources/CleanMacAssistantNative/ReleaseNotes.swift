import Foundation

struct AppReleaseNoteEntry: Identifiable {
    let version: String
    let englishBody: String
    let dutchBody: String

    var id: String { version }

    var updateNotes: String {
        localized("What's new\n\(englishBody)", "Wat is er nieuw\n\(dutchBody)")
    }

    var aboutNotes: String {
        localized("Version \(version)\n\(englishBody)", "Versie \(version)\n\(dutchBody)")
    }
}

enum AppReleaseNotes {
    static let entries: [AppReleaseNoteEntry] = [
        AppReleaseNoteEntry(
            version: "1.0.21",
            englishBody: "• The malware progress ring and bar now reflect the scan itself once the selected files have been counted, instead of feeling stuck at the broader task step\n• The ClamAV flow now counts the selected scan scope first so the checked-files counter, percentage, and ETA have a real baseline\n• The live progress header switches to scan-focused wording during malware checks so it is clearer that you are looking at scan completion, not only overall page progress\n• Release notes and packaging were refreshed for the truer malware scan progress pass",
            dutchBody: "• De malware-voortgangsring en -balk volgen nu de scan zelf zodra de geselecteerde bestanden zijn geteld, in plaats van alleen vast te lijken zitten op de bredere taakstap\n• De ClamAV-flow telt nu eerst het gekozen scangebied zodat de teller van gecontroleerde bestanden, het percentage en de ETA een echte basis hebben\n• De live voortgangskop schakelt tijdens malwarecontroles nu naar scan-gerichte tekst zodat duidelijker is dat u naar scanvoltooiing kijkt en niet alleen naar algemene paginavoortgang\n• Release-notes en packaging zijn vernieuwd voor deze nauwkeurigere malware-voortgangspass"
        ),
        AppReleaseNoteEntry(
            version: "1.0.20",
            englishBody: "• Malware detections that appear during the live ClamAV scan now stay available for the final threat review instead of disappearing when the run ends\n• Live malware detection IDs now match the final review IDs more closely, so ignored items and newly found items behave more consistently\n• When you choose a narrower malware scope such as Applications only, the scan no longer falls back to broader default locations behind your back\n• The malware summary now clearly echoes the exact areas you selected before the scan started",
            dutchBody: "• Malwaredetecties die tijdens de live ClamAV-scan verschijnen blijven nu beschikbaar voor de uiteindelijke dreigingscontrole in plaats van te verdwijnen zodra de run eindigt\n• Live malwaredetectie-ID's sluiten nu beter aan op de uiteindelijke controle-ID's, zodat genegeerde en nieuw gevonden items consistenter werken\n• Wanneer u een smallere malwarescope kiest, zoals alleen Apps, valt de scan niet meer ongemerkt terug op bredere standaardlocaties\n• De malwaresamenvatting noemt nu duidelijk de exacte gebieden die u hebt geselecteerd voordat de scan begon"
        ),
        AppReleaseNoteEntry(
            version: "1.0.19",
            englishBody: "• Live maintenance runs now show clearer timing with elapsed time, a running ETA, and an estimated finish time in the full-screen progress workspace\n• Task cards now use more consistent estimated durations so every maintenance action feels easier to judge before you start it\n• Malware and other longer-running tasks keep their current-item progress visible while the ETA adjusts as the run unfolds\n• Release notes and packaging were refreshed for the richer progress timing pass",
            dutchBody: "• Live onderhoudsruns tonen nu duidelijkere timing met verstreken tijd, een doorlopende ETA en een geschatte eindtijd in de schermvullende voortgangswerkruimte\n• Taakkaarten gebruiken nu consistentere geschatte duur zodat elke onderhoudsactie vooraf makkelijker is in te schatten\n• Malware- en andere langer lopende taken houden hun huidige-item-voortgang zichtbaar terwijl de ETA zich tijdens de run aanpast\n• Release-notes en packaging zijn vernieuwd voor deze rijkere voortgangs- en timingpass"
        ),
        AppReleaseNoteEntry(
            version: "1.0.18",
            englishBody: "• Release and developer update channels are now separated more safely so builds no longer cross-update by accident\n• Page-wide runs now stop and open Review when a task still needs confirmation instead of silently skipping it later\n• Malware results now stay in an attention state until you finish threat actions, and ignored detections can stay ignored across future scans\n• The Files page no longer auto-kicks heavy scans on open, while uninstall actions now refresh the installed-app list more reliably",
            dutchBody: "• Release- en ontwikkelupdates zijn nu veiliger van elkaar gescheiden zodat builds niet per ongeluk naar elkaar updaten\n• Paginabrede runs stoppen nu eerst in Bekijken wanneer een taak nog bevestiging nodig heeft, in plaats van die later stilletjes over te slaan\n• Malware-resultaten blijven nu in een aandachtstatus totdat dreigingsacties zijn afgerond, en genegeerde detecties kunnen bij volgende scans genegeerd blijven\n• De Bestanden-pagina start geen zware scans meer automatisch bij openen, terwijl de lijst met geïnstalleerde apps na verwijderen betrouwbaarder ververst"
        ),
        AppReleaseNoteEntry(
            version: "1.0.17",
            englishBody: "• Malware Scan now lets you choose focused scan areas before ClamAV starts, similar to a proper security review flow\n• The live progress overlay now keeps a dedicated possible-threats card visible beside the active scan status\n• After the scan finishes, detections are shown as cards with per-threat actions for Ignore, Quarantine, or Delete\n• Release notes and packaging were refreshed for the fuller malware response workflow",
            dutchBody: "• Malwarescan laat u nu vooraf gerichte scangebieden kiezen voordat ClamAV start, vergelijkbaar met een echte beveiligingscontroleflow\n• De live-voortgangsoverlay houdt nu een aparte kaart met mogelijke dreigingen zichtbaar naast de actieve scanstatus\n• Na afloop van de scan worden detecties als kaarten getoond met per dreiging acties voor Negeren, Quarantaine of Verwijderen\n• Release-notes en packaging zijn vernieuwd voor deze vollere malware-responsflow"
        ),
        AppReleaseNoteEntry(
            version: "1.0.16",
            englishBody: "• Malware Scan now shows a clearer live workspace with the current scan target, recent ClamAV lines, and a growing checked-files counter\n• The ClamAV sweep now focuses on key app, launch, and user locations so progress feels more relevant than a blind full-disk crawl\n• Final malware results are condensed into findings and scan summary details instead of dumping the entire verbose log into the interface\n• Release notes and packaging were refreshed for the richer malware progress pass",
            dutchBody: "• Malwarescan toont nu een duidelijkere live-werkruimte met het huidige scanpad, recente ClamAV-regels en een oplopende teller van gecontroleerde bestanden\n• De ClamAV-controle richt zich nu op belangrijke app-, opstart- en gebruikerslocaties zodat de voortgang relevanter voelt dan een blinde volledige schijfronde\n• Definitieve malware-resultaten worden nu samengevat tot bevindingen en scansamenvatting in plaats van de hele verbose log in de interface te dumpen\n• Release-notes en packaging zijn vernieuwd voor deze rijkere malware-voortgangspass"
        ),
        AppReleaseNoteEntry(
            version: "1.0.15",
            englishBody: "• Malware Scan now generates its own freshclam configuration inside the app support folder instead of depending on Homebrew's missing default config\n• ClamAV signature downloads now target the app's own local database path more reliably\n• Regular shell tasks no longer launch as a login shell, so broken ~/.zprofile entries stop polluting maintenance output\n• Release notes and packaging were refreshed for the ClamAV reliability fix",
            dutchBody: "• Malwarescan maakt nu zijn eigen freshclam-configuratie aan in de app-supportmap in plaats van te vertrouwen op de ontbrekende standaardconfig van Homebrew\n• ClamAV-signaturedownloads mikken nu betrouwbaarder op de eigen lokale database van de app\n• Gewone shelltaken starten niet meer als login shell, zodat kapotte ~/.zprofile-regels geen onderhoudsoutput meer vervuilen\n• Release-notes en packaging zijn vernieuwd voor deze ClamAV-betrouwbaarheidsfix"
        ),
        AppReleaseNoteEntry(
            version: "1.0.14",
            englishBody: "• The Auto Demo Tour now walks tab by tab through real-looking scan and placebo-task flows instead of just flashing overlay scenes\n• The floating tour overlay was removed so screen recordings stay clean\n• Preview Tools now supports keyboard-driven capture controls, including shortcuts for opening the panel and starting or stopping the tour\n• Release notes and packaging were refreshed for the cleaner recording workflow",
            dutchBody: "• De Auto Demo Tour loopt nu tab voor tab door realistische scan- en placebotaken in plaats van alleen overlayscenes te tonen\n• De zwevende tour-overlay is verwijderd zodat screen recordings schoon blijven\n• Preview Tools ondersteunt nu keyboardbediening voor opnames, inclusief sneltoetsen om het paneel te openen en de tour te starten of te stoppen\n• Release-notes en packaging zijn vernieuwd voor deze schonere opname-workflow"
        ),
        AppReleaseNoteEntry(
            version: "1.0.13",
            englishBody: "• Preview Tools now includes an Auto Demo Tour for hands-off screen recordings\n• The tour walks through dashboard pages, review, update, about, progress, and a harmless placebo run automatically\n• A floating demo controller keeps the current step visible and lets you stop the tour at any time\n• Release notes and packaging were refreshed for the new capture workflow",
            dutchBody: "• Preview Tools bevat nu een Auto Demo Tour voor hands-off screen recordings\n• De tour loopt automatisch door dashboards, review, update, over, voortgang en een onschuldige placeborun\n• Een zwevende demo-controller laat de huidige stap zien en laat u de tour op elk moment stoppen\n• Release-notes en packaging zijn vernieuwd voor deze nieuwe capture-workflow"
        ),
        AppReleaseNoteEntry(
            version: "1.0.12",
            englishBody: "• Update detection now understands release file names such as V1.0.12 instead of missing the version when it is prefixed with a V\n• Automatic update checks now run on app launch without waiting for the previous six-hour cooldown\n• A newly uploaded release should now surface as the in-app update popup more reliably\n• Release notes and packaging were refreshed for the updater reliability pass",
            dutchBody: "• Updatedetectie begrijpt nu bestandsnamen zoals V1.0.12 in plaats van de versie te missen zodra er een V voor staat\n• Automatische updatecontroles draaien nu bij het opstarten van de app zonder te wachten op de vorige zes-uurs cooldown\n• Een nieuw geuploade release hoort nu betrouwbaarder als updatepopup in de app te verschijnen\n• Release-notes en packaging zijn vernieuwd voor deze updater-betrouwbaarheidspass"
        ),
        AppReleaseNoteEntry(
            version: "1.0.11",
            englishBody: "• Malware Scan now prepares its own local ClamAV signatures database in your user Library instead of relying on an empty Homebrew default folder\n• The app refreshes ClamAV signatures automatically when needed before starting a scan\n• Intel and Apple Silicon Macs now use the same calmer ClamAV setup flow\n• Protection copy was refreshed so the first-run database download is explained more clearly",
            dutchBody: "• Malwarescan bereidt nu zijn eigen lokale ClamAV-signaturedatabase voor in uw gebruikersbibliotheek in plaats van te vertrouwen op een lege standaardmap van Homebrew\n• De app ververst ClamAV-signatures nu automatisch wanneer dat nodig is voordat een scan start\n• Intel- en Apple Silicon-Macs gebruiken nu dezelfde rustigere ClamAV-opstartflow\n• De tekst in Bescherming is vernieuwd zodat de eerste database-download duidelijker wordt uitgelegd"
        ),
        AppReleaseNoteEntry(
            version: "1.0.10",
            englishBody: "• Files now asks you to choose scan folders once instead of tripping repeated Desktop, Documents, and Downloads permission prompts\n• Large-file, duplicate, and installer reviews now stay inside the folders you explicitly connected\n• The Files page includes a clearer folder-access panel so the scan scope stays understandable\n• The release metadata was refreshed for the calmer file-access flow",
            dutchBody: "• Bestanden laat u nu één keer scanmappen kiezen in plaats van herhaalde toestemmingsmeldingen voor Bureaublad, Documenten en Downloads op te roepen\n• Controles op grote bestanden, duplicaten en installers blijven nu binnen de mappen die u expliciet hebt gekoppeld\n• De Bestanden-pagina heeft nu een duidelijkere maptoegangspagina zodat de scanscope begrijpelijk blijft\n• De release-metadata is vernieuwd voor deze rustigere bestands-toegangsflow"
        ),
        AppReleaseNoteEntry(
            version: "1.0.9",
            englishBody: "• Applications now includes an installed-app picker for uninstall and preference reset tasks\n• You can choose real apps from the Mac instead of typing names or bundle identifiers manually\n• App removal is more reliable for items in both /Applications and ~/Applications\n• The applications flow now feels closer to a dedicated app manager while keeping the EasyComp updater and cleanup tools",
            dutchBody: "• Apps bevat nu een geïnstalleerde-appkiezer voor verwijderen en voorkeuren resetten\n• U kunt echte apps van de Mac kiezen in plaats van handmatig namen of bundle-identifiers te typen\n• App-verwijdering werkt nu betrouwbaarder voor onderdelen in zowel /Applications als ~/Applications\n• De apps-flow voelt nu meer als een echte appmanager, terwijl de EasyComp-updater en opschoonhulpmiddelen behouden blijven"
        ),
        AppReleaseNoteEntry(
            version: "1.0.8",
            englishBody: "• Reworked app shell with a cleaner Home dashboard and quicker stats\n• Sidebar navigation now feels calmer and closer to a polished Mac cleaner layout\n• File, application, and maintenance routes are more focused while keeping the custom updater and EasyComp-specific tools\n• The About page and preview scenes now reflect the rebrand pass",
            dutchBody: "• Vernieuwde app-shell met een rustiger Home-dashboard en snellere statuskaarten\n• De navigatie links voelt nu kalmer en meer als een verzorgde Mac-cleaner-indeling\n• Bestands-, app- en onderhoudsroutes zijn gerichter geworden, terwijl de maatwerk-updater en EasyComp-tools behouden blijven\n• De Over-pagina en voorbeeldscenes tonen nu ook deze rebrand-pass"
        ),
        AppReleaseNoteEntry(
            version: "1.0.7",
            englishBody: "• New calmer dashboard layout inspired by modern Mac cleaner apps\n• Applications now include an orphaned files review for leftover app data without a matching installed app\n• Task cards and module pages are less cluttered and easier to scan\n• The About page and developer preview scenes were refreshed for the new dashboard pass",
            dutchBody: "• Nieuwe rustigere dashboard-indeling, geinspireerd op moderne Mac-cleaners\n• Apps bevat nu een controle voor verweesde bestanden met appresten zonder bijbehorende geïnstalleerde app\n• Taakkaarten en paginaworkflows zijn minder druk en sneller te overzien\n• De Over-pagina en ontwikkelvoorbeelden zijn vernieuwd voor deze dashboard-pass"
        ),
        AppReleaseNoteEntry(
            version: "1.0.6",
            englishBody: "• New installer cleanup review for DMG, PKG, and XIP files\n• Uninstall now removes common user-library leftovers after the app bundle is removed\n• Files review is better aligned with safer cleanup workflows inspired by modern open-source Mac cleaners\n• The About page and preview changelog now reflect the new cleanup tools",
            dutchBody: "• Nieuwe installer-opruimcontrole voor DMG-, PKG- en XIP-bestanden\n• Verwijderen van apps ruimt nu ook gebruikelijke restbestanden in de gebruikersbibliotheek op\n• Bestandscontrole sluit nu beter aan op veiligere opschoonflows uit moderne open-source Mac-cleaners\n• De Over-pagina en preview-changelog tonen nu ook deze nieuwe opschoonhulpmiddelen"
        ),
        AppReleaseNoteEntry(
            version: "1.0.5",
            englishBody: "• Large and stale files can now be reviewed and removed inside the app\n• Duplicate scans now keep one suggested original and let you remove the extra copies\n• File review scenes are clearer for manual cleanup work\n• Developer preview data now mirrors the new file cleanup flow",
            dutchBody: "• Grote en verouderde bestanden kunnen nu in de app worden bekeken en verwijderd\n• Duplicaatscans bewaren nu één voorgesteld origineel en laten u de extra kopieën verwijderen\n• Bestandscontrole is duidelijker gemaakt voor handmatige opschoning\n• Voorbeelddata voor ontwikkelaars volgt nu de nieuwe bestandsopschoonflow"
        ),
        AppReleaseNoteEntry(
            version: "1.0.4",
            englishBody: "• New in-app update popup when a newer version is found\n• Downloads and installs DMG releases automatically\n• Relaunches into the new version after the install helper finishes\n• Keeps the manual download option as a fallback",
            dutchBody: "• Nieuwe in-app updatepopup zodra er een nieuwere versie is\n• Downloadt en installeert DMG-releases automatisch\n• Start opnieuw op in de nieuwe versie zodra de updatehulp klaar is\n• Behoudt de handmatige downloadoptie als fallback"
        ),
        AppReleaseNoteEntry(
            version: "1.0.3",
            englishBody: "• Fixed update checks for the EasyComp download folder\n• Calmer progress flow with a persistent results screen\n• Visible scroll bars and lighter card copy\n• Subtle completion sounds for steps and finished runs",
            dutchBody: "• Updatecontrole hersteld voor de EasyComp-downloadmap\n• Rustigere voortgangsflow met een blijvend resultaatscherm\n• Zichtbare scrollbalken en compactere teksten\n• Subtiele afrondgeluiden per stap en per run"
        ),
        AppReleaseNoteEntry(
            version: "1.0.2",
            englishBody: "• Full-page progress workspace\n• Cleaner review flow\n• New About page\n• Live preview language switching\n• Repository-based update checks",
            dutchBody: "• Volledige voortgangswerkruimte\n• Rustigere reviewflow\n• Nieuwe Over-pagina\n• Live taalwissel in preview\n• Updatecontrole via de repository"
        )
    ]

    static func notes(for version: String) -> String? {
        let normalized = normalize(version)
        return entries.first(where: { normalize($0.version) == normalized })?.updateNotes
    }

    private static func normalize(_ version: String) -> String {
        version
            .split(separator: ".")
            .map { Int($0) ?? 0 }
            .map(String.init)
            .joined(separator: ".")
    }
}
