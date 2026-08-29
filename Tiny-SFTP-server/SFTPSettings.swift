import SwiftUI
import Combine

struct LogEntry: Identifiable {
    let id = UUID()
    let message: String
}

@MainActor
class SFTPSettings: ObservableObject {
    static let shared = SFTPSettings()
    
    @AppStorage("sharedFolderPath") var sharedFolderPath: String = ""
    @AppStorage("sharedFolderBookmark") var sharedFolderBookmark: Data = Data()
    @AppStorage("sftpPort") var port: String = "2222"
    @AppStorage("allowAnonymous") var allowAnonymous: Bool = false
    @AppStorage("sftpUsername") var username: String = ""
    @AppStorage("sftpPassword") var password: String = ""
    @AppStorage("preventSleep") var preventSleep: Bool = false
    
    @Published var isServerRunning: Bool = false
    @Published var logs: [LogEntry] = []
    
    var resolvedSharedFolderURL: URL? {
        guard !sharedFolderBookmark.isEmpty else { return nil }
        var isStale = false
        do {
            let url = try URL(resolvingBookmarkData: sharedFolderBookmark, options: .withSecurityScope, relativeTo: nil, bookmarkDataIsStale: &isStale)
            if isStale {
                // Ideally, we'd recreate the bookmark here, but it's okay for now
            }
            return url
        } catch {
            print("Failed to resolve bookmark: \(error)")
            return nil
        }
    }
    
    func log(_ message: String) {
        #if DEBUG
        print(message)
        #endif
        DispatchQueue.main.async {
            let formatter = DateFormatter()
            formatter.timeStyle = .medium
            let timeString = formatter.string(from: Date())
            self.logs.append(LogEntry(message: "[\(timeString)] \(message)"))
            // Keep logs to a reasonable size
            if self.logs.count > 100 {
                self.logs.removeFirst()
            }
        }
    }
}
