import SwiftUI
import Combine

/// A single timestamped log message entry displayed in the server logs view.
struct LogEntry: Identifiable {
    let id = UUID()
    let message: String
}

/// Central state manager for server configuration, security bookmarks, and real-time logs.
@MainActor
class SFTPSettings: ObservableObject {
    static let shared = SFTPSettings()
    
    // MARK: - User Preferences & Persistence
    
    @AppStorage("sharedFolderPath") var sharedFolderPath: String = ""
    @AppStorage("sharedFolderBookmark") var sharedFolderBookmark: Data = Data()
    @AppStorage("sftpPort") var port: String = "2222"
    @AppStorage("allowAnonymous") var allowAnonymous: Bool = false
    @AppStorage("sftpUsername") var username: String = ""
    @AppStorage("sftpPassword") var password: String = ""
    @AppStorage("preventSleep") var preventSleep: Bool = false
    
    // MARK: - Published Runtime State
    
    @Published var isServerRunning: Bool = false
    @Published var logs: [LogEntry] = []
    
    // MARK: - Security-Scoped Folder Resolution
    
    /// Resolves the saved security-scoped bookmark to regain file access across application restarts.
    var resolvedSharedFolderURL: URL? {
        guard !sharedFolderBookmark.isEmpty else { return nil }
        var isStale = false
        do {
            let url = try URL(
                resolvingBookmarkData: sharedFolderBookmark,
                options: .withSecurityScope,
                relativeTo: nil,
                bookmarkDataIsStale: &isStale
            )
            // Automatically renew the bookmark if macOS reports it is stale
            if isStale {
                if let renewedBookmark = try? url.bookmarkData(
                    options: .withSecurityScope,
                    includingResourceValuesForKeys: nil,
                    relativeTo: nil
                ) {
                    self.sharedFolderBookmark = renewedBookmark
                }
            }
            return url
        } catch {
            #if DEBUG
            print("Failed to resolve security-scoped bookmark: \(error)")
            #endif
            return nil
        }
    }
    
    // MARK: - Logging
    
    /// Appends a new timestamped log message and keeps the buffer capped at 100 entries.
    /// - Parameter message: The message text to record.
    func log(_ message: String) {
        #if DEBUG
        print(message)
        #endif
        
        let formatter = DateFormatter()
        formatter.timeStyle = .medium
        let timeString = formatter.string(from: Date())
        
        self.logs.append(LogEntry(message: "[\(timeString)] \(message)"))
        
        // Trim older logs to prevent unbounded memory growth
        if self.logs.count > 100 {
            self.logs.removeFirst(self.logs.count - 100)
        }
    }
}
