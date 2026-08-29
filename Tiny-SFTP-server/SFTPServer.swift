import Foundation
@preconcurrency import Citadel
@preconcurrency import NIOSSH
@preconcurrency import NIOCore
import Crypto
import NIOFoundationCompat

// MARK: - File Attributes & Path Helpers

/// Extracts SFTP-compatible file attributes for a given local file or directory URL.
/// - Parameter url: The URL of the local file system item.
/// - Returns: A populated `Citadel.SFTPFileAttributes` struct.
nonisolated fileprivate func getFileAttributes(url: URL) -> Citadel.SFTPFileAttributes {
    let attr = try? FileManager.default.attributesOfItem(atPath: url.path)
    let size = attr?[.size] as? UInt64 ?? 0
    let isDirectory = (attr?[.type] as? FileAttributeType) == .typeDirectory
    
    var attributes = Citadel.SFTPFileAttributes(size: size)
    var permissions = (attr?[.posixPermissions] as? NSNumber)?.uint32Value ?? (isDirectory ? 0o755 : 0o644)
    if isDirectory {
        permissions |= 0o040000 // S_IFDIR
    } else {
        permissions |= 0o100000 // S_IFREG
    }
    attributes.permissions = permissions
    return attributes
}

/// Creates an SFTP path component representing a file or directory for directory listings and real path queries.
/// - Parameters:
///   - url: The item URL.
///   - filename: Optional custom display name; defaults to `url.lastPathComponent`.
/// - Returns: A populated `Citadel.SFTPPathComponent`.
nonisolated fileprivate func makePathComponent(url: URL, filename: String? = nil) -> Citadel.SFTPPathComponent {
    let name = filename ?? url.lastPathComponent
    let attr = try? FileManager.default.attributesOfItem(atPath: url.path)
    let size = attr?[.size] as? UInt64 ?? 0
    let isDirectory = (attr?[.type] as? FileAttributeType) == .typeDirectory
    let attributes = getFileAttributes(url: url)
    
    let typeChar = isDirectory ? "d" : "-"
    let date = Date()
    let formatter = DateFormatter()
    formatter.dateFormat = "MMM dd HH:mm"
    let dateString = formatter.string(from: (attr?[.modificationDate] as? Date) ?? date)
    
    let longname = "\(typeChar)rwxr-xr-x 1 owner group \(size) \(dateString) \(name)"
    return Citadel.SFTPPathComponent(filename: name, longname: longname, attributes: attributes)
}

// MARK: - SSH Authentication Handler

/// Handles SSH user authentication via password or anonymous access.
/// Non-isolated so it can safely execute within NIOSSH event loop callbacks.
final nonisolated class LoginHandler: NIOSSHServerUserAuthenticationDelegate {
    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods {
        .password
    }

    func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
        guard case .password(let passwordRequest) = request.request else {
            responsePromise.succeed(.failure)
            return
        }

        let username = request.username
        let password = passwordRequest.password

        Task { @MainActor in
            let allowAnon = SFTPSettings.shared.allowAnonymous
            let configuredUser = SFTPSettings.shared.username
            let configuredPass = SFTPSettings.shared.password

            // Anonymous authentication: allowed if setting is enabled and credentials match typical anonymous patterns
            if allowAnon && (username.lowercased() == "anonymous" || username.lowercased() == "ftp" || password.isEmpty) {
                SFTPSettings.shared.log("Anonymous login accepted for user '\(username)'")
                responsePromise.succeed(.success)
                return
            }
            
            // Password authentication: require non-empty username configuration to prevent empty-credential bypass
            if !configuredUser.isEmpty && username == configuredUser && password == configuredPass {
                SFTPSettings.shared.log("User '\(username)' logged in successfully")
                responsePromise.succeed(.success)
            } else {
                SFTPSettings.shared.log("Failed login attempt for '\(username)'")
                responsePromise.succeed(.failure)
            }
        }
    }
}

// MARK: - SFTP Server Lifecycle

/// Manages starting, stopping, and hosting the Citadel/NIOSSH SFTP server instance.
@MainActor
class SFTPServer {
    static let shared = SFTPServer()
    
    private var accessedURL: URL?
    private var sshServer: SSHServer?
    
    /// Persists or retrieves a stable ED25519 host key so clients do not see host key mismatch warnings on restart.
    private static func getOrCreateHostKey() -> NIOSSHPrivateKey {
        let keyStorageKey = "sftpHostKeySeed"
        if let seedData = UserDefaults.standard.data(forKey: keyStorageKey),
           let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: seedData) {
            return NIOSSHPrivateKey(ed25519Key: privateKey)
        }
        let newKey = Curve25519.Signing.PrivateKey()
        UserDefaults.standard.set(newKey.rawRepresentation, forKey: keyStorageKey)
        return NIOSSHPrivateKey(ed25519Key: newKey)
    }
    
    /// Starts the SFTP server on the configured port.
    func start() {
        guard sshServer == nil else {
            SFTPSettings.shared.log("Server is already running.")
            return
        }
        
        let portString = SFTPSettings.shared.port
        let portNumber = Int(portString) ?? 2222
        
        guard let folderURL = SFTPSettings.shared.resolvedSharedFolderURL else {
            SFTPSettings.shared.log("Failed to start server: Shared folder is not selected or inaccessible.")
            return
        }
        
        self.accessedURL = folderURL
        let accessGranted = self.accessedURL?.startAccessingSecurityScopedResource() ?? false
        if !accessGranted {
            SFTPSettings.shared.log("Warning: Security-scoped access to shared folder could not be started.")
        }
        
        SFTPSettings.shared.log("Starting SFTP Server on port \(portNumber)...")
        
        Task {
            do {
                let hostKey = SFTPServer.getOrCreateHostKey()
                let server = try await SSHServer.host(
                    host: "0.0.0.0",
                    port: portNumber,
                    hostKeys: [hostKey],
                    authenticationDelegate: LoginHandler()
                )
                
                self.sshServer = server
                server.enableSFTP(withDelegate: MySFTPDelegate(baseDirectory: folderURL))
                
                SFTPSettings.shared.log("Server listening on port \(portNumber)")
                SFTPSettings.shared.isServerRunning = true
                if SFTPSettings.shared.preventSleep {
                    SleepPreventer.shared.startPreventingSleep()
                }
            } catch {
                SFTPSettings.shared.log("Failed to start server: \(error.localizedDescription)")
                self.stop()
            }
        }
    }
    
    /// Gracefully stops the SFTP server and releases all security-scoped resources.
    func stop() {
        Task {
            try? await sshServer?.close()
            sshServer = nil
            
            SFTPSettings.shared.isServerRunning = false
            SleepPreventer.shared.stopPreventingSleep()
            
            self.accessedURL?.stopAccessingSecurityScopedResource()
            self.accessedURL = nil
            SFTPSettings.shared.log("Server stopped")
        }
    }
}

// MARK: - SFTP Delegate Implementation

/// Implements Citadel's `SFTPDelegate` protocol to handle file system operations securely.
final nonisolated class MySFTPDelegate: SFTPDelegate {
    let baseDirectory: URL?
    
    init(baseDirectory: URL?) {
        self.baseDirectory = baseDirectory
    }
    
    /// Resolves a client-requested path against the root base directory, enforcing path boundary security.
    /// - Parameter path: The relative or absolute path requested by the client.
    /// - Throws: An error if the resolved path escapes the base directory (path traversal defense).
    /// - Returns: The validated local file URL.
    private func resolvePath(_ path: String) throws -> URL {
        guard let base = baseDirectory else {
            throw NSError(domain: "SFTPServer", code: 1, userInfo: [NSLocalizedDescriptionKey: "Base directory not configured"])
        }
        
        var cleanPath = path.trimmingCharacters(in: .whitespacesAndNewlines)
        while cleanPath.hasPrefix("/") {
            cleanPath.removeFirst()
        }
        
        let baseURL = base.standardizedFileURL.resolvingSymlinksInPath()
        let targetURL = baseURL.appendingPathComponent(cleanPath).standardizedFileURL.resolvingSymlinksInPath()
        
        let basePath = baseURL.path
        let targetPath = targetURL.path
        
        // Ensure the path does not escape the designated base directory
        let isWithinBase = targetPath == basePath || targetPath.hasPrefix(basePath.hasSuffix("/") ? basePath : basePath + "/")
        guard isWithinBase else {
            throw NSError(domain: "SFTPServer", code: 2, userInfo: [NSLocalizedDescriptionKey: "Access denied: Path is outside shared directory"])
        }
        
        return targetURL
    }
    
    func fileAttributes(atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPFileAttributes {
        let url = try resolvePath(path)
        return getFileAttributes(url: url)
    }
    
    func openFile(_ filePath: String, withAttributes: Citadel.SFTPFileAttributes, flags: Citadel.SFTPOpenFileFlags, context: Citadel.SSHContext) async throws -> any Citadel.SFTPFileHandle {
        let url = try resolvePath(filePath)
        
        // Handle file creation if requested
        if !FileManager.default.fileExists(atPath: url.path) {
            if flags.contains(.create) {
                await SFTPSettings.shared.log("Created file: \(filePath)")
                FileManager.default.createFile(atPath: url.path, contents: nil, attributes: nil)
            } else {
                await SFTPSettings.shared.log("Failed to open file (not found): \(filePath)")
                throw NSError(domain: "SFTPServer", code: 404, userInfo: [NSLocalizedDescriptionKey: "File not found"])
            }
        }
        
        let fileHandle: FileHandle
        if flags.contains(.write) || flags.contains(.append) {
            await SFTPSettings.shared.log("Opened file for writing: \(filePath)")
            fileHandle = try FileHandle(forUpdating: url)
            
            // Handle truncation if requested (e.g. uploading/replacing a file)
            if flags.contains(.truncate) {
                if #available(macOS 10.15.4, *) {
                    try fileHandle.truncate(atOffset: 0)
                } else {
                    fileHandle.truncateFile(atOffset: 0)
                }
            }
            
            // Handle appending if requested
            if flags.contains(.append) {
                if #available(macOS 10.15.4, *) {
                    try fileHandle.seekToEnd()
                } else {
                    fileHandle.seekToEndOfFile()
                }
            }
        } else {
            await SFTPSettings.shared.log("Opened file for reading: \(filePath)")
            fileHandle = try FileHandle(forReadingFrom: url)
        }
        
        return MyFileHandle(fileHandle: fileHandle, url: url)
    }
    
    func removeFile(_ filePath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        let url = try resolvePath(filePath)
        try FileManager.default.removeItem(at: url)
        await SFTPSettings.shared.log("Removed file: \(filePath)")
        return .ok
    }
    
    func createDirectory(_ filePath: String, withAttributes: Citadel.SFTPFileAttributes, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        let url = try resolvePath(filePath)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: nil)
        await SFTPSettings.shared.log("Created directory: \(filePath)")
        return .ok
    }
    
    func removeDirectory(_ filePath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        let url = try resolvePath(filePath)
        try FileManager.default.removeItem(at: url)
        await SFTPSettings.shared.log("Removed directory: \(filePath)")
        return .ok
    }
    
    func realPath(for canonicalUrl: String, context: Citadel.SSHContext) async throws -> [Citadel.SFTPPathComponent] {
        var path = canonicalUrl
        if path.isEmpty || path == "." {
            path = "/"
        }
        let url = try resolvePath(path)
        let name = path == "/" ? "/" : url.lastPathComponent
        return [makePathComponent(url: url, filename: name)]
    }
    
    func openDirectory(atPath path: String, context: Citadel.SSHContext) async throws -> any Citadel.SFTPDirectoryHandle {
        let url = try resolvePath(path)
        await SFTPSettings.shared.log("Listed directory: \(path)")
        return MyDirectoryHandle(url: url)
    }
    
    func setFileAttributes(to attributes: Citadel.SFTPFileAttributes, atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        return .ok
    }
    
    func addSymlink(linkPath: String, targetPath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        return .failure
    }
    
    func readSymlink(atPath path: String, context: Citadel.SSHContext) async throws -> [Citadel.SFTPPathComponent] {
        return []
    }
    
    func rename(oldPath: String, newPath: String, flags: UInt32, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        let oldUrl = try resolvePath(oldPath)
        let newUrl = try resolvePath(newPath)
        try FileManager.default.moveItem(at: oldUrl, to: newUrl)
        await SFTPSettings.shared.log("Renamed: \(oldPath) -> \(newPath)")
        return .ok
    }
}

// MARK: - File Handle Implementation

/// Represents an active file handle for streaming read and write operations.
final nonisolated class MyFileHandle: SFTPFileHandle {
    let fileHandle: FileHandle
    let url: URL
    
    init(fileHandle: FileHandle, url: URL) {
        self.fileHandle = fileHandle
        self.url = url
    }
    
    deinit {
        // Ensure underlying file handle descriptor is closed upon deallocation
        try? fileHandle.close()
    }
    
    func read(at offset: UInt64, length: UInt32) async throws -> NIOCore.ByteBuffer {
        try fileHandle.seek(toOffset: offset)
        // Cap single read request to 256KB to avoid memory exhaustion from malformed client requests
        let safeLength = min(Int(length), 262144)
        if #available(macOS 10.15.4, *) {
            if let data = try fileHandle.read(upToCount: safeLength) {
                return ByteBuffer(bytes: data)
            } else {
                return ByteBuffer() // EOF reached
            }
        } else {
            let data = fileHandle.readData(ofLength: safeLength)
            return ByteBuffer(bytes: data)
        }
    }
    
    func write(_ data: NIOCore.ByteBuffer, atOffset offset: UInt64) async throws -> Citadel.SFTPStatusCode {
        try fileHandle.seek(toOffset: offset)
        var dataCopy = data
        if let bytes = dataCopy.readBytes(length: dataCopy.readableBytes) {
            let nsData = Data(bytes)
            if #available(macOS 10.15.4, *) {
                try fileHandle.write(contentsOf: nsData)
            } else {
                fileHandle.write(nsData)
            }
        }
        return .ok
    }
    
    func close() async throws -> Citadel.SFTPStatusCode {
        try fileHandle.close()
        return .ok
    }
    
    func readFileAttributes() async throws -> Citadel.SFTPFileAttributes {
        return getFileAttributes(url: url)
    }
    
    func setFileAttributes(to attributes: Citadel.SFTPFileAttributes) async throws {
    }
}

// MARK: - Directory Handle Implementation

/// Represents an active directory handle for enumerating directory entries.
final nonisolated class MyDirectoryHandle: SFTPDirectoryHandle {
    let url: URL
    private var listed = false
    
    init(url: URL) {
        self.url = url
    }
    
    func listFiles(context: Citadel.SSHContext) async throws -> [Citadel.SFTPFileListing] {
        // Return empty listing on subsequent calls to indicate EOF
        if listed { return [] }
        listed = true
        
        var paths = [Citadel.SFTPPathComponent]()
        paths.append(makePathComponent(url: url, filename: "."))
        paths.append(makePathComponent(url: url.deletingLastPathComponent(), filename: ".."))
        
        let contents = (try? FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)) ?? []
        
        for item in contents {
            paths.append(makePathComponent(url: item))
        }
        return [Citadel.SFTPFileListing(path: paths)]
    }
}
