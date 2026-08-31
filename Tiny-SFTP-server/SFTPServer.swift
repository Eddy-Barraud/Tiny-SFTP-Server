import Foundation
@preconcurrency import NIOSSH
@preconcurrency import NIOCore
import Crypto
import NIOFoundationCompat

// MARK: - File Attributes & Path Helpers

/// Extracts SFTP-compatible file attributes for a given local file or directory URL.
/// - Parameter url: The URL of the local file system item.
/// - Throws: An error if the file or directory does not exist or attributes cannot be read.
/// - Returns: A populated `SFTPFileAttributes` struct.
nonisolated fileprivate func getFileAttributes(url: URL) throws -> SFTPFileAttributes {
    guard FileManager.default.fileExists(atPath: url.path) else {
        throw NSError(domain: "SFTPServer", code: 404, userInfo: [NSLocalizedDescriptionKey: "No such file or directory"])
    }
    let attr = try FileManager.default.attributesOfItem(atPath: url.path)
    let size = attr[.size] as? UInt64 ?? 0
    let isDirectory = (attr[.type] as? FileAttributeType) == .typeDirectory
    
    var attributes = SFTPFileAttributes(size: size)
    var permissions = (attr[.posixPermissions] as? NSNumber)?.uint32Value ?? (isDirectory ? 0o755 : 0o644)
    if isDirectory {
        permissions |= 0o040000 // S_IFDIR
    } else {
        permissions |= 0o100000 // S_IFREG
    }
    attributes.permissions = permissions
    let modDate = (attr[.modificationDate] as? Date) ?? Date()
    let accessDate = (attr[.creationDate] as? Date) ?? modDate
    attributes.accessModificationTime = .init(accessTime: accessDate, modificationTime: modDate)
    return attributes
}

/// Creates an SFTP path component representing a file or directory for directory listings and real path queries.
/// - Parameters:
///   - url: The item URL.
///   - filename: Optional custom display name; defaults to `url.lastPathComponent`.
/// - Returns: A populated `SFTPPathComponent`.
nonisolated fileprivate func makePathComponent(url: URL, filename: String? = nil) -> SFTPPathComponent {
    let name = filename ?? url.lastPathComponent
    let attr = (try? FileManager.default.attributesOfItem(atPath: url.path)) ?? [:]
    let size = attr[.size] as? UInt64 ?? 0
    let isDirectory = (attr[.type] as? FileAttributeType) == .typeDirectory
    
    var attributes = SFTPFileAttributes(size: size)
    var permissions = (attr[.posixPermissions] as? NSNumber)?.uint32Value ?? (isDirectory ? 0o755 : 0o644)
    if isDirectory {
        permissions |= 0o040000 // S_IFDIR
    } else {
        permissions |= 0o100000 // S_IFREG
    }
    attributes.permissions = permissions
    let modDate = (attr[.modificationDate] as? Date) ?? Date()
    let accessDate = (attr[.creationDate] as? Date) ?? modDate
    attributes.accessModificationTime = .init(accessTime: accessDate, modificationTime: modDate)
    
    let formatter = DateFormatter()
    formatter.dateFormat = "MMM dd HH:mm"
    let dateString = formatter.string(from: modDate)
    
    let typeChar = isDirectory ? "d" : "-"
    let longname = "\(typeChar)rwxr-xr-x 1 owner group \(size) \(dateString) \(name)"
    return SFTPPathComponent(filename: name, longname: longname, attributes: attributes)
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

/// Manages starting, stopping, and hosting the NIOSSH SFTP server instance.
@MainActor
class SFTPServer {
    static let shared = SFTPServer()
    
    private var accessedURL: URL?
    private var sshServer: SFTPServerEngine?
    
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
                let privateKey = HostKeyManager.shared.getOrCreateHostPrivateKey()
                
                let sftpDelegate = MySFTPDelegate(baseDirectory: folderURL)
                let server = try await SFTPServerEngine.start(
                    port: portNumber,
                    hostKeys: [privateKey],
                    sftpDelegate: sftpDelegate,
                    authDelegate: LoginHandler()
                )
                
                self.sshServer = server
                
                SFTPSettings.shared.log("Server listening on port \(portNumber)")
                SFTPSettings.shared.isServerRunning = true
                if SFTPSettings.shared.preventSleep {
                    SleepPreventer.shared.startPreventingSleep()
                }
            } catch {
                let message = SFTPServer.formatStartServerError(error, port: portNumber)
                SFTPSettings.shared.log("Failed to start server: \(message)")
                SFTPSettings.shared.errorMessage = message
                self.stop()
            }
        }
    }
    
    /// Translates low-level networking/NIO errors into actionable user-friendly messages.
    private static func formatStartServerError(_ error: Error, port: Int) -> String {
        if let ioError = error as? IOError {
            if ioError.errnoCode == EADDRINUSE {
                return "Port \(port) is already in use by another application. Please choose a different port or terminate the conflicting process."
            } else if ioError.errnoCode == EPERM || ioError.errnoCode == EACCES {
                if port < 1024 {
                    return "Port \(port) requires administrator/root privileges. Please choose a port number above 1024 (e.g. 2222)."
                } else {
                    return "Port \(port) could not be opened (port is already in use or permission was denied). Please choose a different port."
                }
            }
        }
        
        let nsError = error as NSError
        if nsError.domain == NSPOSIXErrorDomain {
            if nsError.code == Int(EADDRINUSE) {
                return "Port \(port) is already in use by another application. Please choose a different port."
            } else if nsError.code == Int(EPERM) || nsError.code == Int(EACCES) {
                if port < 1024 {
                    return "Port \(port) requires administrator privileges (< 1024). Please choose a port above 1024 (e.g. 2222)."
                } else {
                    return "Port \(port) could not be bound (permission denied or port already in use). Please choose a different port."
                }
            }
        }
        
        let desc = error.localizedDescription
        if desc.contains("error 48") || desc.contains("Address already in use") {
            return "Port \(port) is already in use by another application. Please choose a different port."
        } else if desc.contains("error 1") || desc.contains("error 13") || desc.contains("Operation not permitted") {
            if port < 1024 {
                return "Port \(port) requires administrator privileges (< 1024). Please choose a port above 1024 (e.g. 2222)."
            } else {
                return "Port \(port) could not be bound (port already in use or permission denied). Please choose a different port."
            }
        }
        
        return error.localizedDescription
    }
    
    /// Gracefully stops the SFTP server and releases all security-scoped resources.
    func stop() {
        Task {
            await sshServer?.close()
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

/// Implements the `SFTPDelegate` protocol to handle file system operations securely.
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
    
    func fileAttributes(atPath path: String, context: SSHContext) async throws -> SFTPFileAttributes {
        let url = try resolvePath(path)
        return try getFileAttributes(url: url)
    }
    
    func openFile(_ filePath: String, withAttributes: SFTPFileAttributes, flags: SFTPOpenFileFlags, context: SSHContext) async throws -> any SFTPFileHandle {
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
    
    func removeFile(_ filePath: String, context: SSHContext) async throws -> SFTPStatusCode {
        let url = try resolvePath(filePath)
        try FileManager.default.removeItem(at: url)
        await SFTPSettings.shared.log("Removed file: \(filePath)")
        return .ok
    }
    
    func createDirectory(_ filePath: String, withAttributes: SFTPFileAttributes, context: SSHContext) async throws -> SFTPStatusCode {
        let url = try resolvePath(filePath)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: nil)
        await SFTPSettings.shared.log("Created directory: \(filePath)")
        return .ok
    }
    
    func removeDirectory(_ filePath: String, context: SSHContext) async throws -> SFTPStatusCode {
        let url = try resolvePath(filePath)
        try FileManager.default.removeItem(at: url)
        await SFTPSettings.shared.log("Removed directory: \(filePath)")
        return .ok
    }
    
    func realPath(for canonicalUrl: String, context: SSHContext) async throws -> [SFTPPathComponent] {
        var path = canonicalUrl
        if path.isEmpty || path == "." {
            path = "/"
        }
        let url = try resolvePath(path)
        let name = path == "/" ? "/" : url.lastPathComponent
        let attributes = (try? getFileAttributes(url: url)) ?? SFTPFileAttributes(size: 0)
        return [SFTPPathComponent(filename: name, longname: name, attributes: attributes)]
    }
    
    func openDirectory(atPath path: String, context: SSHContext) async throws -> any SFTPDirectoryHandle {
        let url = try resolvePath(path)
        await SFTPSettings.shared.log("Listed directory: \(path)")
        return MyDirectoryHandle(url: url)
    }
    
    func setFileAttributes(to attributes: SFTPFileAttributes, atPath path: String, context: SSHContext) async throws -> SFTPStatusCode {
        let url = try resolvePath(path)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return .noSuchFile
        }
        var attributesDict = [FileAttributeKey: Any]()
        if let permissions = attributes.permissions {
            attributesDict[.posixPermissions] = NSNumber(value: permissions & 0o7777)
        }
        if let mtime = attributes.accessModificationTime?.modificationTime {
            attributesDict[.modificationDate] = mtime
        }
        if !attributesDict.isEmpty {
            try? FileManager.default.setAttributes(attributesDict, ofItemAtPath: url.path)
        }
        return .ok
    }
    
    func addSymlink(linkPath: String, targetPath: String, context: SSHContext) async throws -> SFTPStatusCode {
        return .failure
    }
    
    func readSymlink(atPath path: String, context: SSHContext) async throws -> [SFTPPathComponent] {
        return []
    }
    
    func rename(oldPath: String, newPath: String, flags: UInt32, context: SSHContext) async throws -> SFTPStatusCode {
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
        // Cap single read request to 32KB (standard SFTP packet payload limit) to prevent buffer overflows
        let safeLength = min(Int(length), 32768)
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
    
    func write(_ data: NIOCore.ByteBuffer, atOffset offset: UInt64) async throws -> SFTPStatusCode {
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
    
    func close() async throws -> SFTPStatusCode {
        if #available(macOS 10.15.4, *) {
            try? fileHandle.synchronize()
        }
        try? fileHandle.close()
        return .ok
    }
    
    func readFileAttributes() async throws -> SFTPFileAttributes {
        return try getFileAttributes(url: url)
    }
    
    func setFileAttributes(to attributes: SFTPFileAttributes) async throws {
        var attributesDict = [FileAttributeKey: Any]()
        if let permissions = attributes.permissions {
            attributesDict[.posixPermissions] = NSNumber(value: permissions & 0o7777)
        }
        if let mtime = attributes.accessModificationTime?.modificationTime {
            attributesDict[.modificationDate] = mtime
        }
        if !attributesDict.isEmpty {
            try? FileManager.default.setAttributes(attributesDict, ofItemAtPath: url.path)
        }
    }
}

// MARK: - Directory Handle Implementation

/// Represents an active directory handle for enumerating directory entries.
final nonisolated class MyDirectoryHandle: SFTPDirectoryHandle {
    let url: URL
    
    init(url: URL) {
        self.url = url
    }
    
    func listFiles(context: SSHContext) async throws -> [SFTPFileListing] {
        var paths = [SFTPPathComponent]()
        paths.append(makePathComponent(url: url, filename: "."))
        paths.append(makePathComponent(url: url.deletingLastPathComponent(), filename: ".."))
        
        let contents = (try? FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)) ?? []
        
        for item in contents {
            paths.append(makePathComponent(url: item))
        }
        
        // Chunk each item into its own SFTPFileListing so the server streams them across readdir calls without exceeding packet limits
        return paths.map { SFTPFileListing(path: [$0]) }
    }
}
