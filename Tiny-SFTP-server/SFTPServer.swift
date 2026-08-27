import Foundation
import Citadel
import NIOSSH
import NIOCore
import NIOPosix
import Crypto
import NIOFoundationCompat

fileprivate func getFileAttributes(url: URL) -> Citadel.SFTPFileAttributes {
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

fileprivate func makePathComponent(url: URL, filename: String? = nil) -> Citadel.SFTPPathComponent {
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

final class LoginHandler: NIOSSHServerUserAuthenticationDelegate {
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

        if SFTPSettings.shared.allowAnonymous && (username.lowercased() == "anonymous" || username.lowercased() == "ftp" || password == "") {
            SFTPSettings.shared.log("Anonymous login successful")
            responsePromise.succeed(.success)
            return
        }
        
        let correctUsername = SFTPSettings.shared.username
        let correctPassword = SFTPSettings.shared.password
        
        if username == correctUsername && password == correctPassword {
            SFTPSettings.shared.log("User '\(username)' logged in successfully")
            responsePromise.succeed(.success)
        } else {
            SFTPSettings.shared.log("Failed login attempt for '\(username)'")
            responsePromise.succeed(.failure)
        }
    }
}

class SFTPServer {
    static let shared = SFTPServer()
    
    private let queue = DispatchQueue(label: "com.tinysftpserver.serverQueue", qos: .background)
    private var accessedURL: URL?
    private var sshServer: SSHServer?
    
    func start() {
        let portString = SFTPSettings.shared.port
        let portNumber = Int(portString) ?? 2222
        
        self.accessedURL = SFTPSettings.shared.resolvedSharedFolderURL
        let _ = self.accessedURL?.startAccessingSecurityScopedResource()
        
        SFTPSettings.shared.log("Attempting to start SFTP Server on port \(portNumber)...")
        
        Task {
            do {
                let privateKey = NIOSSHPrivateKey(ed25519Key: .init())
                let server = try await SSHServer.host(
                    host: "0.0.0.0",
                    port: portNumber,
                    hostKeys: [privateKey],
                    authenticationDelegate: LoginHandler()
                )
                
                self.sshServer = server
                server.enableSFTP(withDelegate: MySFTPDelegate(baseDirectory: self.accessedURL))
                
                DispatchQueue.main.async {
                    SFTPSettings.shared.log("Server listening on port \(portNumber)")
                    SFTPSettings.shared.isServerRunning = true
                    if SFTPSettings.shared.preventSleep {
                        SleepPreventer.shared.startPreventingSleep()
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    SFTPSettings.shared.log("Failed to start server: \(error)")
                    self.stop()
                }
            }
        }
    }
    
    func stop() {
        Task {
            try? await sshServer?.close()
            sshServer = nil
            
            DispatchQueue.main.async {
                SFTPSettings.shared.isServerRunning = false
                SleepPreventer.shared.stopPreventingSleep()
            }
            
            self.accessedURL?.stopAccessingSecurityScopedResource()
            self.accessedURL = nil
            SFTPSettings.shared.log("Server stopped")
        }
    }
}

final class MySFTPDelegate: SFTPDelegate {
    let baseDirectory: URL?
    
    init(baseDirectory: URL?) {
        self.baseDirectory = baseDirectory
    }
    
    private func resolvePath(_ path: String) throws -> URL {
        guard let base = baseDirectory else { throw NSError(domain: "SFTPServer", code: 1, userInfo: nil) }
        var cleanPath = path
        if cleanPath.hasPrefix("/") {
            cleanPath.removeFirst()
        }
        let url = base.appendingPathComponent(cleanPath).standardizedFileURL
        if !url.path.hasPrefix(base.standardizedFileURL.path) {
            throw NSError(domain: "SFTPServer", code: 2, userInfo: nil)
        }
        return url
    }
    
    func fileAttributes(atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPFileAttributes {
        let url = try resolvePath(path)
        return getFileAttributes(url: url)
    }
    
    func openFile(_ filePath: String, withAttributes: Citadel.SFTPFileAttributes, flags: Citadel.SFTPOpenFileFlags, context: Citadel.SSHContext) async throws -> any Citadel.SFTPFileHandle {
        let url = try resolvePath(filePath)
        if !FileManager.default.fileExists(atPath: url.path) {
            if flags.contains(.create) {
                SFTPSettings.shared.log("Created file: \(filePath)")
                FileManager.default.createFile(atPath: url.path, contents: nil, attributes: nil)
            } else {
                SFTPSettings.shared.log("Failed to open file (not found): \(filePath)")
                throw NSError(domain: "SFTPServer", code: 404, userInfo: nil)
            }
        }
        let fileHandle: FileHandle
        if flags.contains(.write) || flags.contains(.append) {
            SFTPSettings.shared.log("Opened file for writing: \(filePath)")
            fileHandle = try FileHandle(forUpdating: url)
        } else {
            SFTPSettings.shared.log("Opened file for reading: \(filePath)")
            fileHandle = try FileHandle(forReadingFrom: url)
        }
        return MyFileHandle(fileHandle: fileHandle, url: url)
    }
    
    func removeFile(_ filePath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        let url = try resolvePath(filePath)
        try FileManager.default.removeItem(at: url)
        SFTPSettings.shared.log("Removed file: \(filePath)")
        return .ok
    }
    
    func createDirectory(_ filePath: String, withAttributes: Citadel.SFTPFileAttributes, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        let url = try resolvePath(filePath)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: nil)
        SFTPSettings.shared.log("Created directory: \(filePath)")
        return .ok
    }
    
    func removeDirectory(_ filePath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        let url = try resolvePath(filePath)
        try FileManager.default.removeItem(at: url)
        SFTPSettings.shared.log("Removed directory: \(filePath)")
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
        SFTPSettings.shared.log("Listed directory: \(path)")
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
        SFTPSettings.shared.log("Renamed: \(oldPath) -> \(newPath)")
        return .ok
    }
}

final class MyFileHandle: SFTPFileHandle {
    let fileHandle: FileHandle
    let url: URL
    
    init(fileHandle: FileHandle, url: URL) {
        self.fileHandle = fileHandle
        self.url = url
    }
    
    func read(at offset: UInt64, length: UInt32) async throws -> NIOCore.ByteBuffer {
        try fileHandle.seek(toOffset: offset)
        // Client requests a specific length for pipelined reads. We must fulfill it exactly to avoid gaps and overlapping re-reads.
        // We cap it at 256KB (262144) to prevent memory issues if a client requests UInt32.max
        let safeLength = min(Int(length), 262144)
        if #available(macOS 10.15.4, *) {
            if let data = try fileHandle.read(upToCount: safeLength) {
                return ByteBuffer(data: data)
            } else {
                return ByteBuffer() // EOF
            }
        } else {
            let data = fileHandle.readData(ofLength: safeLength)
            return ByteBuffer(data: data)
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

final class MyDirectoryHandle: SFTPDirectoryHandle {
    let url: URL
    private var listed = false
    
    init(url: URL) {
        self.url = url
    }
    
    func listFiles(context: Citadel.SSHContext) async throws -> [Citadel.SFTPFileListing] {
        if listed { return [] }
        listed = true
        
        var paths = [Citadel.SFTPPathComponent]()
        paths.append(makePathComponent(url: url, filename: "."))
        paths.append(makePathComponent(url: url.deletingLastPathComponent(), filename: ".."))
        
        let contents = try FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)
        
        for item in contents {
            paths.append(makePathComponent(url: item))
        }
        return [Citadel.SFTPFileListing(path: paths)]
    }
}
