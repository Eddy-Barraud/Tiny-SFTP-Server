//
//  SFTPTypes.swift
//  Tiny-SFTP-server
//

import Foundation
@preconcurrency import NIOCore

// MARK: - SFTP Status Codes

public enum SFTPStatusCode: RawRepresentable, Hashable, CustomDebugStringConvertible, Sendable {
    case ok
    case eof
    case noSuchFile
    case permissionDenied
    case failure
    case badMessage
    case noConnection
    case connectionLost
    case unsupportedOperation
    case unknown(UInt32)
    
    public var rawValue: UInt32 {
        switch self {
        case .ok: return 0
        case .eof: return 1
        case .noSuchFile: return 2
        case .permissionDenied: return 3
        case .failure: return 4
        case .badMessage: return 5
        case .noConnection: return 6
        case .connectionLost: return 7
        case .unsupportedOperation: return 8
        case .unknown(let value): return value
        }
    }
    
    public init?(rawValue: UInt32) {
        switch rawValue {
        case 0: self = .ok
        case 1: self = .eof
        case 2: self = .noSuchFile
        case 3: self = .permissionDenied
        case 4: self = .failure
        case 5: self = .badMessage
        case 6: self = .noConnection
        case 7: self = .connectionLost
        case 8: self = .unsupportedOperation
        case let value: self = .unknown(value)
        }
    }
    
    public init(_ rawValue: UInt32) {
        self.init(rawValue: rawValue)!
    }

    public var debugDescription: String {
        switch self {
        case .ok: return "SSH_FX_OK"
        case .eof: return "SSH_FX_EOF"
        case .noSuchFile: return "SSH_FX_NO_SUCH_FILE"
        case .permissionDenied: return "SSH_FX_PERMISSION_DENIED"
        case .failure: return "SSH_FX_FAILURE"
        case .badMessage: return "SSH_FX_BAD_MESSAGE"
        case .noConnection: return "SSH_FX_NO_CONNECTION"
        case .connectionLost: return "SSH_FX_CONNECTION_LOST"
        case .unsupportedOperation: return "SSH_FX_OP_UNSUPPORTED"
        case .unknown(let value): return "SSH_FX_\(value)"
        }
    }
}

// MARK: - SFTP File Open Flags

public struct SFTPOpenFileFlags: OptionSet, CustomDebugStringConvertible, Sendable {
    public var rawValue: UInt32
    
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    public static let read = SFTPOpenFileFlags(rawValue: 0x00000001)
    public static let write = SFTPOpenFileFlags(rawValue: 0x00000002)
    public static let append = SFTPOpenFileFlags(rawValue: 0x00000004)
    public static let create = SFTPOpenFileFlags(rawValue: 0x00000008)
    public static let truncate = SFTPOpenFileFlags(rawValue: 0x00000010)
    public static let forceCreate = SFTPOpenFileFlags(rawValue: 0x00000020)
    
    public var debugDescription: String {
        String(format: "0x%08x", self.rawValue)
    }
}

// MARK: - SFTP File Attributes

public struct SFTPFileAttributes: CustomDebugStringConvertible, Sendable, Hashable {
    public struct Flags: OptionSet, Hashable, Sendable {
        public var rawValue: UInt32
        
        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        public static let size = Flags(rawValue: 0x00000001)
        public static let uidgid = Flags(rawValue: 0x00000002)
        public static let permissions = Flags(rawValue: 0x00000004)
        public static let acmodtime = Flags(rawValue: 0x00000008)
        public static let extended = Flags(rawValue: 0x80000000)
    }
    
    public struct UserGroupId: Sendable, Hashable {
        public let userId: UInt32
        public let groupId: UInt32
        
        public init(userId: UInt32, groupId: UInt32) {
            self.userId = userId
            self.groupId = groupId
        }
    }
    
    public struct AccessModificationTime: Sendable, Hashable {
        public let accessTime: Date
        public let modificationTime: Date
        
        public init(accessTime: Date, modificationTime: Date) {
            self.accessTime = accessTime
            self.modificationTime = modificationTime
        }
    }
    
    public var flags: Flags {
        var flags: Flags = []
        if size != nil { flags.insert(.size) }
        if uidgid != nil { flags.insert(.uidgid) }
        if permissions != nil { flags.insert(.permissions) }
        if accessModificationTime != nil { flags.insert(.acmodtime) }
        return flags
    }
    
    public var size: UInt64?
    public var uidgid: UserGroupId?
    public var permissions: UInt32?
    public var accessModificationTime: AccessModificationTime?
    
    public init(size: UInt64? = nil, accessModificationTime: AccessModificationTime? = nil) {
        self.size = size
        self.accessModificationTime = accessModificationTime
    }
    
    public static let none = SFTPFileAttributes()
    
    public var debugDescription: String {
        "{perm: \(String(describing: permissions)), size: \(String(describing: size)), uidgid: \(String(describing: uidgid))}"
    }
}

// MARK: - SFTP Path Component & Directory Listing

public struct SFTPPathComponent: Sendable {
    public let filename: String
    public let longname: String
    public let attributes: SFTPFileAttributes
    
    public init(filename: String, longname: String, attributes: SFTPFileAttributes) {
        self.filename = filename
        self.longname = longname
        self.attributes = attributes
    }
}

public struct SFTPFileListing: Sendable {
    public let path: [SFTPPathComponent]
    
    public init(path: [SFTPPathComponent]) {
        self.path = path
    }
}

// MARK: - SSH Context

public struct SSHContext: Sendable {
    public let username: String?
    
    public init(username: String?) {
        self.username = username
    }
}

// MARK: - SFTP Handles & Delegate Protocols

public protocol SFTPFileHandle: Sendable {
    func read(at offset: UInt64, length: UInt32) async throws -> ByteBuffer
    func write(_ data: ByteBuffer, atOffset offset: UInt64) async throws -> SFTPStatusCode
    func close() async throws -> SFTPStatusCode
    func readFileAttributes() async throws -> SFTPFileAttributes
    func setFileAttributes(to attributes: SFTPFileAttributes) async throws
}

public protocol SFTPDirectoryHandle: Sendable {
    func listFiles(context: SSHContext) async throws -> [SFTPFileListing]
}

public protocol SFTPDelegate: Sendable {
    func fileAttributes(atPath path: String, context: SSHContext) async throws -> SFTPFileAttributes
    func openFile(_ filePath: String, withAttributes: SFTPFileAttributes, flags: SFTPOpenFileFlags, context: SSHContext) async throws -> SFTPFileHandle
    func removeFile(_ filePath: String, context: SSHContext) async throws -> SFTPStatusCode
    func createDirectory(_ filePath: String, withAttributes: SFTPFileAttributes, context: SSHContext) async throws -> SFTPStatusCode
    func removeDirectory(_ filePath: String, context: SSHContext) async throws -> SFTPStatusCode
    func realPath(for canonicalUrl: String, context: SSHContext) async throws -> [SFTPPathComponent]
    func openDirectory(atPath path: String, context: SSHContext) async throws -> SFTPDirectoryHandle
    func setFileAttributes(to attributes: SFTPFileAttributes, atPath path: String, context: SSHContext) async throws -> SFTPStatusCode
    func addSymlink(linkPath: String, targetPath: String, context: SSHContext) async throws -> SFTPStatusCode
    func readSymlink(atPath path: String, context: SSHContext) async throws -> [SFTPPathComponent]
    func rename(oldPath: String, newPath: String, flags: UInt32, context: SSHContext) async throws -> SFTPStatusCode
}
