//
//  SFTPServerEngine.swift
//  Tiny-SFTP-server
//

import Foundation
@preconcurrency import NIOCore
@preconcurrency import NIOPosix
@preconcurrency import NIOSSH

// MARK: - SFTP Constants

enum SFTPPacketType: UInt8 {
    case `init` = 1
    case version = 2
    case open = 3
    case close = 4
    case read = 5
    case write = 6
    case lstat = 7
    case fstat = 8
    case setstat = 9
    case fsetstat = 10
    case opendir = 11
    case readdir = 12
    case remove = 13
    case mkdir = 14
    case rmdir = 15
    case realpath = 16
    case stat = 17
    case rename = 18
    case status = 101
    case handle = 102
    case data = 103
    case name = 104
    case attrs = 105
}

// MARK: - SFTP Inbound Request & Outbound Response

enum SFTPPacket: Sendable, CustomStringConvertible {
    case `init`(version: UInt32)
    case open(requestId: UInt32, path: String, flags: UInt32, attributes: SFTPFileAttributes)
    case close(requestId: UInt32, handle: UInt32)
    case read(requestId: UInt32, handle: UInt32, offset: UInt64, length: UInt32)
    case write(requestId: UInt32, handle: UInt32, offset: UInt64, data: ByteBuffer)
    case lstat(requestId: UInt32, path: String)
    case fstat(requestId: UInt32, handle: UInt32)
    case setstat(requestId: UInt32, path: String, attributes: SFTPFileAttributes)
    case fsetstat(requestId: UInt32, handle: UInt32, attributes: SFTPFileAttributes)
    case opendir(requestId: UInt32, path: String)
    case readdir(requestId: UInt32, handle: UInt32)
    case remove(requestId: UInt32, path: String)
    case mkdir(requestId: UInt32, path: String, attributes: SFTPFileAttributes)
    case rmdir(requestId: UInt32, path: String)
    case realpath(requestId: UInt32, path: String)
    case stat(requestId: UInt32, path: String)
    case rename(requestId: UInt32, oldPath: String, newPath: String, flags: UInt32)

    // Outbound
    case version(version: UInt32)
    case status(requestId: UInt32, code: UInt32, message: String)
    case handle(requestId: UInt32, handle: UInt32)
    case data(requestId: UInt32, data: ByteBuffer)
    case name(requestId: UInt32, components: [SFTPPathComponent])
    case attrs(requestId: UInt32, attributes: SFTPFileAttributes)

    var description: String {
        switch self {
        case .`init`(let v): return "INIT(v: \(v))"
        case .open(let req, let p, let f, _): return "OPEN(req: \(req), path: \(p), flags: \(f))"
        case .close(let req, let h): return "CLOSE(req: \(req), handle: \(h))"
        case .read(let req, let h, let off, let len): return "READ(req: \(req), handle: \(h), off: \(off), len: \(len))"
        case .write(let req, let h, let off, let d): return "WRITE(req: \(req), handle: \(h), off: \(off), bytes: \(d.readableBytes))"
        case .lstat(let req, let p): return "LSTAT(req: \(req), path: \(p))"
        case .fstat(let req, let h): return "FSTAT(req: \(req), handle: \(h))"
        case .setstat(let req, let p, _): return "SETSTAT(req: \(req), path: \(p))"
        case .fsetstat(let req, let h, _): return "FSETSTAT(req: \(req), handle: \(h))"
        case .opendir(let req, let p): return "OPENDIR(req: \(req), path: \(p))"
        case .readdir(let req, let h): return "READDIR(req: \(req), handle: \(h))"
        case .remove(let req, let p): return "REMOVE(req: \(req), path: \(p))"
        case .mkdir(let req, let p, _): return "MKDIR(req: \(req), path: \(p))"
        case .rmdir(let req, let p): return "RMDIR(req: \(req), path: \(p))"
        case .realpath(let req, let p): return "REALPATH(req: \(req), path: \(p))"
        case .stat(let req, let p): return "STAT(req: \(req), path: \(p))"
        case .rename(let req, let o, let n, _): return "RENAME(req: \(req), \(o) -> \(n))"
        case .version(let v): return "VERSION(v: \(v))"
        case .status(let req, let c, let msg): return "STATUS(req: \(req), code: \(c), msg: '\(msg)')"
        case .handle(let req, let h): return "HANDLE(req: \(req), handle: \(h))"
        case .data(let req, let d): return "DATA(req: \(req), bytes: \(d.readableBytes))"
        case .name(let req, let comps): return "NAME(req: \(req), count: \(comps.count))"
        case .attrs(let req, _): return "ATTRS(req: \(req))"
        }
    }
}

// MARK: - Channel Codecs

final class SSHChannelDataUnwrapper: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            Task { @MainActor in
                SFTPSettings.shared.log("Error setting allowRemoteHalfClosure: \(error)")
            }
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channelData = self.unwrapInboundIn(data)
        guard case .byteBuffer(let bytes) = channelData.data, case .channel = channelData.type else {
            return
        }
        BandwidthTracker.shared.recordInbound(bytes: bytes.readableBytes)
        context.fireChannelRead(self.wrapInboundOut(bytes))
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        Task { @MainActor in
            SFTPSettings.shared.log("SSHChannelDataUnwrapper error: \(error.localizedDescription)")
        }
        context.fireErrorCaught(error)
    }
}

final class SSHOutboundChannelDataWrapper: ChannelOutboundHandler, @unchecked Sendable {
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = self.unwrapOutboundIn(data)
        BandwidthTracker.shared.recordOutbound(bytes: buffer.readableBytes)
        context.write(self.wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(buffer))), promise: promise)
    }
}

// MARK: - ByteBuffer SFTP Helpers

fileprivate extension ByteBuffer {
    mutating func readSSHString() -> String? {
        guard let length = readInteger(as: UInt32.self) else { return nil }
        return readString(length: Int(length))
    }

    mutating func readSSHBuffer() -> ByteBuffer? {
        guard let length = readInteger(as: UInt32.self) else { return nil }
        return readSlice(length: Int(length))
    }

    mutating func writeSSHString(_ string: String) {
        writeInteger(UInt32(string.utf8.count))
        writeString(string)
    }

    mutating func writeSSHBuffer(_ buffer: inout ByteBuffer) {
        writeInteger(UInt32(buffer.readableBytes))
        writeBuffer(&buffer)
    }

    mutating func writeSFTPAttributes(_ attributes: SFTPFileAttributes) {
        writeInteger(attributes.flags.rawValue)
        if let size = attributes.size {
            writeInteger(size)
        }
        if let uidgid = attributes.uidgid {
            writeInteger(uidgid.userId)
            writeInteger(uidgid.groupId)
        }
        if let permissions = attributes.permissions {
            writeInteger(permissions)
        }
        if let acmodtime = attributes.accessModificationTime {
            writeInteger(UInt32(acmodtime.accessTime.timeIntervalSince1970))
            writeInteger(UInt32(acmodtime.modificationTime.timeIntervalSince1970))
        }
    }

    mutating func readSFTPAttributes() -> SFTPFileAttributes? {
        guard let flagsRaw = readInteger(as: UInt32.self) else { return nil }
        let flags = SFTPFileAttributes.Flags(rawValue: flagsRaw)
        var attrs = SFTPFileAttributes()

        if flags.contains(.size) {
            guard let size = readInteger(as: UInt64.self) else { return nil }
            attrs.size = size
        }
        if flags.contains(.uidgid) {
            guard let uid = readInteger(as: UInt32.self), let gid = readInteger(as: UInt32.self) else { return nil }
            attrs.uidgid = .init(userId: uid, groupId: gid)
        }
        if flags.contains(.permissions) {
            guard let perms = readInteger(as: UInt32.self) else { return nil }
            attrs.permissions = perms
        }
        if flags.contains(.acmodtime) {
            guard let atime = readInteger(as: UInt32.self), let mtime = readInteger(as: UInt32.self) else { return nil }
            attrs.accessModificationTime = .init(
                accessTime: Date(timeIntervalSince1970: TimeInterval(atime)),
                modificationTime: Date(timeIntervalSince1970: TimeInterval(mtime))
            )
        }
        return attrs
    }
}

// MARK: - Packet Parser & Serializer

final class SFTPPacketParser: ByteToMessageDecoder, @unchecked Sendable {
    typealias InboundOut = SFTPPacket

    func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        let oldIndex = buffer.readerIndex
        guard
            let length = buffer.readInteger(as: UInt32.self),
            let typeRaw = buffer.readInteger(as: UInt8.self),
            var payload = buffer.readSlice(length: Int(length) - 1),
            let type = SFTPPacketType(rawValue: typeRaw)
        else {
            buffer.moveReaderIndex(to: oldIndex)
            return .needMoreData
        }

        let packet: SFTPPacket
        switch type {
        case .`init`:
            guard let version = payload.readInteger(as: UInt32.self) else { return .continue }
            packet = .`init`(version: version)
        case .open:
            guard
                let reqId = payload.readInteger(as: UInt32.self),
                let path = payload.readSSHString(),
                let flags = payload.readInteger(as: UInt32.self),
                let attrs = payload.readSFTPAttributes()
            else { return .continue }
            packet = .open(requestId: reqId, path: path, flags: flags, attributes: attrs)
        case .close:
            guard
                let reqId = payload.readInteger(as: UInt32.self),
                var handleBuf = payload.readSSHBuffer(),
                let handle = handleBuf.readInteger(as: UInt32.self)
            else { return .continue }
            packet = .close(requestId: reqId, handle: handle)
        case .read:
            guard
                let reqId = payload.readInteger(as: UInt32.self),
                var handleBuf = payload.readSSHBuffer(),
                let handle = handleBuf.readInteger(as: UInt32.self),
                let offset = payload.readInteger(as: UInt64.self),
                let length = payload.readInteger(as: UInt32.self)
            else { return .continue }
            packet = .read(requestId: reqId, handle: handle, offset: offset, length: length)
        case .write:
            guard
                let reqId = payload.readInteger(as: UInt32.self),
                var handleBuf = payload.readSSHBuffer(),
                let handle = handleBuf.readInteger(as: UInt32.self),
                let offset = payload.readInteger(as: UInt64.self),
                let data = payload.readSSHBuffer()
            else { return .continue }
            packet = .write(requestId: reqId, handle: handle, offset: offset, data: data)
        case .stat:
            guard let reqId = payload.readInteger(as: UInt32.self), let path = payload.readSSHString() else { return .continue }
            packet = .stat(requestId: reqId, path: path)
        case .lstat:
            guard let reqId = payload.readInteger(as: UInt32.self), let path = payload.readSSHString() else { return .continue }
            packet = .lstat(requestId: reqId, path: path)
        case .fstat:
            guard
                let reqId = payload.readInteger(as: UInt32.self),
                var handleBuf = payload.readSSHBuffer(),
                let handle = handleBuf.readInteger(as: UInt32.self)
            else { return .continue }
            packet = .fstat(requestId: reqId, handle: handle)
        case .setstat:
            guard
                let reqId = payload.readInteger(as: UInt32.self),
                let path = payload.readSSHString(),
                let attrs = payload.readSFTPAttributes()
            else { return .continue }
            packet = .setstat(requestId: reqId, path: path, attributes: attrs)
        case .fsetstat:
            guard
                let reqId = payload.readInteger(as: UInt32.self),
                var handleBuf = payload.readSSHBuffer(),
                let handle = handleBuf.readInteger(as: UInt32.self),
                let attrs = payload.readSFTPAttributes()
            else { return .continue }
            packet = .fsetstat(requestId: reqId, handle: handle, attributes: attrs)
        case .opendir:
            guard let reqId = payload.readInteger(as: UInt32.self), let path = payload.readSSHString() else { return .continue }
            packet = .opendir(requestId: reqId, path: path)
        case .readdir:
            guard
                let reqId = payload.readInteger(as: UInt32.self),
                var handleBuf = payload.readSSHBuffer(),
                let handle = handleBuf.readInteger(as: UInt32.self)
            else { return .continue }
            packet = .readdir(requestId: reqId, handle: handle)
        case .remove:
            guard let reqId = payload.readInteger(as: UInt32.self), let path = payload.readSSHString() else { return .continue }
            packet = .remove(requestId: reqId, path: path)
        case .mkdir:
            guard
                let reqId = payload.readInteger(as: UInt32.self),
                let path = payload.readSSHString(),
                let attrs = payload.readSFTPAttributes()
            else { return .continue }
            packet = .mkdir(requestId: reqId, path: path, attributes: attrs)
        case .rmdir:
            guard let reqId = payload.readInteger(as: UInt32.self), let path = payload.readSSHString() else { return .continue }
            packet = .rmdir(requestId: reqId, path: path)
        case .realpath:
            guard let reqId = payload.readInteger(as: UInt32.self), let path = payload.readSSHString() else { return .continue }
            packet = .realpath(requestId: reqId, path: path)
        case .rename:
            guard
                let reqId = payload.readInteger(as: UInt32.self),
                let oldPath = payload.readSSHString(),
                let newPath = payload.readSSHString(),
                let flags = payload.readInteger(as: UInt32.self)
            else { return .continue }
            packet = .rename(requestId: reqId, oldPath: oldPath, newPath: newPath, flags: flags)
        default:
            return .continue
        }

        context.fireChannelRead(wrapInboundOut(packet))
        return .continue
    }
}

final class SFTPPacketSerializer: MessageToByteEncoder, @unchecked Sendable {
    typealias OutboundIn = SFTPPacket

    func encode(data: SFTPPacket, out: inout ByteBuffer) throws {
        let lengthIndex = out.writerIndex
        out.moveWriterIndex(forwardBy: 4)

        switch data {
        case .version(let version):
            out.writeInteger(SFTPPacketType.version.rawValue)
            out.writeInteger(version)

        case .status(let requestId, let code, let message):
            out.writeInteger(SFTPPacketType.status.rawValue)
            out.writeInteger(requestId)
            out.writeInteger(code)
            out.writeSSHString(message)
            out.writeSSHString("EN")

        case .handle(let requestId, let handleId):
            out.writeInteger(SFTPPacketType.handle.rawValue)
            out.writeInteger(requestId)
            out.writeInteger(UInt32(4))
            out.writeInteger(handleId, endianness: .big)

        case .data(let requestId, var fileData):
            out.writeInteger(SFTPPacketType.data.rawValue)
            out.writeInteger(requestId)
            out.writeSSHBuffer(&fileData)

        case .name(let requestId, let components):
            out.writeInteger(SFTPPacketType.name.rawValue)
            out.writeInteger(requestId)
            out.writeInteger(UInt32(components.count))
            for comp in components {
                out.writeSSHString(comp.filename)
                out.writeSSHString(comp.longname)
                out.writeSFTPAttributes(comp.attributes)
            }

        case .attrs(let requestId, let attributes):
            out.writeInteger(SFTPPacketType.attrs.rawValue)
            out.writeInteger(requestId)
            out.writeSFTPAttributes(attributes)

        default:
            break
        }

        let writtenLength = out.writerIndex - lengthIndex - 4
        out.setInteger(UInt32(writtenLength), at: lengthIndex)
    }
}

// MARK: - SFTP Channel Handler

final class SFTPSessionHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = SFTPPacket

    let delegate: SFTPDelegate
    let username: String?

    private var nextHandleId: UInt32 = 0
    private var openFiles = [UInt32: SFTPFileHandle]()
    private var openDirectories = [UInt32: (SFTPDirectoryHandle, [SFTPFileListing])]()
    private var queue: EventLoopFuture<Void>

    init(delegate: SFTPDelegate, eventLoop: EventLoop, username: String?) {
        self.delegate = delegate
        self.username = username
        self.queue = eventLoop.makeSucceededVoidFuture()
    }

    private func makeContext() -> SSHContext {
        SSHContext(username: self.username)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let packet = unwrapInboundIn(data)
        Task { @MainActor in
            SFTPSettings.shared.log("SFTP In: \(packet.description)")
        }

        switch packet {
        case .`init`(let version):
            guard version >= 3 else {
                context.channel.close(promise: nil)
                return
            }
            context.writeAndFlush(NIOAny(SFTPPacket.version(version: 3)), promise: nil)

        case .open(let reqId, let path, let flags, let attrs):
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                    do {
                        let file = try await self.delegate.openFile(
                            path,
                            withAttributes: attrs,
                            flags: SFTPOpenFileFlags(rawValue: flags),
                            context: self.makeContext()
                        )
                        context.eventLoop.execute {
                            let id = self.nextHandleId
                            self.nextHandleId &+= 1
                            self.openFiles[id] = file
                            context.writeAndFlush(NIOAny(SFTPPacket.handle(requestId: reqId, handle: id)), promise: nil)
                        }
                    } catch {
                        context.eventLoop.execute {
                            context.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 2, message: error.localizedDescription)), promise: nil)
                        }
                    }
                }
                return promise.futureResult
            }

        case .close(let reqId, let handleId):
            if let file = openFiles.removeValue(forKey: handleId) {
                queue = queue.flatMap {
                    let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
                    promise.completeWithTask {
                        try await file.close()
                    }
                    return promise.futureResult.flatMap { _ in
                        context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 0, message: "")))
                    }.flatMapError { _ in
                        context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 0, message: "")))
                    }
                }
            } else if openDirectories.removeValue(forKey: handleId) != nil {
                queue = queue.flatMap {
                    context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 0, message: "")))
                }
            } else {
                queue = queue.flatMap {
                    context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 0, message: "")))
                }
            }

        case .read(let reqId, let handleId, let offset, let length):
            guard let file = openFiles[handleId] else {
                queue = queue.flatMap {
                    context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 4, message: "Bad handle")))
                }
                return
            }
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: ByteBuffer.self)
                promise.completeWithTask {
                    try await file.read(at: offset, length: length)
                }
                return promise.futureResult.flatMap { data in
                    if data.readableBytes == 0 {
                        return context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 1, message: "EOF")))
                    } else {
                        return context.channel.writeAndFlush(NIOAny(SFTPPacket.data(requestId: reqId, data: data)))
                    }
                }.flatMapError { _ in
                    context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 1, message: "EOF")))
                }
            }

        case .write(let reqId, let handleId, let offset, let data):
            guard let file = openFiles[handleId] else {
                queue = queue.flatMap {
                    context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 4, message: "Bad handle")))
                }
                return
            }
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
                promise.completeWithTask {
                    try await file.write(data, atOffset: offset)
                }
                return promise.futureResult.flatMap { status in
                    let code: UInt32 = (status == .ok) ? 0 : 4
                    return context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: code, message: "")))
                }.flatMapError { _ in
                    context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 4, message: "")))
                }
            }

        case .stat(let reqId, let path), .lstat(let reqId, let path):
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                    do {
                        let attrs = try await self.delegate.fileAttributes(atPath: path, context: self.makeContext())
                        context.eventLoop.execute {
                            context.writeAndFlush(NIOAny(SFTPPacket.attrs(requestId: reqId, attributes: attrs)), promise: nil)
                        }
                    } catch {
                        context.eventLoop.execute {
                            context.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 2, message: error.localizedDescription)), promise: nil)
                        }
                    }
                }
                return promise.futureResult
            }

        case .fstat(let reqId, let handleId):
            guard let file = openFiles[handleId] else {
                queue = queue.flatMap {
                    context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 4, message: "Bad handle")))
                }
                return
            }
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                    do {
                        let attrs = try await file.readFileAttributes()
                        context.eventLoop.execute {
                            context.writeAndFlush(NIOAny(SFTPPacket.attrs(requestId: reqId, attributes: attrs)), promise: nil)
                        }
                    } catch {
                        context.eventLoop.execute {
                            context.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 4, message: error.localizedDescription)), promise: nil)
                        }
                    }
                }
                return promise.futureResult
            }

        case .setstat(let reqId, let path, let attrs):
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                    let status = (try? await self.delegate.setFileAttributes(to: attrs, atPath: path, context: self.makeContext())) ?? .failure
                    let code: UInt32 = (status == .ok) ? 0 : 4
                    context.eventLoop.execute {
                        context.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: code, message: "")), promise: nil)
                    }
                }
                return promise.futureResult
            }

        case .fsetstat(let reqId, let handleId, let attrs):
            guard let file = openFiles[handleId] else {
                queue = queue.flatMap {
                    context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 4, message: "Bad handle")))
                }
                return
            }
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                    try? await file.setFileAttributes(to: attrs)
                    context.eventLoop.execute {
                        context.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 0, message: "")), promise: nil)
                    }
                }
                return promise.futureResult
            }

        case .realpath(let reqId, let path):
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                    do {
                        let components = try await self.delegate.realPath(for: path, context: self.makeContext())
                        context.eventLoop.execute {
                            context.writeAndFlush(NIOAny(SFTPPacket.name(requestId: reqId, components: components)), promise: nil)
                        }
                    } catch {
                        context.eventLoop.execute {
                            context.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 2, message: error.localizedDescription)), promise: nil)
                        }
                    }
                }
                return promise.futureResult
            }

        case .opendir(let reqId, let path):
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                    do {
                        let dirHandle = try await self.delegate.openDirectory(atPath: path, context: self.makeContext())
                        let listing = try await dirHandle.listFiles(context: self.makeContext())
                        context.eventLoop.execute {
                            let id = self.nextHandleId
                            self.nextHandleId &+= 1
                            self.openDirectories[id] = (dirHandle, listing)
                            context.writeAndFlush(NIOAny(SFTPPacket.handle(requestId: reqId, handle: id)), promise: nil)
                        }
                    } catch {
                        context.eventLoop.execute {
                            context.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 2, message: error.localizedDescription)), promise: nil)
                        }
                    }
                }
                return promise.futureResult
            }

        case .readdir(let reqId, let handleId):
            queue = queue.flatMap {
                guard var (dirHandle, listing) = self.openDirectories[handleId] else {
                    return context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 4, message: "Bad handle")))
                }
                if listing.isEmpty {
                    return context.channel.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: 1, message: "EOF")))
                } else {
                    let first = listing.removeFirst()
                    self.openDirectories[handleId] = (dirHandle, listing)
                    return context.channel.writeAndFlush(NIOAny(SFTPPacket.name(requestId: reqId, components: first.path)))
                }
            }

        case .remove(let reqId, let path):
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                    let status = (try? await self.delegate.removeFile(path, context: self.makeContext())) ?? .failure
                    let code: UInt32 = (status == .ok) ? 0 : 4
                    context.eventLoop.execute {
                        context.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: code, message: "")), promise: nil)
                    }
                }
                return promise.futureResult
            }

        case .rmdir(let reqId, let path):
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                    let status = (try? await self.delegate.removeDirectory(path, context: self.makeContext())) ?? .failure
                    let code: UInt32 = (status == .ok) ? 0 : 4
                    context.eventLoop.execute {
                        context.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: code, message: "")), promise: nil)
                    }
                }
                return promise.futureResult
            }

        case .mkdir(let reqId, let path, let attrs):
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                    let status = (try? await self.delegate.createDirectory(path, withAttributes: attrs, context: self.makeContext())) ?? .failure
                    let code: UInt32 = (status == .ok) ? 0 : 4
                    context.eventLoop.execute {
                        context.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: code, message: "")), promise: nil)
                    }
                }
                return promise.futureResult
            }

        case .rename(let reqId, let oldPath, let newPath, let flags):
            queue = queue.flatMap {
                let promise = context.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                    let status = (try? await self.delegate.rename(oldPath: oldPath, newPath: newPath, flags: flags, context: self.makeContext())) ?? .failure
                    let code: UInt32 = (status == .ok) ? 0 : 4
                    context.eventLoop.execute {
                        context.writeAndFlush(NIOAny(SFTPPacket.status(requestId: reqId, code: code, message: "")), promise: nil)
                    }
                }
                return promise.futureResult
            }

        default:
            break
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case ChannelEvent.inputClosed:
            Task { @MainActor in
                SFTPSettings.shared.log("Client closed input (EOF), waiting for queue to drain before closing channel...")
            }
            queue = queue.flatMap {
                Task { @MainActor in
                    SFTPSettings.shared.log("Queue drained. Closing child channel now.")
                }
                return context.channel.close()
            }
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        Task { @MainActor in
            SFTPSettings.shared.log("SFTPSessionHandler error: \(error.localizedDescription)")
        }
        context.fireErrorCaught(error)
    }
}

// MARK: - Subsystem Dispatcher

final class SFTPSubsystemHandler: ChannelDuplexHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = SSHChannelData
    typealias OutboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData

    let sftpDelegate: SFTPDelegate

    init(sftpDelegate: SFTPDelegate) {
        self.sftpDelegate = sftpDelegate
    }

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            Task { @MainActor in
                SFTPSettings.shared.log("Failed to set allowRemoteHalfClosure on subsystem handler: \(error)")
            }
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let req as SSHChannelRequestEvent.SubsystemRequest:
            if req.subsystem == "sftp" {
                Task { @MainActor in
                    SFTPSettings.shared.log("Subsystem 'sftp' accepted")
                }
                let channel = context.channel
                _ = channel.pipeline.addHandlers([
                    SSHChannelDataUnwrapper(),
                    SSHOutboundChannelDataWrapper(),
                    ByteToMessageHandler(SFTPPacketParser()),
                    MessageToByteHandler(SFTPPacketSerializer()),
                    SFTPSessionHandler(delegate: self.sftpDelegate, eventLoop: channel.eventLoop, username: nil)
                ]).flatMap {
                    context.pipeline.removeHandler(self)
                }.flatMap {
                    let promise = context.eventLoop.makePromise(of: Void.self)
                    channel.triggerUserOutboundEvent(ChannelSuccessEvent(), promise: promise)
                    return promise.futureResult
                }
            } else {
                Task { @MainActor in
                    SFTPSettings.shared.log("Rejected unknown subsystem: \(req.subsystem)")
                }
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent(), promise: nil)
            }

        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        Task { @MainActor in
            SFTPSettings.shared.log("SFTPSubsystemHandler error: \(error.localizedDescription)")
        }
        context.fireErrorCaught(error)
    }
}

// MARK: - Native SFTP Server Engine

final class SFTPServerEngine: @unchecked Sendable {
    private let channel: Channel
    private let group: MultiThreadedEventLoopGroup

    init(channel: Channel, group: MultiThreadedEventLoopGroup) {
        self.channel = channel
        self.group = group
    }

    func close() async {
        try? await channel.close()
        try? await group.shutdownGracefully()
    }

    static func start(
        port: Int,
        hostKeys: [NIOSSHPrivateKey],
        sftpDelegate: SFTPDelegate,
        authDelegate: NIOSSHServerUserAuthenticationDelegate
    ) async throws -> SFTPServerEngine {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

        final class ServerGlobalDelegate: GlobalRequestDelegate, @unchecked Sendable {}
        let globalDelegate = ServerGlobalDelegate()

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let serverConfig = SSHServerConfiguration(
                    hostKeys: hostKeys,
                    userAuthDelegate: authDelegate,
                    globalRequestDelegate: globalDelegate
                )

                return channel.pipeline.addHandler(
                    NIOSSHHandler(
                        role: .server(serverConfig),
                        allocator: channel.allocator,
                        inboundChildChannelInitializer: { childChannel, channelType in
                            guard channelType == .session else {
                                return childChannel.close()
                            }
                            return childChannel.pipeline.addHandler(
                                SFTPSubsystemHandler(sftpDelegate: sftpDelegate)
                            )
                        }
                    )
                )
            }

        let channel = try await bootstrap.bind(host: "0.0.0.0", port: port).get()
        return SFTPServerEngine(channel: channel, group: group)
    }
}
