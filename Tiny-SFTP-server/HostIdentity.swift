//
//  HostIdentity.swift
//  Tiny-SFTP-server
//

import Foundation
import SwiftData

/// SwiftData persistent model representing the SFTP/SSH host identification key.
@Model
final class HostIdentity {
    /// Identifier for key uniqueness (e.g. primary host key)
    @Attribute(.unique) var id: String
    var rawPrivateKey: Data
    var keyType: String
    var createdAt: Date
    
    init(id: String = "primary", rawPrivateKey: Data, keyType: String = "ed25519", createdAt: Date = Date()) {
        self.id = id
        self.rawPrivateKey = rawPrivateKey
        self.keyType = keyType
        self.createdAt = createdAt
    }
}

