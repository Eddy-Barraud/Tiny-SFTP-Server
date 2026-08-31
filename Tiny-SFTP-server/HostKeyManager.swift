//
//  HostKeyManager.swift
//  Tiny-SFTP-server
//

import Foundation
import SwiftData
import Crypto
import NIOSSH

/// Manages SSH Host Identification persistence using SwiftData.
@MainActor
final class HostKeyManager {
    static let shared = HostKeyManager()
    
    let modelContainer: ModelContainer
    
    init() {
        do {
            let schema = Schema([HostIdentity.self])
            let configuration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: false)
            self.modelContainer = try ModelContainer(for: schema, configurations: [configuration])
        } catch {
            fatalError("Failed to initialize SwiftData ModelContainer for HostIdentity: \(error)")
        }
    }
    
    /// Retrieves the persisted host key from SwiftData, or generates, persists, and returns a new Ed25519 host key.
    func getOrCreateHostPrivateKey() -> NIOSSHPrivateKey {
        let context = ModelContext(modelContainer)
        let descriptor = FetchDescriptor<HostIdentity>(
            predicate: #Predicate<HostIdentity> { $0.id == "primary" }
        )
        
        do {
            let identities = try context.fetch(descriptor)
            if let existing = identities.first {
                let curveKey = try Curve25519.Signing.PrivateKey(rawRepresentation: existing.rawPrivateKey)
                SFTPSettings.shared.log("Loaded persistent host identification (Ed25519, created \(existing.createdAt.formatted(date: .abbreviated, time: .shortened)))")
                return NIOSSHPrivateKey(ed25519Key: curveKey)
            }
        } catch {
            SFTPSettings.shared.log("Notice: Could not load existing host key (\(error.localizedDescription)). Generating a new one.")
        }
        
        // Generate a new Ed25519 host private key and persist it
        let newCurveKey = Curve25519.Signing.PrivateKey()
        let newIdentity = HostIdentity(id: "primary", rawPrivateKey: newCurveKey.rawRepresentation, keyType: "ed25519")
        context.insert(newIdentity)
        do {
            try context.save()
            SFTPSettings.shared.log("Generated and saved new persistent host identification (Ed25519)")
        } catch {
            SFTPSettings.shared.log("Warning: Failed to persist host identification to SwiftData: \(error.localizedDescription)")
        }
        
        return NIOSSHPrivateKey(ed25519Key: newCurveKey)
    }
}

