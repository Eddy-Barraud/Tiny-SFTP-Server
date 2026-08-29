//
//  Tiny_SFTP_serverApp.swift
//  Tiny-SFTP-server
//
//  Created by Eddy Barraud on 27/08/2026.
//

import SwiftUI

@main
struct Tiny_SFTP_serverApp: App {
    @StateObject private var settings = SFTPSettings.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(settings)
        }
        .windowResizability(.contentSize)
        .defaultSize(width: 320, height: 600)
    }
}
