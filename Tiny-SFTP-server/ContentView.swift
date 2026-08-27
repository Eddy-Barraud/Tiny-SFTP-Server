//
//  ContentView.swift
//  Tiny-SFTP-server
//
//  Created by Eddy Barraud on 27/08/2026.
//

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var settings: SFTPSettings
    @State private var isLogsExpanded: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            
            HStack {
                Text("Shared Folder:")
                    .frame(width: 100, alignment: .trailing)
                TextField("Select a folder...", text: $settings.sharedFolderPath)
                    .disabled(true)
                Button("Browse...") {
                    selectFolder()
                }
                .disabled(settings.isServerRunning)
            }
            
            HStack {
                Text("Port:")
                    .frame(width: 100, alignment: .trailing)
                TextField("e.g. 2222", text: $settings.port)
                    .frame(width: 80)
                    .disabled(settings.isServerRunning)
            }
            
            HStack {
                Spacer().frame(width: 100)
                Toggle("Prevent Mac from sleeping when server is running", isOn: $settings.preventSleep)
            }
            
            Divider()
            
            HStack {
                Spacer().frame(width: 100)
                Toggle("Allow anonymous connections (Any password)", isOn: $settings.allowAnonymous)
            }
            
            HStack {
                Text("Username:")
                    .frame(width: 100, alignment: .trailing)
                TextField("Username", text: $settings.username)
            }
            
            HStack {
                Text("Password:")
                    .frame(width: 100, alignment: .trailing)
                SecureField("Password", text: $settings.password)
            }
            
            HStack {
                Spacer().frame(width: 100)
                Button("Wipe Credentials") {
                    settings.username = ""
                    settings.password = ""
                }
            }
            
            Divider()
            
            HStack {
                Spacer()
                if settings.isServerRunning {
                    Button("Stop Server") {
                        SFTPServer.shared.stop()
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                } else {
                    Button("Start Server") {
                        if settings.sharedFolderPath.isEmpty {
                            selectFolder()
                        }
                        if !settings.sharedFolderPath.isEmpty {
                            SFTPServer.shared.start()
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
                }
                Spacer()
            }
            
            DisclosureGroup(isExpanded: $isLogsExpanded) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(settings.logs) { log in
                            Text(log.message)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(height: 150)
                .padding(4)
                .background(Color(NSColor.textBackgroundColor))
                .cornerRadius(4)
            } label: {
                HStack {
                    Text("Server Logs")
                    Spacer()
                    Button("Copy") {
                        let logText = settings.logs.map { $0.message }.joined(separator: "\n")
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(logText, forType: .string)
                    }
                    .buttonStyle(BorderlessButtonStyle())
                }
            }
            
        }
        .padding()
        .frame(width: 450)
    }
    
    private func selectFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK {
            if let url = panel.url {
                settings.sharedFolderPath = url.path
                do {
                    let bookmarkData = try url.bookmarkData(options: .withSecurityScope, includingResourceValuesForKeys: nil, relativeTo: nil)
                    settings.sharedFolderBookmark = bookmarkData
                } catch {
                    print("Failed to save bookmark: \(error)")
                }
            }
        }
    }
}

#Preview {
    ContentView()
        .environmentObject(SFTPSettings.shared)
}
