# Tiny SFTP Server

A lightweight, native macOS SFTP server application built with SwiftUI and Swift Concurrency. **Tiny SFTP Server** makes it easy to turn any local directory into a secure SFTP share in seconds.

---

## Features

- **Native macOS Interface**: Clean, minimal SwiftUI control panel.
- **Custom Folder Sharing**: Select any folder using native macOS file dialogs with persistent security-scoped bookmark support.
- **Configurable Port & Auth**:
  - Custom listening port (default `2222`).
  - Username and password protection.
  - Optional anonymous login mode.
- **Sleep Prevention**: Built-in macOS IOKit power assertions prevent your Mac from sleeping while the server is running.
- **Persistent Host Key**: Automatically saves a stable ED25519 host key so SFTP clients (FileZilla, Cyberduck, Transmit, etc.) don't trigger "Host key changed" warnings on every restart.
- **Hardened File Operations**:
  - Strict path normalization to prevent directory traversal and symlink escape attacks.
  - Pipelined read support and file truncation handling for accurate uploads.
- **Live Activity Logs**: Real-time server log feed with one-click clipboard copying.
- **Swift 6 Ready**: Modern Swift concurrency with strict actor isolation.

---

## Getting Started

### Prerequisites

- macOS 14.0 (Sonoma) or later
- Xcode 15 or 16

### Building and Running

1. Clone the repository:
   ```bash
   git clone https://github.com/Eddy-Barraud/Tiny-SFTP-Server.git
   cd Tiny-SFTP-Server
   ```
2. Open `Tiny-SFTP-server.xcodeproj` in Xcode.
3. Select the `Tiny-SFTP-server` scheme and click **Run** (`⌘R`).

### How to Use

1. Click **Browse...** to pick the folder you wish to share.
2. Configure your desired **Port** (e.g. `2222`).
3. Set your **Username** and **Password**, or enable **Allow anonymous connections**.
4. (Optional) Check **Prevent Mac from sleeping when server is running**.
5. Click **Start Server**.
6. Connect using any standard SFTP client:
   ```bash
   sftp -P 2222 username@<your-mac-ip>
   ```

---

## Credits & Acknowledgements

This project is made possible thanks to the following open-source projects:

- **[Citadel](https://github.com/orlandos-nl/Citadel)** by [Joannis Orlandos](https://github.com/orlandos-nl): An elegant SSH and SFTP library for Swift built on top of SwiftNIO.
- **[SwiftNIO SSH](https://github.com/apple/swift-nio-ssh)** & **[SwiftNIO](https://github.com/apple/swift-nio)** by Apple.

---

## License

This project is licensed under the MIT License.
