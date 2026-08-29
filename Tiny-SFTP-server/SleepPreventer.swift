import Foundation
import IOKit.pwr_mgt

/// Manages system sleep prevention using macOS IOKit power assertions while the SFTP server is active.
@MainActor
class SleepPreventer {
    static let shared = SleepPreventer()
    
    private var assertionID: IOPMAssertionID = 0
    private var isPreventingSleep = false
    
    /// Requests a power management assertion to prevent the Mac from entering display and system sleep.
    func startPreventingSleep() {
        guard !isPreventingSleep else { return }
        
        let reasonForActivity = "Tiny SFTP Server is running" as CFString
        let success = IOPMAssertionCreateWithName(
            kIOPMAssertionTypeNoDisplaySleep as CFString,
            IOPMAssertionLevel(kIOPMAssertionLevelOn),
            reasonForActivity,
            &assertionID
        )
        
        if success == kIOReturnSuccess {
            isPreventingSleep = true
            #if DEBUG
            print("Sleep prevention activated.")
            #endif
        } else {
            #if DEBUG
            print("Failed to activate sleep prevention. Return code: \(success)")
            #endif
        }
    }
    
    /// Releases the active power management assertion, allowing the system to sleep normally.
    func stopPreventingSleep() {
        guard isPreventingSleep else { return }
        
        let success = IOPMAssertionRelease(assertionID)
        if success == kIOReturnSuccess {
            isPreventingSleep = false
            #if DEBUG
            print("Sleep prevention released.")
            #endif
        } else {
            #if DEBUG
            print("Failed to release sleep prevention assertion. Return code: \(success)")
            #endif
        }
    }
}
