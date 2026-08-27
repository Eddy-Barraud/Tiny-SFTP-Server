import Foundation
import IOKit.pwr_mgt

class SleepPreventer {
    static let shared = SleepPreventer()
    
    private var assertionID: IOPMAssertionID = 0
    private var isPreventingSleep = false
    
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
            print("Successfully prevented sleep.")
        } else {
            print("Failed to prevent sleep.")
        }
    }
    
    func stopPreventingSleep() {
        guard isPreventingSleep else { return }
        
        let success = IOPMAssertionRelease(assertionID)
        if success == kIOReturnSuccess {
            isPreventingSleep = false
            print("Successfully allowed sleep.")
        } else {
            print("Failed to allow sleep.")
        }
    }
}
