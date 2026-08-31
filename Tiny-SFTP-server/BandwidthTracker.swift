//
//  BandwidthTracker.swift
//  Tiny-SFTP-server
//

import Foundation

/// Thread-safe accumulator for monitoring real-time network throughput.
final class BandwidthTracker: @unchecked Sendable {
    static let shared = BandwidthTracker()
    
    private let lock = NSLock()
    private var totalBytesIn: UInt64 = 0
    private var totalBytesOut: UInt64 = 0
    private var lastBytesIn: UInt64 = 0
    private var lastBytesOut: UInt64 = 0
    private var lastTimestamp: Date = Date()
    
    func recordInbound(bytes: Int) {
        guard bytes > 0 else { return }
        lock.lock()
        totalBytesIn &+= UInt64(bytes)
        lock.unlock()
    }
    
    func recordOutbound(bytes: Int) {
        guard bytes > 0 else { return }
        lock.lock()
        totalBytesOut &+= UInt64(bytes)
        lock.unlock()
    }
    
    func reset() {
        lock.lock()
        totalBytesIn = 0
        totalBytesOut = 0
        lastBytesIn = 0
        lastBytesOut = 0
        lastTimestamp = Date()
        lock.unlock()
    }
    
    /// Returns a snapshot of live throughput (in Mbps) and total accumulated byte counts.
    func sampleThroughput() -> (inputMbps: Double, outputMbps: Double, totalBytesIn: UInt64, totalBytesOut: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        
        let now = Date()
        let elapsed = now.timeIntervalSince(lastTimestamp)
        guard elapsed >= 0.1 else {
            return (0.0, 0.0, totalBytesIn, totalBytesOut)
        }
        
        let deltaIn = totalBytesIn >= lastBytesIn ? (totalBytesIn - lastBytesIn) : 0
        let deltaOut = totalBytesOut >= lastBytesOut ? (totalBytesOut - lastBytesOut) : 0
        
        lastBytesIn = totalBytesIn
        lastBytesOut = totalBytesOut
        lastTimestamp = now
        
        // 1 Byte = 8 bits. 1 Megabit = 1,000,000 bits.
        let inputMbps = (Double(deltaIn) * 8.0) / (elapsed * 1_000_000.0)
        let outputMbps = (Double(deltaOut) * 8.0) / (elapsed * 1_000_000.0)
        
        return (inputMbps, outputMbps, totalBytesIn, totalBytesOut)
    }
}
