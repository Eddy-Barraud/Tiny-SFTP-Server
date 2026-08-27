//
//  Item.swift
//  Tiny-SFTP-server
//
//  Created by Eddy Barraud on 27/08/2026.
//

import Foundation
import SwiftData

@Model
final class Item {
    var timestamp: Date
    
    init(timestamp: Date) {
        self.timestamp = timestamp
    }
}
