import Foundation

/// Recognises the container format of picked image bytes. The core decodes PNG and JPEG only,
/// so anything else (HEIC from the camera roll, for example) is converted by the app first.
public enum ImageFormat: Equatable {
    case png
    case jpeg
    case other
}

public enum ImageSniffer {
    public static func sniff(_ data: Data) -> ImageFormat {
        let b = [UInt8](data.prefix(8))
        if b.count >= 8, b[0] == 0x89, b[1] == 0x50, b[2] == 0x4E, b[3] == 0x47,
           b[4] == 0x0D, b[5] == 0x0A, b[6] == 0x1A, b[7] == 0x0A {
            return .png
        }
        if b.count >= 3, b[0] == 0xFF, b[1] == 0xD8, b[2] == 0xFF {
            return .jpeg
        }
        return .other
    }
}
