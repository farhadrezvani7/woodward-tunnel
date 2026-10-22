import UIKit

enum ImageNormalizer {
    /// The core decodes PNG and JPEG. Camera-roll photos are often HEIC, so convert those.
    /// Returns nil when the bytes are not an image at all.
    static func pngOrJPEG(_ data: Data) -> Data? {
        switch ImageSniffer.sniff(data) {
        case .png, .jpeg:
            return data
        case .other:
            guard let image = UIImage(data: data) else { return nil }
            return image.jpegData(compressionQuality: 0.95)
        }
    }
}
