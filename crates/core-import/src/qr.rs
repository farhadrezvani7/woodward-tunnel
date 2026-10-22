//! QR codes and raw file bytes. Camera scanning is done by the platform UI, which passes the
//! decoded text to [`crate::analyze`]; this module covers images picked from disk or the clipboard.

use crate::analyze::{analyze, Analysis};
use core_model::ConfigIssue;

const MAX_IMAGE_BYTES: usize = 12 * 1024 * 1024;
const MAX_PIXELS: u64 = 40_000_000;

/// Decode every QR code found in a PNG/JPEG image.
pub fn decode_image(bytes: &[u8]) -> Result<Vec<String>, ConfigIssue> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(ConfigIssue::TooLarge(bytes.len()));
    }
    let reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| ConfigIssue::Unrecognized)?;
    let (w, h) = reader
        .into_dimensions()
        .map_err(|_| ConfigIssue::Unrecognized)?;
    if u64::from(w) * u64::from(h) > MAX_PIXELS {
        return Err(ConfigIssue::TooLarge(bytes.len()));
    }
    let img = image::load_from_memory(bytes)
        .map_err(|_| ConfigIssue::Unrecognized)?
        .to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(img);
    let texts: Vec<String> = prepared
        .detect_grids()
        .into_iter()
        .filter_map(|g| g.decode().ok().map(|(_, c)| c))
        .collect();
    if texts.is_empty() {
        return Err(ConfigIssue::Unrecognized);
    }
    Ok(texts)
}

fn is_image(b: &[u8]) -> bool {
    b.starts_with(&[0x89, b'P', b'N', b'G']) || b.starts_with(&[0xFF, 0xD8, 0xFF])
}

/// Analyze file/clipboard bytes: an image is scanned for QR codes, anything else is read as text.
pub fn analyze_bytes(bytes: &[u8]) -> Analysis {
    if is_image(bytes) {
        return match decode_image(bytes) {
            Ok(texts) => {
                let mut all = Analysis::default();
                for t in texts {
                    let a = analyze(&t);
                    all.profiles.extend(a.profiles);
                    all.issues.extend(a.issues);
                    all.subscription_urls.extend(a.subscription_urls);
                }
                all
            }
            Err(e) => {
                let mut a = Analysis::default();
                a.issues.push(crate::analyze::Issue {
                    label: "image".into(),
                    issue: e,
                });
                a
            }
        };
    }
    // UTF-16 with BOM (Windows Notepad "Unicode") is common for exported configs.
    let text = if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        let le = bytes[0] == 0xFF;
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    analyze(&text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageFormat, Luma};
    use std::io::Cursor;

    fn qr_png(text: &str) -> Vec<u8> {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let img = code.render::<Luma<u8>>().min_dimensions(300, 300).build();
        let mut out = Vec::new();
        image::DynamicImage::ImageLuma8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn qr_image_with_share_link() {
        let link = "trojan://pw1234@a.example.com:443?sni=a.example.com#QR";
        let a = analyze_bytes(&qr_png(link));
        assert_eq!(a.profiles.len(), 1, "{:?}", a.issues);
        assert_eq!(a.profiles[0].name, "QR");
    }

    #[test]
    fn image_without_qr_is_reported() {
        let blank = {
            let img = image::GrayImage::from_pixel(200, 200, Luma([255]));
            let mut out = Vec::new();
            image::DynamicImage::ImageLuma8(img)
                .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
                .unwrap();
            out
        };
        let a = analyze_bytes(&blank);
        assert!(a.profiles.is_empty() && a.issues.len() == 1);
    }

    #[test]
    fn utf16_text_file() {
        let text = "trojan://pw1234@a.example.com:443#U";
        let mut bytes = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            bytes.extend(u.to_le_bytes());
        }
        assert_eq!(analyze_bytes(&bytes).profiles.len(), 1);
    }

    #[test]
    fn garbage_bytes_do_not_panic() {
        for b in [
            &[0u8; 0][..],
            &[0x89, b'P', b'N', b'G', 1, 2, 3][..],
            &[0xFF, 0xD8, 0xFF, 0, 0][..],
            &[0xFF, 0xFE, 0x41][..],
        ] {
            let _ = analyze_bytes(b);
        }
    }
}
