//! Subscription download. HTTPS only, small size cap, no private-network targets.

use std::net::IpAddr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FetchError {
    #[error("only https links can be downloaded")]
    NotHttps,
    #[error("this address points to a private network")]
    PrivateAddress,
    #[error("download failed: {0}")]
    Failed(String),
    #[error("response is too large")]
    TooLarge,
}

impl FetchError {
    pub fn user_message(&self) -> String {
        match self {
            FetchError::NotHttps => "فقط لینک‌های https قابل دریافت هستند.".into(),
            FetchError::PrivateAddress => "این آدرس به شبکهٔ داخلی اشاره می‌کند و دریافت نمی‌شود.".into(),
            FetchError::Failed(_) => "دریافت لینک اشتراک ناموفق بود. اتصال اینترنت و درستی لینک را بررسی کنید.".into(),
            FetchError::TooLarge => "پاسخ سرور بزرگ‌تر از حد معمول یک اشتراک است.".into(),
        }
    }
}

pub trait Fetcher: Send + Sync {
    fn get(&self, url: &str) -> Result<String, FetchError>;
}

/// Reject non-https and obviously private/loopback hosts before any request is made.
pub fn check_url(url: &str) -> Result<(), FetchError> {
    let rest = url.strip_prefix("https://").ok_or(FetchError::NotHttps)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    let host = if let Some(h) = host.strip_prefix('[') { h.split(']').next().unwrap_or("") } else { host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host) };
    if host.is_empty() {
        return Err(FetchError::Failed("empty host".into()));
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") || lower.ends_with(".internal") {
        return Err(FetchError::PrivateAddress);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        let private = match ip {
            IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast(),
            IpAddr::V6(v) => v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
        };
        if private {
            return Err(FetchError::PrivateAddress);
        }
    }
    Ok(())
}

#[cfg(feature = "http")]
pub struct HttpFetcher;

#[cfg(feature = "http")]
impl Fetcher for HttpFetcher {
    fn get(&self, url: &str) -> Result<String, FetchError> {
        use std::io::Read;
        check_url(url)?;
        const MAX: u64 = 5 * 1024 * 1024;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(20)))
            .https_only(true)
            .max_redirects(3)
            .build()
            .into();
        let mut resp = agent.get(url).header("User-Agent", "woodward-tunnel").call().map_err(|e| FetchError::Failed(e.to_string()))?;
        let mut body = String::new();
        resp.body_mut().as_reader().take(MAX + 1).read_to_string(&mut body).map_err(|e| FetchError::Failed(e.to_string()))?;
        if body.len() as u64 > MAX {
            return Err(FetchError::TooLarge);
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_policy() {
        assert!(check_url("https://panel.example.com/sub?token=abc").is_ok());
        assert_eq!(check_url("http://panel.example.com/x"), Err(FetchError::NotHttps));
        for bad in ["https://localhost/x", "https://127.0.0.1/x", "https://10.1.2.3/x", "https://192.168.0.5:8443/x", "https://[::1]/x", "https://printer.local/x", "https://169.254.169.254/latest", "https://user:pw@172.16.0.1/x"] {
            assert_eq!(check_url(bad), Err(FetchError::PrivateAddress), "{bad}");
        }
    }
}
