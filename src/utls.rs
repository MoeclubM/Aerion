use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, de};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UtlsFingerprint {
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    Qihoo360,
    Qq,
    Random,
    Randomized,
    RandomizedAlpn,
    RandomizedNoAlpn,
}

impl UtlsFingerprint {
    pub fn from_mihomo_name(value: &str) -> Result<Option<Self>> {
        let value = value.trim();
        let normalized = value.to_ascii_lowercase().replace(['-', '_'], "");
        if value.is_empty()
            || normalized == "none"
            || normalized == "unsafe"
            || normalized == "golang"
            || normalized == "hellogolang"
        {
            return Ok(None);
        }
        Ok(Some(value.parse()?))
    }

    pub fn as_mihomo_name(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Edge => "edge",
            Self::Qihoo360 => "360",
            Self::Qq => "qq",
            Self::Random => "random",
            Self::Randomized => "randomized",
            Self::RandomizedAlpn => "randomizedalpn",
            Self::RandomizedNoAlpn => "randomizednoalpn",
        }
    }

    pub fn as_utls_client_hello_id(self) -> &'static str {
        match self {
            Self::Chrome => "HelloChrome_133",
            Self::Firefox => "HelloFirefox_148",
            Self::Safari => "HelloSafari_26_3",
            Self::Ios => "HelloIOS_14",
            Self::Android => "HelloAndroid_11_OkHttp",
            Self::Edge => "HelloEdge_106",
            Self::Qihoo360 => "Hello360_11_0",
            Self::Qq => "HelloQQ_11_1",
            Self::Random | Self::Randomized => "HelloRandomized",
            Self::RandomizedAlpn => "HelloRandomizedALPN",
            Self::RandomizedNoAlpn => "HelloRandomizedNoALPN",
        }
    }

    pub fn is_randomized(self) -> bool {
        matches!(
            self,
            Self::Random | Self::Randomized | Self::RandomizedAlpn | Self::RandomizedNoAlpn
        )
    }

    pub fn rustls_alpn_protocols(self) -> Vec<Vec<u8>> {
        match self {
            Self::RandomizedNoAlpn => Vec::new(),
            Self::Safari | Self::Ios => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Self::Chrome
            | Self::Firefox
            | Self::Android
            | Self::Edge
            | Self::Qihoo360
            | Self::Qq
            | Self::Random
            | Self::Randomized
            | Self::RandomizedAlpn => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    }

    pub fn rustls_profile_note(self) -> &'static str {
        match self {
            Self::RandomizedNoAlpn => {
                "rustls profile with no ALPN; ClientHello extension order is still rustls"
            }
            _ => {
                "rustls profile with browser-like ALPN; ClientHello extension order is still rustls"
            }
        }
    }
}

impl FromStr for UtlsFingerprint {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let normalized = value.trim().to_ascii_lowercase().replace(['-', '_'], "");
        match normalized.as_str() {
            "chrome" | "hellochrome" | "hellochromeauto" => Ok(Self::Chrome),
            other if other.starts_with("hellochrome") || other.starts_with("chrome") => {
                Ok(Self::Chrome)
            }
            "firefox" | "hellofirefox" | "hellofirefoxauto" => Ok(Self::Firefox),
            other if other.starts_with("hellofirefox") || other.starts_with("firefox") => {
                Ok(Self::Firefox)
            }
            "safari" | "hellosafari" | "hellosafariauto" => Ok(Self::Safari),
            other if other.starts_with("hellosafari") || other.starts_with("safari") => {
                Ok(Self::Safari)
            }
            "ios" | "helloios" | "helloiosauto" => Ok(Self::Ios),
            other if other.starts_with("helloios") => Ok(Self::Ios),
            "android" | "okhttp" | "android11okhttp" | "helloandroid11okhttp" => Ok(Self::Android),
            other if other.starts_with("helloandroid") || other.starts_with("android") => {
                Ok(Self::Android)
            }
            "edge" | "helloedge" | "helloedgeauto" => Ok(Self::Edge),
            other if other.starts_with("helloedge") || other.starts_with("edge") => Ok(Self::Edge),
            "360" | "qihoo360" | "hello360" | "hello360auto" => Ok(Self::Qihoo360),
            other if other.starts_with("hello360") || other.starts_with("qihoo360") => {
                Ok(Self::Qihoo360)
            }
            "qq" | "helloqq" | "helloqqauto" => Ok(Self::Qq),
            other if other.starts_with("helloqq") => Ok(Self::Qq),
            "random" => Ok(Self::Random),
            "randomized" | "hellorandomized" => Ok(Self::Randomized),
            "randomizedalpn" | "hellorandomizedalpn" => Ok(Self::RandomizedAlpn),
            "randomizednoalpn" | "hellorandomizednoalpn" => Ok(Self::RandomizedNoAlpn),
            other => bail!("unsupported uTLS client fingerprint: {other}"),
        }
    }
}

impl fmt::Display for UtlsFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_mihomo_name())
    }
}

impl<'de> Deserialize<'de> for UtlsFingerprint {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

pub fn deserialize_optional_fingerprint<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<UtlsFingerprint>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value {
        Some(value) => UtlsFingerprint::from_mihomo_name(&value).map_err(de::Error::custom),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests;
