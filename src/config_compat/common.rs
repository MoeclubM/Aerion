//! Helpers shared by the JSON-based compatibility parsers (sing-box and Xray).
//!
//! Both formats deserialize into `serde_json` values, so these utilities can be
//! reused verbatim instead of being duplicated in each module.

use crate::config_compat::mihomo::OneOrManyStrings;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::net::{IpAddr, Ipv4Addr};

/// Normalizes an optional ALPN list into trimmed, non-empty protocol strings.
pub(crate) fn alpn_values(alpn: Option<&OneOrManyStrings>) -> Vec<String> {
    alpn.map(OneOrManyStrings::to_vec)
        .unwrap_or_default()
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

/// Returns whether a JSON value carries any meaningful (non-empty) data.
pub(crate) fn value_has_data(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_u64().unwrap_or(1) != 0,
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

/// Rejects a configuration object that still carries unrecognized fields.
pub(crate) fn ensure_no_extra_fields(owner: &str, extra: &Map<String, Value>) -> Result<()> {
    ensure!(
        extra.is_empty(),
        "{owner} has unsupported fields {:?}",
        extra.keys().collect::<Vec<_>>()
    );
    Ok(())
}

/// Parses a listen address, accepting the usual wildcard/loopback shorthands.
pub(crate) fn parse_listen_ip(format: &str, value: &str) -> Result<IpAddr> {
    let value = value.trim();
    match value {
        "" | "0.0.0.0" => Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        "localhost" => Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        value => value
            .parse()
            .with_context(|| format!("parse {format} listen address {value}")),
    }
}

/// serde helper: parses an optional `u16` that may arrive as a number or string.
pub(crate) fn deserialize_optional_u16<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Number(number) => Ok(number.as_u64().and_then(|value| u16::try_from(value).ok())),
        Value::String(text) => Ok(text.trim().parse::<u16>().ok()),
        _ => Ok(None),
    }
}
