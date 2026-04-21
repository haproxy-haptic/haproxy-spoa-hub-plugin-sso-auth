use haproxy_spoa_hub_plugin_api::SpoeMessage;
use std::fmt;
use std::str::FromStr;

/// Protocol type for the identity provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Oidc,
    Saml,
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "oidc" => Ok(Self::Oidc),
            "saml" => Ok(Self::Saml),
            other => Err(format!(
                "unknown protocol: {other} (expected 'oidc' or 'saml')"
            )),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oidc => write!(f, "oidc"),
            Self::Saml => write!(f, "saml"),
        }
    }
}

/// Configuration for a single identity provider, parsed from a JSON
/// string passed as the `provider_config` SPOE message argument.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub protocol: Protocol,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub discovery_url: Option<String>,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub jwks_url: Option<String>,
    pub logout_url: Option<String>,
    pub redirect_uri: String,
    pub post_logout_redirect_uri: Option<String>,
    pub scopes: Vec<String>,
    pub extract_claims: Vec<String>,
    pub idp_cert: Option<String>,
    pub timeout_ms: Option<u64>,
}

impl ProviderConfig {
    /// Parse provider configuration from SPOE message arguments.
    ///
    /// Requires `provider` (name) and `provider_config` (JSON string
    /// with all provider settings from a single `HAProxy` map file).
    pub fn parse_from_args(message: &SpoeMessage) -> Result<Self, String> {
        let name = message
            .get_string("provider")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "missing required SPOE arg: provider".to_owned())?;
        let json_str = message
            .get_string("provider_config")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "missing required SPOE arg: provider_config".to_owned())?;
        Self::parse_from_json(name, json_str)
    }

    fn parse_from_json(name: &str, json_str: &str) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("invalid provider_config JSON: {e}"))?;

        let str_field = |field: &str| -> Option<String> {
            v.get(field).and_then(|v| v.as_str()).map(String::from)
        };

        let require = |field: &str| -> Result<String, String> {
            str_field(field).ok_or_else(|| format!("provider_config missing '{field}'"))
        };

        let protocol: Protocol = require("protocol")?.parse()?;
        let client_id = require("client_id")?;
        let redirect_uri = require("redirect_uri")?;

        let scopes = match str_field("scopes") {
            Some(s) => s.split(',').map(|p| p.trim().to_owned()).collect(),
            None => vec!["openid".to_owned()],
        };

        let extract_claims = str_field("extract_claims")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let timeout_ms = str_field("timeout_ms").and_then(|s| s.parse::<u64>().ok());

        Ok(Self {
            name: name.to_owned(),
            protocol,
            client_id,
            client_secret: str_field("client_secret"),
            discovery_url: str_field("discovery_url"),
            auth_url: str_field("auth_url"),
            token_url: str_field("token_url"),
            jwks_url: str_field("jwks_url"),
            logout_url: str_field("logout_url"),
            redirect_uri,
            post_logout_redirect_uri: str_field("post_logout_redirect_uri"),
            scopes,
            extract_claims,
            idp_cert: str_field("idp_cert"),
            timeout_ms,
        })
    }
}
