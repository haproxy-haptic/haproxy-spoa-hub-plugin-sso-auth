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

/// Which OIDC token the session keeps and returns as the `token` variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassToken {
    IdToken,
    AccessToken,
}

impl FromStr for PassToken {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "id_token" => Ok(Self::IdToken),
            "access_token" => Ok(Self::AccessToken),
            other => Err(format!(
                "unknown pass_token: {other} (expected 'id_token' or 'access_token')"
            )),
        }
    }
}

/// Configuration for a single identity provider, parsed from the
/// `[providers.<name>]` table in the plugin params or from a JSON string
/// passed as the `provider_config` SPOE message argument.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub protocol: Protocol,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Only honoured for providers defined in the plugin params; resolved
    /// into `client_secret` at plugin init.
    pub client_secret_file: Option<String>,
    /// Encrypts this provider's cookies instead of the global
    /// `cookie_secret_1`/`cookie_secret_2`.
    pub cookie_secret: Option<String>,
    /// Resolved into `cookie_secret` at plugin init, like `client_secret_file`.
    pub cookie_secret_file: Option<String>,
    pub discovery_url: Option<String>,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub jwks_url: Option<String>,
    pub logout_url: Option<String>,
    pub redirect_uri: String,
    pub post_logout_redirect_uri: Option<String>,
    pub scopes: Vec<String>,
    pub extract_claims: Vec<String>,
    pub groups_claim: String,
    pub pass_token: Option<PassToken>,
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
            .ok_or_else(|| {
                format!("unknown provider '{name}': not in params and no provider_config arg")
            })?;
        let v: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("invalid provider_config JSON: {e}"))?;
        let config = Self::from_value(name, &v)?;
        if config.client_secret_file.is_some() || config.cookie_secret_file.is_some() {
            return Err(format!(
                "provider '{name}': *_file secrets are only supported for providers defined in the plugin params"
            ));
        }
        Ok(config)
    }

    pub fn from_value(name: &str, v: &serde_json::Value) -> Result<Self, String> {
        let str_field = |field: &str| -> Option<String> {
            v.get(field).and_then(|v| v.as_str()).map(String::from)
        };

        let require = |field: &str| -> Result<String, String> {
            str_field(field).ok_or_else(|| format!("provider '{name}' missing '{field}'"))
        };

        // Comma-separated string (map/JSON form) or array of strings (TOML form).
        let list_field = |field: &str| -> Option<Vec<String>> {
            let items: Vec<String> = match v.get(field)? {
                serde_json::Value::String(s) => s.split(',').map(str::to_owned).collect(),
                serde_json::Value::Array(a) => a
                    .iter()
                    .filter_map(|i| i.as_str().map(str::to_owned))
                    .collect(),
                _ => return None,
            };
            Some(
                items
                    .into_iter()
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect(),
            )
        };

        let protocol: Protocol = require("protocol")?.parse()?;
        let client_id = require("client_id")?;
        if protocol == Protocol::Oidc
            && str_field("discovery_url").is_none()
            && ["auth_url", "token_url", "jwks_url"]
                .iter()
                .any(|f| str_field(f).is_none())
        {
            return Err(format!(
                "provider '{name}' needs discovery_url, or auth_url, token_url and jwks_url"
            ));
        }
        let redirect_uri = require("redirect_uri")?;

        let scopes = list_field("scopes").unwrap_or_else(|| vec!["openid".to_owned()]);
        let groups_claim = str_field("groups_claim").unwrap_or_else(|| "groups".to_owned());
        let mut extract_claims = list_field("extract_claims").unwrap_or_default();
        if !extract_claims.contains(&groups_claim) {
            extract_claims.push(groups_claim.clone());
        }

        let pass_token = str_field("pass_token")
            .map(|s| s.parse::<PassToken>())
            .transpose()
            .map_err(|e| format!("provider '{name}': {e}"))?;
        if pass_token.is_some() && protocol != Protocol::Oidc {
            return Err(format!(
                "provider '{name}': pass_token requires protocol oidc"
            ));
        }

        let secret_field = |field: &str| -> Result<(Option<String>, Option<String>), String> {
            let inline = str_field(field);
            let file = str_field(&format!("{field}_file"));
            if inline.is_some() && file.is_some() {
                return Err(format!(
                    "provider '{name}': set {field} or {field}_file, not both"
                ));
            }
            Ok((inline, file))
        };
        let (client_secret, client_secret_file) = secret_field("client_secret")?;
        let (cookie_secret, cookie_secret_file) = secret_field("cookie_secret")?;
        if cookie_secret.as_ref().is_some_and(|s| s.len() < 16) {
            return Err(format!(
                "provider '{name}': cookie_secret must be at least 16 characters"
            ));
        }

        // Integer in TOML, string in the JSON map form.
        let timeout_ms = v.get("timeout_ms").and_then(|t| {
            t.as_u64()
                .or_else(|| t.as_str().and_then(|s| s.parse::<u64>().ok()))
        });

        Ok(Self {
            name: name.to_owned(),
            protocol,
            client_id,
            client_secret,
            client_secret_file,
            cookie_secret,
            cookie_secret_file,
            discovery_url: str_field("discovery_url"),
            auth_url: str_field("auth_url"),
            token_url: str_field("token_url"),
            jwks_url: str_field("jwks_url"),
            logout_url: str_field("logout_url"),
            redirect_uri,
            post_logout_redirect_uri: str_field("post_logout_redirect_uri"),
            scopes,
            extract_claims,
            groups_claim,
            pass_token,
            idp_cert: str_field("idp_cert"),
            timeout_ms,
        })
    }

    /// Read the `*_file` secrets into `client_secret` and `cookie_secret`.
    pub fn load_secret_files(&mut self) -> Result<(), String> {
        let name = &self.name;
        if let Some(ref path) = self.client_secret_file {
            self.client_secret = Some(
                crate::config::read_secret_file(path)
                    .map_err(|e| format!("provider '{name}': {e}"))?,
            );
        }
        if let Some(ref path) = self.cookie_secret_file {
            let secret = crate::config::read_secret_file(path)
                .map_err(|e| format!("provider '{name}': {e}"))?;
            if secret.len() < 16 {
                return Err(format!(
                    "provider '{name}': cookie_secret must be at least 16 characters"
                ));
            }
            self.cookie_secret = Some(secret);
        }
        Ok(())
    }

    /// False while a `*_file` secret hasn't been read successfully.
    pub fn secrets_loaded(&self) -> bool {
        (self.client_secret_file.is_none() || self.client_secret.is_some())
            && (self.cookie_secret_file.is_none() || self.cookie_secret.is_some())
    }

    /// The `redirect_uri` for a request to `host`. A path-only `redirect_uri`
    /// is completed with the request's host, so one provider serves every
    /// host of a route; browsers only send the session back to that host.
    pub fn redirect_uri_for(&self, host: Option<&str>) -> Result<String, String> {
        if !self.redirect_uri.starts_with('/') {
            return Ok(self.redirect_uri.clone());
        }
        match host {
            Some(h) if !h.is_empty() && !h.contains(['/', '\\', '@', '?', '#']) => {
                Ok(format!("https://{h}{}", self.redirect_uri))
            }
            _ => Err(format!(
                "provider '{}': a path-only redirect_uri needs the request_host arg",
                self.name
            )),
        }
    }

    /// Path component of `redirect_uri`; requests to it carry the callback.
    pub fn redirect_path(&self) -> &str {
        let after_scheme = self
            .redirect_uri
            .split_once("://")
            .map_or(self.redirect_uri.as_str(), |(_, rest)| rest);
        let path = after_scheme.find('/').map_or("/", |i| &after_scheme[i..]);
        path.split(['?', '#']).next().unwrap_or("/")
    }
}

/// The OIDC provider `mykeycloak`, using the global cookie secrets.
#[cfg(test)]
pub fn test_provider() -> ProviderConfig {
    ProviderConfig::from_value(
        "mykeycloak",
        &serde_json::json!({
            "protocol": "oidc",
            "client_id": "app",
            "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
            "redirect_uri": "https://app.example.com/oauth2/callback",
        }),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> serde_json::Value {
        serde_json::json!({
            "protocol": "oidc",
            "client_id": "app",
            "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
            "redirect_uri": "https://app.example.com/oauth2/callback?x=1",
        })
    }

    #[test]
    fn toml_arrays_and_defaults() {
        let mut v = base();
        v["scopes"] = serde_json::json!(["openid", "email"]);
        v["extract_claims"] = serde_json::json!(["email"]);
        let p = ProviderConfig::from_value("kc", &v).unwrap();
        assert_eq!(p.scopes, vec!["openid", "email"]);
        assert_eq!(p.extract_claims, vec!["email", "groups"]);
        assert_eq!(p.pass_token, None);
        assert_eq!(p.redirect_path(), "/oauth2/callback");
    }

    #[test]
    fn json_string_lists_and_custom_groups_claim() {
        let mut v = base();
        v["extract_claims"] = serde_json::json!("email, roles");
        v["groups_claim"] = serde_json::json!("roles");
        v["pass_token"] = serde_json::json!("access_token");
        v["timeout_ms"] = serde_json::json!("2500");
        let p = ProviderConfig::from_value("kc", &v).unwrap();
        assert_eq!(p.extract_claims, vec!["email", "roles"]);
        assert_eq!(p.pass_token, Some(PassToken::AccessToken));
        assert_eq!(p.timeout_ms, Some(2500));
    }

    #[test]
    fn oidc_needs_discovery_or_all_manual_endpoints() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("discovery_url");
        v["auth_url"] = serde_json::json!("https://idp/auth");
        assert!(ProviderConfig::from_value("kc", &v).is_err());
        v["token_url"] = serde_json::json!("https://idp/token");
        v["jwks_url"] = serde_json::json!("https://idp/jwks");
        assert!(ProviderConfig::from_value("kc", &v).is_ok());
    }

    #[test]
    fn rejects_bad_pass_token_and_double_secret() {
        let mut v = base();
        v["pass_token"] = serde_json::json!("refresh_token");
        assert!(ProviderConfig::from_value("kc", &v).is_err());

        let mut v = base();
        v["client_secret"] = serde_json::json!("a");
        v["client_secret_file"] = serde_json::json!("/s");
        assert!(ProviderConfig::from_value("kc", &v).is_err());
    }

    #[test]
    fn redirect_path_without_path() {
        let mut v = base();
        v["redirect_uri"] = serde_json::json!("https://app.example.com");
        assert_eq!(
            ProviderConfig::from_value("kc", &v)
                .unwrap()
                .redirect_path(),
            "/"
        );
    }

    #[test]
    fn path_only_redirect_uri_uses_request_host() {
        let mut v = base();
        v["redirect_uri"] = serde_json::json!("/oauth2/callback");
        let p = ProviderConfig::from_value("kc", &v).unwrap();
        assert_eq!(p.redirect_path(), "/oauth2/callback");
        assert_eq!(
            p.redirect_uri_for(Some("app.example.com:8443")).unwrap(),
            "https://app.example.com:8443/oauth2/callback"
        );
        assert!(p.redirect_uri_for(None).is_err());
        assert!(p.redirect_uri_for(Some("evil.com/x")).is_err());
        assert!(p.redirect_uri_for(Some("a@evil.com")).is_err());
    }

    #[test]
    fn secret_files_load_late() {
        let dir = std::env::temp_dir().join(format!("sso-auth-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let client = dir.join("client");
        let cookie = dir.join("cookie");
        let mut v = base();
        v["client_secret_file"] = serde_json::json!(client.to_str().unwrap());
        v["cookie_secret_file"] = serde_json::json!(cookie.to_str().unwrap());
        let mut p = ProviderConfig::from_value("kc", &v).unwrap();

        assert!(p.load_secret_files().is_err());
        assert!(!p.secrets_loaded());

        std::fs::write(&client, "s3cret\n").unwrap();
        std::fs::write(&cookie, "short").unwrap();
        assert!(p.load_secret_files().is_err());

        std::fs::write(&cookie, "cookie-secret-16-chars").unwrap();
        p.load_secret_files().unwrap();
        assert!(p.secrets_loaded());
        assert_eq!(p.client_secret.as_deref(), Some("s3cret"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
