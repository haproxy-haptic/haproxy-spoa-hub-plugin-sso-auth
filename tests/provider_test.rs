/// Tests for the SPOE interface contract documentation.

#[test]
fn spoe_contract_has_required_args() {
    let contract = include_str!("../specs/001-sso-auth-plugin/contracts/spoe-interface.md");
    for arg in ["provider", "provider_config"] {
        assert!(
            contract.contains(&format!("`{arg}`")),
            "SPOE contract missing required arg: {arg}"
        );
    }
}

#[test]
fn spoe_contract_has_provider_config_json_fields() {
    let contract = include_str!("../specs/001-sso-auth-plugin/contracts/spoe-interface.md");
    for field in [
        "protocol",
        "client_id",
        "redirect_uri",
        "discovery_url",
        "client_secret",
        "auth_url",
        "token_url",
        "jwks_url",
        "logout_url",
        "scopes",
        "extract_claims",
        "idp_cert",
        "signing_key",
        "signing_algo",
    ] {
        assert!(
            contract.contains(&format!("`{field}`")),
            "SPOE contract missing provider config field: {field}"
        );
    }
}

#[test]
fn spoe_contract_has_common_args() {
    let contract = include_str!("../specs/001-sso-auth-plugin/contracts/spoe-interface.md");
    for arg in [
        "cookie",
        "auth_state_cookie",
        "request_path",
        "callback_code",
        "callback_state",
        "callback_saml_response",
        "is_logout",
    ] {
        assert!(
            contract.contains(&format!("`{arg}`")),
            "SPOE contract missing common arg: {arg}"
        );
    }
}

#[test]
fn spoe_contract_has_output_variables() {
    let contract = include_str!("../specs/001-sso-auth-plugin/contracts/spoe-interface.md");
    for var in [
        "allowed",
        "action",
        "redirect_url",
        "set_cookie",
        "set_cookie_header",
        "set_auth_state_cookie",
        "set_auth_state_header",
        "clear_cookie",
        "clear_cookie_header",
        "error",
        "status_code",
    ] {
        assert!(
            contract.contains(&format!("`{var}`")),
            "SPOE contract missing output variable: {var}"
        );
    }
}
