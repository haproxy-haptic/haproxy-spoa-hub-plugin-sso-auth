/// Tests for the plugin config JSON schema contract.

#[test]
fn config_schema_is_valid_json() {
    let schema_str =
        include_str!("../specs/001-sso-auth-plugin/contracts/plugin-config-schema.json");
    let parsed: serde_json::Value = serde_json::from_str(schema_str).unwrap();
    assert_eq!(parsed["type"].as_str().unwrap(), "object");
    assert!(parsed["required"].as_array().unwrap().len() >= 2);
}

#[test]
fn config_schema_lists_all_properties() {
    let schema_str =
        include_str!("../specs/001-sso-auth-plugin/contracts/plugin-config-schema.json");
    let parsed: serde_json::Value = serde_json::from_str(schema_str).unwrap();
    let props = parsed["properties"].as_object().unwrap();

    for field in [
        "cookie_secret_1",
        "cookie_secret_2",
        "current_cookie_secret",
        "cookie_domain",
        "cookie_secure",
        "cookie_httponly",
        "cookie_samesite",
        "cookie_lifetime_secs",
        "default_timeout_ms",
        "fail_open",
        "max_providers",
        "clock_skew_secs",
        "discovery_ttl_secs",
    ] {
        assert!(
            props.contains_key(field),
            "schema missing property: {field}"
        );
    }
}

#[test]
fn config_schema_required_fields() {
    let schema_str =
        include_str!("../specs/001-sso-auth-plugin/contracts/plugin-config-schema.json");
    let parsed: serde_json::Value = serde_json::from_str(schema_str).unwrap();
    let required: Vec<&str> = parsed["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(required.contains(&"cookie_secret_1"));
    assert!(required.contains(&"cookie_domain"));
}

#[test]
fn config_schema_defaults() {
    let schema_str =
        include_str!("../specs/001-sso-auth-plugin/contracts/plugin-config-schema.json");
    let parsed: serde_json::Value = serde_json::from_str(schema_str).unwrap();
    let props = &parsed["properties"];
    assert_eq!(props["cookie_secure"]["default"], true);
    assert_eq!(props["cookie_httponly"]["default"], true);
    assert_eq!(props["cookie_samesite"]["default"], "Lax");
    assert_eq!(props["cookie_lifetime_secs"]["default"], 36000);
    assert_eq!(props["default_timeout_ms"]["default"], 5000);
    assert_eq!(props["fail_open"]["default"], false);
    assert_eq!(props["max_providers"]["default"], 256);
    assert_eq!(props["clock_skew_secs"]["default"], 60);
    assert_eq!(props["discovery_ttl_secs"]["default"], 3600);
}

#[test]
fn config_schema_no_additional_properties() {
    let schema_str =
        include_str!("../specs/001-sso-auth-plugin/contracts/plugin-config-schema.json");
    let parsed: serde_json::Value = serde_json::from_str(schema_str).unwrap();
    assert_eq!(parsed["additionalProperties"], false);
}

#[test]
fn config_schema_cookie_secret_min_length() {
    let schema_str =
        include_str!("../specs/001-sso-auth-plugin/contracts/plugin-config-schema.json");
    let parsed: serde_json::Value = serde_json::from_str(schema_str).unwrap();
    assert_eq!(parsed["properties"]["cookie_secret_1"]["minLength"], 16);
}
