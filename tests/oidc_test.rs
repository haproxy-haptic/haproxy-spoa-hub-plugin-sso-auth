use tiny_http::{Response, Server};

fn start_mock_oidc_server() -> (Server, u16) {
    let server = Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    (server, port)
}

fn discovery_json(port: u16) -> String {
    format!(
        r#"{{
  "issuer": "http://127.0.0.1:{port}",
  "authorization_endpoint": "http://127.0.0.1:{port}/authorize",
  "token_endpoint": "http://127.0.0.1:{port}/token",
  "jwks_uri": "http://127.0.0.1:{port}/jwks",
  "end_session_endpoint": "http://127.0.0.1:{port}/logout",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}}"#
    )
}

fn token_response_json() -> &'static str {
    // Minimal JWT: header={"alg":"none","typ":"JWT"},
    // payload={"sub":"testuser","email":"test@example.com","name":"Test User",
    //          "nonce":"testnonce","iss":"http://localhost","aud":"test-client","exp":9999999999}
    r#"{
  "access_token": "access-tok-123",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh-tok-456",
  "id_token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0dXNlciIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsIm5hbWUiOiJUZXN0IFVzZXIiLCJub25jZSI6InRlc3Rub25jZSIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJhdWQiOiJ0ZXN0LWNsaWVudCIsImV4cCI6OTk5OTk5OTk5OX0."
}"#
}

#[test]
fn mock_oidc_discovery_returns_endpoints() {
    let (server, port) = start_mock_oidc_server();

    let handle = std::thread::spawn(move || {
        let request = server.recv().unwrap();
        assert!(
            request.url().contains(".well-known"),
            "expected discovery request, got: {}",
            request.url()
        );
        let response = Response::from_string(discovery_json(port)).with_header(
            tiny_http::Header::from_bytes(b"Content-Type", b"application/json").unwrap(),
        );
        request.respond(response).unwrap();
    });

    let agent = ureq::Agent::new_with_defaults();
    let resp = agent
        .get(&format!(
            "http://127.0.0.1:{port}/.well-known/openid-configuration"
        ))
        .call()
        .unwrap();

    let body = resp.into_body().read_to_string().unwrap();
    assert!(body.contains("authorization_endpoint"));
    assert!(body.contains("token_endpoint"));
    assert!(body.contains("jwks_uri"));

    handle.join().unwrap();
}

#[test]
fn mock_oidc_token_endpoint_returns_tokens() {
    let (server, port) = start_mock_oidc_server();

    let handle = std::thread::spawn(move || {
        let request = server.recv().unwrap();
        assert!(request.url().contains("/token"));
        let response = Response::from_string(token_response_json()).with_header(
            tiny_http::Header::from_bytes(b"Content-Type", b"application/json").unwrap(),
        );
        request.respond(response).unwrap();
    });

    let agent = ureq::Agent::new_with_defaults();
    let resp = agent
        .post(&format!("http://127.0.0.1:{port}/token"))
        .send_form([
            ("grant_type", "authorization_code"),
            ("code", "test-code"),
            ("redirect_uri", "http://localhost/callback"),
            ("client_id", "test-client"),
        ])
        .unwrap();

    let body = resp.into_body().read_to_string().unwrap();
    assert!(body.contains("access_token"));
    assert!(body.contains("refresh_token"));
    assert!(body.contains("id_token"));

    handle.join().unwrap();
}

#[test]
fn id_token_jwt_payload_contains_claims() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let token_json = token_response_json();
    let id_token_start = token_json.find("\"id_token\"").unwrap();
    let after = &token_json[id_token_start..];
    let value_start = after.find(": \"").unwrap() + 3;
    let value_end = after[value_start..].find('"').unwrap();
    let id_token = &after[value_start..value_start + value_end];

    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 parts");

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let payload = String::from_utf8(payload_bytes).unwrap();

    assert!(payload.contains("\"sub\":\"testuser\""));
    assert!(payload.contains("\"email\":\"test@example.com\""));
    assert!(payload.contains("\"name\":\"Test User\""));
}
