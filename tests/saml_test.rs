use base64::Engine;
use base64::engine::general_purpose::STANDARD;

fn sample_saml_response() -> String {
    r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2026-04-12T00:00:00Z" Destination="https://example.com/saml/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_assert1" Version="2.0" IssueInstant="2026-04-12T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">testuser@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2099-12-31T23:59:59Z" Recipient="https://example.com/saml/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z">
      <saml:AudienceRestriction><saml:Audience>urn:haproxy:sp</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-04-12T00:00:00Z" SessionIndex="_session1">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>testuser@example.com</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="displayname"><saml:AttributeValue>Test User</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="groups"><saml:AttributeValue>admin</saml:AttributeValue><saml:AttributeValue>users</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#
        .to_owned()
}

#[test]
fn saml_response_base64_round_trip() {
    let xml = sample_saml_response();
    let encoded = STANDARD.encode(xml.as_bytes());
    let decoded = STANDARD.decode(&encoded).unwrap();
    assert_eq!(String::from_utf8(decoded).unwrap(), xml);
}

#[test]
fn saml_response_contains_expected_attributes() {
    let xml = sample_saml_response();
    assert!(xml.contains("Name=\"email\""));
    assert!(xml.contains("Name=\"displayname\""));
    assert!(xml.contains("Name=\"groups\""));
}

#[test]
fn saml_response_contains_session_index() {
    let xml = sample_saml_response();
    assert!(xml.contains("SessionIndex=\"_session1\""));
}

#[test]
fn saml_response_contains_name_id() {
    let xml = sample_saml_response();
    assert!(xml.contains("<saml:NameID"));
    assert!(xml.contains("testuser@example.com"));
}

#[test]
fn saml_response_has_multi_valued_groups() {
    let xml = sample_saml_response();
    // Groups attribute has two AttributeValue elements.
    let groups_pos = xml.find("Name=\"groups\"").unwrap();
    let after_groups = &xml[groups_pos..];
    let count = after_groups.matches("<saml:AttributeValue>").count();
    assert_eq!(count, 2, "groups should have 2 attribute values");
}
