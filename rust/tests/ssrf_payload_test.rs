use antissrf::{AntiSSRFError, AntiSSRFPolicy, PolicyConfigOptions};

fn make_external_policy() -> AntiSSRFPolicy {
    AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest)
}

#[test]
fn test_localhost_variants_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec![
        "127.0.0.1",
        "127.0.0.2",
        "127.1.0.1",
        "0.0.0.0",
        "0.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
    ];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_cloud_metadata_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec![
        "169.254.169.254",
        "168.63.129.16",
        "192.0.0.192",
        "100.100.100.200",
    ];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_ipv6_localhost_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec!["::1", "::ffff:127.0.0.1", "::ffff:7f00:1"];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_ipv6_cloud_metadata_blocked() {
    let mut policy = make_external_policy();
    let allowed = policy
        .is_network_connection_allowed(&["::ffff:169.254.169.254"])
        .unwrap();
    assert!(!allowed, "Expected IPv6-mapped IMDS to be blocked");
}

#[test]
fn test_private_network_ranges_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec![
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
        "100.64.0.1", // CGNAT
        "100.127.255.255",
        "198.18.0.1", // Benchmarking
        "198.19.255.255",
    ];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_link_local_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec!["169.254.0.1", "169.254.255.255", "fe80::1"];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_multicast_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec!["224.0.0.1", "239.255.255.255", "ff02::1"];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_allowlist_overrides_denylist() {
    let mut policy = make_external_policy();
    policy.add_allowed_addresses(&["127.0.0.1/32"]).unwrap();

    let allowed = policy
        .is_network_connection_allowed(&["127.0.0.1"])
        .unwrap();
    assert!(allowed, "Expected allowlisted IP to pass");
}

#[test]
fn test_deny_all_unspecified_blocks_non_allowlisted() {
    let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    policy.set_deny_all_unspecified_ips(true).unwrap();
    policy.add_allowed_addresses(&["8.8.8.8/32"]).unwrap();

    let blocked = policy.is_network_connection_allowed(&["1.1.1.1"]).unwrap();
    let allowed = policy.is_network_connection_allowed(&["8.8.8.8"]).unwrap();

    assert!(!blocked, "Expected non-allowlisted IP to be blocked");
    assert!(allowed, "Expected allowlisted IP to pass");
}

#[test]
fn test_protocol_smuggling_blocked() {
    let mut policy = make_external_policy();
    let blocked_protocols = vec![
        "file:", "gopher:", "dict:", "ftp:", "sftp:", "jar:", "ldap:", "tftp:",
    ];
    for protocol in &blocked_protocols {
        let mut headers = Vec::new();
        let result = policy.validate_request(protocol, &mut headers);
        assert!(
            result.is_err(),
            "Expected protocol {} to be blocked, got {:?}",
            protocol,
            result
        );
    }
}

#[test]
fn test_http_allowed_when_plaintext_enabled() {
    let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    policy.set_allow_plaintext_http(true).unwrap();
    let mut headers = Vec::new();
    let result = policy.validate_request("http:", &mut headers);
    assert!(
        result.is_ok(),
        "Expected HTTP to be allowed when plaintext enabled, got {:?}",
        result
    );
}

#[test]
fn test_http_blocked_when_plaintext_disabled() {
    let mut policy = make_external_policy();
    let mut headers = Vec::new();
    let result = policy.validate_request("http:", &mut headers);
    assert!(
        result.is_err(),
        "Expected HTTP to be blocked when plaintext disabled, got {:?}",
        result
    );
}

#[test]
fn test_https_always_allowed() {
    let mut policy = make_external_policy();
    let mut headers = Vec::new();
    let result = policy.validate_request("https:", &mut headers);
    assert!(
        result.is_ok(),
        "Expected HTTPS to be allowed, got {:?}",
        result
    );
}

#[test]
fn test_required_headers_enforced() {
    let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    policy.add_required_headers(&["X-Custom-Auth"]).unwrap();

    // Missing required header
    let mut headers = Vec::new();
    let result = policy.validate_request("https:", &mut headers);
    assert!(
        matches!(result, Err(AntiSSRFError::HeaderRequired)),
        "Expected missing required header to fail, got {:?}",
        result
    );

    // Required header present
    let mut headers = vec![("X-Custom-Auth".to_string(), "token".to_string())];
    let result = policy.validate_request("https:", &mut headers);
    assert!(
        result.is_ok(),
        "Expected required header to pass, got {:?}",
        result
    );
}

#[test]
fn test_denied_headers_enforced() {
    let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    policy.add_denied_headers(&["X-Internal-Token"]).unwrap();

    // Denied header present
    let mut headers = vec![("X-Internal-Token".to_string(), "secret".to_string())];
    let result = policy.validate_request("https:", &mut headers);
    assert!(
        matches!(result, Err(AntiSSRFError::HeaderDenied)),
        "Expected denied header to fail, got {:?}",
        result
    );

    // Denied header absent
    let mut headers = Vec::new();
    let result = policy.validate_request("https:", &mut headers);
    assert!(
        result.is_ok(),
        "Expected no denied headers to pass, got {:?}",
        result
    );
}

#[test]
fn test_header_case_insensitive() {
    let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    policy.add_denied_headers(&["x-internal-token"]).unwrap();

    // Uppercase variant of denied header
    let mut headers = vec![("X-Internal-Token".to_string(), "secret".to_string())];
    let result = policy.validate_request("https:", &mut headers);
    assert!(
        matches!(result, Err(AntiSSRFError::HeaderDenied)),
        "Expected case-insensitive denied header to fail, got {:?}",
        result
    );
}

#[test]
fn test_xff_header_injected() {
    let mut policy = make_external_policy();
    // ExternalOnlyLatest sets add_xff_header = true
    let mut headers = Vec::new();
    let result = policy.validate_request("https:", &mut headers);
    assert!(result.is_ok());

    assert!(
        headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for")),
        "Expected X-Forwarded-For header to be injected"
    );
}

#[test]
fn test_xff_header_not_duplicated() {
    let mut policy = make_external_policy();
    let mut headers = vec![("X-Forwarded-For".to_string(), "1.2.3.4".to_string())];
    let result = policy.validate_request("https:", &mut headers);
    assert!(result.is_ok());

    let xff_count = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
        .count();
    assert_eq!(xff_count, 1, "Expected exactly one X-Forwarded-For header");
}

#[test]
fn test_public_ips_allowed() {
    let mut policy = make_external_policy();
    let allowed_ips = vec!["8.8.8.8", "1.1.1.1", "208.67.222.222"];
    for ip_str in &allowed_ips {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(allowed, "Expected {} to be allowed", ip_str);
    }
}

#[test]
fn test_dns_rebinding_simulation() {
    let mut policy = make_external_policy();
    let allowed = policy.is_network_connection_allowed(&["8.8.8.8"]).unwrap();
    let blocked = policy
        .is_network_connection_allowed(&["127.0.0.1"])
        .unwrap();

    assert!(allowed, "Expected public IP to be allowed");
    assert!(!blocked, "Expected localhost to be blocked");
}

#[test]
fn test_cidr_contains_sub_ip() {
    let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    policy.add_denied_addresses(&["10.0.0.0/8"]).unwrap();

    let blocked = policy.is_network_connection_allowed(&["10.0.0.1"]).unwrap();
    assert!(!blocked, "Expected IP in denied CIDR to be blocked");

    let allowed = policy.is_network_connection_allowed(&["11.0.0.1"]).unwrap();
    assert!(allowed, "Expected IP outside denied CIDR to be allowed");
}

#[test]
fn test_invalid_ip_rejected() {
    let mut policy = make_external_policy();
    let result = policy.is_network_connection_allowed(&["not-an-ip"]);
    assert!(
        matches!(result, Err(AntiSSRFError::InvalidIP(_))),
        "Expected invalid IP to be rejected, got {:?}",
        result
    );
}

#[test]
fn test_policy_locks_after_use() {
    let mut policy = make_external_policy();
    policy.is_network_connection_allowed(&["8.8.8.8"]).unwrap();

    assert!(policy.is_locked());

    let result = policy.add_allowed_addresses(&["1.2.3.4/32"]);
    assert!(
        matches!(result, Err(AntiSSRFError::PolicyLocked)),
        "Expected locked policy to reject modifications, got {:?}",
        result
    );
}

#[test]
fn test_batch_ip_check_fails_if_any_blocked() {
    let mut policy = make_external_policy();
    let allowed = policy
        .is_network_connection_allowed(&["8.8.8.8", "127.0.0.1"])
        .unwrap();
    assert!(!allowed, "Expected batch with blocked IP to fail");
}

#[test]
fn test_batch_ip_check_succeeds_if_all_allowed() {
    let mut policy = make_external_policy();
    let allowed = policy
        .is_network_connection_allowed(&["8.8.8.8", "1.1.1.1"])
        .unwrap();
    assert!(allowed, "Expected batch with all allowed IPs to pass");
}

#[test]
fn test_conflicting_configuration_rejected() {
    let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::InternalOnly);
    let result = policy.add_denied_addresses(&["10.0.0.0/8"]);
    assert!(
        matches!(result, Err(AntiSSRFError::ConflictingConfiguration)),
        "Expected conflicting configuration to be rejected, got {:?}",
        result
    );
}

#[test]
fn test_wireserver_blocked() {
    let mut policy = make_external_policy();
    let allowed = policy
        .is_network_connection_allowed(&["168.63.129.16"])
        .unwrap();
    assert!(!allowed, "Expected Azure WireServer to be blocked");
}

#[test]
fn test_imds_blocked() {
    let mut policy = make_external_policy();
    let allowed = policy
        .is_network_connection_allowed(&["169.254.169.254"])
        .unwrap();
    assert!(!allowed, "Expected AWS IMDS to be blocked");
}

#[test]
fn test_loopback_variants_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec!["127.0.0.1", "127.255.255.255", "127.0.0.0"];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_unique_local_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec!["fc00::1", "fd00::1"];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_site_local_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec!["fec0::1"];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_documentation_network_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec!["192.0.2.1", "198.51.100.1", "203.0.113.1"];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_shared_address_space_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec!["100.64.0.1", "100.100.100.100", "100.127.255.255"];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_reserved_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec!["240.0.0.1", "255.255.255.255"];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_benchmarking_blocked() {
    let mut policy = make_external_policy();
    let blocked = vec!["198.18.0.1", "198.19.255.255"];
    for ip_str in &blocked {
        let allowed = policy.is_network_connection_allowed(&[ip_str]).unwrap();
        assert!(!allowed, "Expected {} to be blocked", ip_str);
    }
}

#[test]
fn test_decimal_hex_octal_ip_rejected() {
    let mut policy = make_external_policy();
    // Raw encoded IP bypass formats - rejected by IpAddr::from_str
    // url crate normalizes these before resolver sees host
    let invalid_ips = vec![
        "2130706433",          // decimal 127.0.0.1
        "0x7f000001",          // hex 127.0.0.1
        "0177.0.0.1",          // octal 127.0.0.1
        "0xA9.0xFE.0xA9.0xFE", // hex 169.254.169.254
        "0xA9FEA9FE",          // hex 169.254.169.254
        "0251.0376.0251.0376", // octal 169.254.169.254
        "0",                   // decimal 0.0.0.0
    ];
    for ip_str in &invalid_ips {
        let result = policy.is_network_connection_allowed(&[ip_str]);
        assert!(
            matches!(result, Err(AntiSSRFError::InvalidIP(_))),
            "Expected {} to be rejected as invalid IP, got {:?}",
            ip_str,
            result
        );
    }
}

#[test]
fn test_shortened_ip_blocked_or_rejected() {
    let mut policy = make_external_policy();
    // 127.1 is shorthand for 127.0.0.1 in some parsers (inet_aton)
    // Rust's IpAddr::from_str may accept or reject it
    let result = policy.is_network_connection_allowed(&["127.1"]);
    match result {
        Ok(allowed) => assert!(!allowed, "Expected 127.1 to be blocked as localhost"),
        Err(_) => (), // InvalidIP is acceptable - still prevents bypass
    }
}

#[test]
fn test_url_parsing_at_redirects() {
    // Verify url crate correctly handles @ redirect patterns
    // These are Orange Tsai's URL parsing discrepancy bypasses

    // evil.com@127.0.0.1 - host is correctly identified as 127.0.0.1
    let url = url::Url::parse("http://evil.com@127.0.0.1/").unwrap();
    assert_eq!(url.host_str(), Some("127.0.0.1"));

    // 127.0.0.1@evil.com - host is correctly identified as evil.com
    let url = url::Url::parse("http://127.0.0.1@evil.com/").unwrap();
    assert_eq!(url.host_str(), Some("evil.com"));

    // Port + @ confusion: 127.1.1.1:80@127.2.2.2:80
    let url = url::Url::parse("http://127.1.1.1:80@127.2.2.2:80/").unwrap();
    assert_eq!(url.host_str(), Some("127.2.2.2"));
}
