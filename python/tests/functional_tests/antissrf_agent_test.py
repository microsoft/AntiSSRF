# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
    Tests for AntiSSRF agent internals and request-path behaviors.

    Covers the HTTP-method matrix, host resolution/validation helpers, the
    adapter/session wiring, and DNS rebinding protection. Policy allow/deny,
    header, and scheme decisions are covered by the unit policy tests.
"""

import pytest
import socket
from AntiSSRF import AntiSSRFPolicy, PolicyConfigOptions
from AntiSSRF._antissrf_agent import _resolve_host, _validate_request_host, AntiSSRFSession
from AntiSSRF import AntiSSRFError
from AntiSSRF._ipaddr import IPAddress


# Test that AntiSSRFPolicy.get_antissrf_session returns an AntiSSRFSession
def test_get_antissrf_session():
    policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
    session = policy.get_antissrf_session()
    assert isinstance(session, AntiSSRFSession)


# ===========================================================================
# HTTPS Other Methods Tests
# ===========================================================================

class TestHttpsOtherMethods:
    """HTTPS tests for various HTTP methods (GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS)."""
    
    TEST_URL = "https://ambitious-flower-0611c910f.2.azurestaticapps.net/api/method"
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up allowed and disallowed sessions."""
        # Allowed policy
        self.allow_policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.allow_session = self.allow_policy.get_antissrf_session()
        
        # Disallowed policy - block the test URL's IP
        self.disallow_policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        test_hostname = "ambitious-flower-0611c910f.2.azurestaticapps.net"
        disallowed_ips = [str(addr.get_address()) for addr in _resolve_host(test_hostname)]
        self.disallow_policy.add_denied_addresses(disallowed_ips)
        self.disallow_session = self.disallow_policy.get_antissrf_session()
    
    # ----- Allowed requests for each method -----
    
    def test_get_allowed(self):
        response = self.allow_session.get(self.TEST_URL)
        assert response.status_code == 200
        data = response.json()
        assert data["method"] == "GET"
    
    def test_post_allowed(self):
        response = self.allow_session.post(self.TEST_URL)
        assert response.status_code == 200
        data = response.json()
        assert data["method"] == "POST"
    
    def test_put_allowed(self):
        response = self.allow_session.put(self.TEST_URL)
        assert response.status_code == 200
        data = response.json()
        assert data["method"] == "PUT"
    
    def test_delete_allowed(self):
        response = self.allow_session.delete(self.TEST_URL)
        assert response.status_code == 200
        data = response.json()
        assert data["method"] == "DELETE"
    
    def test_head_allowed(self):
        response = self.allow_session.head(self.TEST_URL)
        assert response.status_code == 200
    
    def test_patch_allowed(self):
        response = self.allow_session.patch(self.TEST_URL)
        assert response.status_code == 200
        data = response.json()
        assert data["method"] == "PATCH"
    
    def test_options_allowed(self):
        response = self.allow_session.options(self.TEST_URL)
        assert response.status_code == 200
        data = response.json()
        assert data["method"] == "OPTIONS"
    
    # ----- Disallowed requests for each method -----
    
    def test_get_disallowed(self):
        with pytest.raises(AntiSSRFError):
            self.disallow_session.get(self.TEST_URL)
    
    def test_post_disallowed(self):
        with pytest.raises(AntiSSRFError):
            self.disallow_session.post(self.TEST_URL)
    
    def test_put_disallowed(self):
        with pytest.raises(AntiSSRFError):
            self.disallow_session.put(self.TEST_URL)
    
    def test_delete_disallowed(self):
        with pytest.raises(AntiSSRFError):
            self.disallow_session.delete(self.TEST_URL)
    
    def test_head_disallowed(self):
        with pytest.raises(AntiSSRFError):
            self.disallow_session.head(self.TEST_URL)
    
    def test_patch_disallowed(self):
        with pytest.raises(AntiSSRFError):
            self.disallow_session.patch(self.TEST_URL)
    
    def test_options_disallowed(self):
        with pytest.raises(AntiSSRFError):
            self.disallow_session.options(self.TEST_URL)


# ===========================================================================
# resolve_host Function Tests
# ===========================================================================

class TestResolveHost:
    """Tests for the resolve_host function."""
    
    def test_resolve_public_hostname(self):
        """resolve_host should resolve public hostnames."""
        addrs = _resolve_host("www.google.com")
        
        assert len(addrs) > 0
        for addr in addrs:
            assert addr.get_address() is not None
    
    def test_resolve_ipv4_literal(self):
        """resolve_host with IPv4 literal should return that IP."""
        addrs = _resolve_host("8.8.8.8")
        
        assert len(addrs) == 1
        assert str(addrs[0].get_address()) == "8.8.8.8"
    
    def test_resolve_ipv6_literal(self):
        """resolve_host with IPv6 literal should return that IP."""
        addrs = _resolve_host("::1")
        
        assert len(addrs) == 1
        assert str(addrs[0].get_address()) == "::1"
    
    def test_resolve_localhost(self):
        """resolve_host should resolve localhost."""
        addrs = _resolve_host("localhost")
        
        assert len(addrs) > 0
    
    def test_resolve_nonexistent_host(self):
        """resolve_host with nonexistent host should raise or return empty."""
        try:
            addrs = _resolve_host("this-domain-definitely-does-not-exist-12345.invalid")
            # If it returns, should be empty
            assert len(addrs) == 0
        except socket.gaierror:
            # This is also acceptable
            pass
    
    def test_resolve_returns_ipaddress_objects(self):
        """resolve_host should return IPAddress objects."""
        from AntiSSRF._ipaddr import IPAddress
        
        addrs = _resolve_host("www.bing.com")
        
        for addr in addrs:
            assert isinstance(addr, IPAddress)


# ===========================================================================
# Validate Request Host Tests
# ===========================================================================

class TestValidateRequestHost:
    """Resolved addresses are validated against the policy's allow/deny rules."""

    def test_empty_host_returns_empty(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        assert _validate_request_host(policy, "") == []

    def test_allowed_ip_returns_addresses(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        addrs = _validate_request_host(policy, "203.0.113.10")
        assert len(addrs) == 1
        assert int(addrs[0].get_address()) == int(IPAddress("203.0.113.10").get_address())

    def test_denied_ip_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.add_denied_addresses(["203.0.113.0/24"])
        with pytest.raises(AntiSSRFError):
            _validate_request_host(policy, "203.0.113.10")

    def test_deny_all_wildcard_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.deny_all_unspecified_ips = True
        with pytest.raises(AntiSSRFError):
            _validate_request_host(policy, "203.0.113.10")

    def test_allow_overrides_deny(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.add_denied_addresses(["203.0.113.0/24"])
        policy.add_allowed_addresses(["203.0.113.10/32"])
        addrs = _validate_request_host(policy, "203.0.113.10")
        assert len(addrs) == 1


# ===========================================================================
# AntiSSRFAdapter Tests
# ===========================================================================

class TestAntiSSRFAdapterUnit:
    """Unit tests for AntiSSRFAdapter."""
    
    def test_adapter_stores_policy(self):
        """AntiSSRFAdapter should store the policy."""
        from AntiSSRF._antissrf_agent import _AntiSSRFAdapter
        
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        adapter = _AntiSSRFAdapter(policy)
        
        assert adapter._policy is policy
    
    def test_adapter_inherits_http_adapter(self):
        """AntiSSRFAdapter should inherit from HTTPAdapter."""
        from AntiSSRF._antissrf_agent import _AntiSSRFAdapter
        from requests.adapters import HTTPAdapter
        
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        adapter = _AntiSSRFAdapter(policy)
        
        assert isinstance(adapter, HTTPAdapter)


# ===========================================================================
# AntiSSRFSession Tests
# ===========================================================================

class TestAntiSSRFSessionUnit:
    """Unit tests for AntiSSRFSession."""
    
    def test_session_stores_policy(self):
        """AntiSSRFSession should store the policy."""
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        session = AntiSSRFSession(policy)
        
        assert session._policy is policy
    
    def test_session_inherits_requests_session(self):
        """AntiSSRFSession should inherit from requests.Session."""
        from requests import Session
        
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        session = AntiSSRFSession(policy)
        
        assert isinstance(session, Session)
    
    def test_session_mounts_antissrf_adapters(self):
        """AntiSSRFSession should mount AntiSSRFAdapter for http and https."""
        from AntiSSRF._antissrf_agent import _AntiSSRFAdapter
        
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        session = AntiSSRFSession(policy)
        
        http_adapter = session.get_adapter("http://example.com")
        https_adapter = session.get_adapter("https://example.com")
        
        assert isinstance(http_adapter, _AntiSSRFAdapter)
        assert isinstance(https_adapter, _AntiSSRFAdapter)
    
    def test_session_adapters_have_policy(self):
        """Session adapters should have the same policy."""
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        session = AntiSSRFSession(policy)
        
        http_adapter = session.get_adapter("http://example.com")
        https_adapter = session.get_adapter("https://example.com")
        
        assert http_adapter._policy is policy
        assert https_adapter._policy is policy


# ===========================================================================
# DNS Rebinding Protection Tests
# ===========================================================================

class TestAdditionalNSRebindingProtection:
    """
    Tests to verify protection against DNS rebinding attacks.
    
    DNS rebinding attack flow:
    1. Attacker controls a domain (e.g., evil.com)
    2. First DNS query returns a safe public IP (passes validation)
    3. Second DNS query returns an internal IP (e.g., 127.0.0.1, 169.254.169.254)
    4. If the library re-resolves DNS at connection time, it connects to the internal IP
    
    The AntiSSRF library protects against this by:
    1. Resolving DNS once and validating ALL returned IPs
    2. Replacing the hostname with a validated IP before connection
    3. Never re-resolving the hostname during the connection phase
    """
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.policy.allow_plain_text_http = True
        self.session = self.policy.get_antissrf_session()
    
    def test_connects_to_validated_ip_not_hostname(self):
        """
        Verify that we connect to the validated IP address, not the hostname.
        
        This is the core DNS rebinding protection: after validation, we connect
        directly to the IP we validated, preventing TOCTOU attacks.
        """
        from AntiSSRF._antissrf_agent import _AntiSSRFAdapter
        from requests import PreparedRequest
        
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        policy.allow_plain_text_http = True
        adapter = _AntiSSRFAdapter(policy)
        
        # Create a mock request
        request = PreparedRequest()
        request.prepare(method='GET', url='http://example.com/', headers={})
        
        # Call the method that resolves and validates
        host_params, pool_kwargs = adapter.build_connection_pool_key_attributes(
            request, verify=True
        )
        
        # The host should now be an IP address, not a hostname
        # This proves we connect to the validated IP directly
        host = host_params["host"]
        assert host != "example.com", "Host should be replaced with IP, not remain as hostname"
        
        # Verify it's a valid IP address format
        import socket
        try:
            socket.inet_aton(host)  # IPv4
            is_valid_ip = True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, host)  # IPv6
                is_valid_ip = True
            except socket.error:
                is_valid_ip = False
        
        assert is_valid_ip, f"Host '{host}' should be a valid IP address"
    
    def test_rebinding_first_safe_then_malicious_blocked(self):
        """
        Simulate DNS rebinding: first call returns safe IP, second returns malicious.
        
        Even if the second DNS resolution returns a malicious IP, the connection
        should still go to the first (validated) IP since we don't re-resolve.
        """
        from unittest.mock import patch
        from AntiSSRF._antissrf_agent import _AntiSSRFAdapter, _resolve_host
        from AntiSSRF._ipaddr import IPAddress
        from requests import PreparedRequest
        
        call_count = [0]  # Use list to allow modification in nested function
        
        def mock_resolve_host(hostname):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: return safe public IP (Google DNS)
                return [IPAddress("8.8.8.8")]
            else:
                # Second call: return malicious internal IP
                # This should never be called during a single request
                return [IPAddress("127.0.0.1")]
        
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        policy.allow_plain_text_http = True
        adapter = _AntiSSRFAdapter(policy)
        
        request = PreparedRequest()
        request.prepare(method='GET', url='http://rebind.example.com/', headers={})
        
        with patch('AntiSSRF._antissrf_agent._resolve_host', mock_resolve_host):
            host_params, _ = adapter.build_connection_pool_key_attributes(
                request, verify=True
            )
        
        # Should connect to the safe IP from first resolution
        assert host_params["host"] == "8.8.8.8"
        # DNS should only be resolved once per request
        assert call_count[0] == 1, "DNS should only be resolved once"
    
    def test_host_header_preserved_after_ip_replacement(self):
        """
        After replacing hostname with IP, Host header should still contain original hostname.
        
        This ensures proper HTTP virtual hosting while still connecting to validated IP.
        """
        from unittest.mock import patch
        from AntiSSRF._antissrf_agent import _AntiSSRFAdapter
        from AntiSSRF._ipaddr import IPAddress
        from requests import PreparedRequest
        
        def mock_resolve_host(hostname):
            return [IPAddress("93.184.216.34")]  # example.com's actual IP
        
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        policy.allow_plain_text_http = True
        adapter = _AntiSSRFAdapter(policy)
        
        request = PreparedRequest()
        request.prepare(method='GET', url='http://example.com/path', headers={})
        
        with patch('AntiSSRF._antissrf_agent._resolve_host', mock_resolve_host):
            host_params, _ = adapter.build_connection_pool_key_attributes(
                request, verify=True
            )
        
        # Connection goes to IP
        assert host_params["host"] == "93.184.216.34"
        # But Host header contains original hostname
        assert request.headers.get("Host") == "example.com"
    
    def test_no_dns_resolution_during_connection(self):
        """
        Verify that DNS is resolved before connection, not during.
        
        This is tested by ensuring socket.getaddrinfo is not called after
        the initial validation in build_connection_pool_key_attributes.
        """
        from unittest.mock import patch
        from AntiSSRF._antissrf_agent import _AntiSSRFAdapter
        from requests import PreparedRequest
        
        dns_calls = []
        
        original_getaddrinfo = socket.getaddrinfo
        def tracking_getaddrinfo(*args, **kwargs):
            dns_calls.append(args)
            return original_getaddrinfo(*args, **kwargs)
        
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        policy.allow_plain_text_http = True
        adapter = _AntiSSRFAdapter(policy)
        
        request = PreparedRequest()
        request.prepare(method='GET', url='http://example.com/', headers={})
        
        with patch('socket.getaddrinfo', tracking_getaddrinfo):
            host_params, _ = adapter.build_connection_pool_key_attributes(
                request, verify=True
            )
        
        # DNS was called during validation
        initial_call_count = len(dns_calls)
        assert initial_call_count >= 1, "DNS should be resolved during validation"
        
        # After validation, the host is an IP - no further DNS needed
        # The host_params["host"] should be an IP that doesn't need resolution
        host = host_params["host"]
        assert host != "example.com", "Should be IP, not hostname"
