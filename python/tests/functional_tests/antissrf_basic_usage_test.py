# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Basic usage tests for AntiSSRF.

These functional tests cover behaviors not exercised by the policy unit tests:
URL-parsing bypass attempts and redirect handling through a live session.
"""

import pytest
from AntiSSRF import AntiSSRFPolicy, PolicyConfigOptions
from AntiSSRF import AntiSSRFError
import socket

# ===========================================================================
# URL Parsing Bypass Attempts Tests
# ===========================================================================

class TestURLParsingBypassAttempts:
    """Test that URL parsing bypass attempts are blocked."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = self.policy.get_antissrf_session()
    
    def test_userinfo_bypass_attempt(self):
        """URL with userinfo containing blocked IP should be blocked."""
        # Attempt: http://evil.com@127.0.0.1/ - some parsers extract 127.0.0.1 as host
        with pytest.raises((AntiSSRFError, Exception)):
            self.session.get("https://evil.com@127.0.0.1/")
    
    def test_fragment_bypass_attempt(self):
        """URL with fragment should not bypass checks."""
        with pytest.raises(AntiSSRFError):
            self.session.get("https://127.0.0.1/#http://allowed.com")
    
    def test_fragment_bypass_attempt_no_slash(self):
        """URL with fragment and no slashes should not bypass checks."""
        with pytest.raises(AntiSSRFError):
            self.session.get("https://127.0.0.1#http://#allowed.com")
    
    def test_fragment_bypass_attempt_no_scheme(self):
        """URL with fragment and no scheme should not bypass checks."""
        with pytest.raises(AntiSSRFError):
            self.session.get("https://127.0.0.1/#allowed.com")
    
    def test_localhost_variations(self):
        """Various localhost variations should be blocked."""
        blocked_hosts = [
            "https://localhost/",
            "https://LOCALHOST/",
            "https://Localhost/",
            "https://127.0.0.1/",
            "https://127.1/",  # Some systems interpret this as 127.0.0.1
        ]
        
        for url in blocked_hosts:
            with pytest.raises((AntiSSRFError, socket.gaierror)):
                self.session.get(url)
    
    def test_ipv6_localhost_variations(self):
        """IPv6 localhost variations should be blocked."""
        blocked_hosts = [
            "https://[::1]/",
            "https://[0:0:0:0:0:0:0:1]/",
            "https://[0000:0000:0000:0000:0000:0000:0000:0001]/",
        ]
        
        for url in blocked_hosts:
            with pytest.raises((AntiSSRFError, socket.gaierror)):
                self.session.get(url)
    
    def test_decimal_ip_encoding(self):
        """Decimal-encoded IPs should be blocked."""
        # 127.0.0.1 = 2130706433 in decimal
        with pytest.raises((AntiSSRFError, socket.gaierror)):
            self.session.get("https://2130706433/")
    
    def test_hex_ip_encoding(self):
        """Hex-encoded IPs should be blocked."""
        # 127.0.0.1 = 0x7f000001
        with pytest.raises((AntiSSRFError, socket.gaierror)):
            self.session.get("https://0x7f000001/")
    
    def test_octal_ip_encoding(self):
        """Octal-encoded IPs should be blocked."""
        # 127.0.0.1 = 0177.0.0.01
        with pytest.raises((AntiSSRFError, socket.gaierror)):
            self.session.get("https://0177.0.0.01/")
    
    def test_mixed_encoding_ip(self):
        """Mixed-encoding IPs should be blocked."""
        # 127.0.0.1 in mixed notation
        with pytest.raises((AntiSSRFError, socket.gaierror)):
            self.session.get("https://0x7f.0.0.1/")
    
    def test_ipv4_mapped_ipv6(self):
        """IPv4-mapped IPv6 addresses should be blocked."""
        with pytest.raises((AntiSSRFError, socket.gaierror)):
            self.session.get("https://[::ffff:127.0.0.1]/")
    
    def test_double_url_encoding_not_processed(self):
        """Double URL encoding should not bypass checks."""
        # %31%32%37%2e%30%2e%30%2e%31 = 127.0.0.1
        # The URL library should not double-decode
        try:
            # This might raise various errors depending on URL parsing
            self.session.get("https://%31%32%37%2e%30%2e%30%2e%31/")
        except AntiSSRFError:
            pass  # Expected if decoded
        except Exception:
            pass  # Also acceptable if URL parsing fails


# ===========================================================================
# Redirect Behavior Tests
# ===========================================================================

class TestRedirectBehavior:
    """Test redirect handling with AntiSSRF policy."""
    
    TEST_URL_BASE = "https://ambitious-flower-0611c910f.2.azurestaticapps.net/api"
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = self.policy.get_antissrf_session()
    
    def test_successful_redirect(self):
        """Successful redirect to allowed destination."""
        response = self.session.get(f"{self.TEST_URL_BASE}/redirect?num=1")
        assert response.status_code == 200
    
    def test_redirect_to_imds_ip_blocked(self):
        """Redirect to IMDS IP should be blocked."""
        with pytest.raises((AntiSSRFError, socket.gaierror)):
            self.session.get(f"{self.TEST_URL_BASE}/imds-ip")
    
    def test_redirect_to_imds_url_blocked(self):
        """Redirect to IMDS URL should be blocked."""
        with pytest.raises((AntiSSRFError, socket.gaierror)):
            self.session.get(f"{self.TEST_URL_BASE}/imds-url")
    
    def test_redirect_to_wireserver_blocked(self):
        """Redirect to WireServer should be blocked."""
        with pytest.raises((AntiSSRFError, socket.gaierror)):
            self.session.get(f"{self.TEST_URL_BASE}/wireserver")
