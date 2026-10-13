# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest
from requests.exceptions import InvalidSchema

from AntiSSRF import AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError


class TestPolicySchemeCheckDefaults:
    """Plain-text HTTP is disallowed by default across all config options."""

    @pytest.mark.parametrize("config", [
        PolicyConfigOptions.INTERNAL_ONLY,
        PolicyConfigOptions.EXTERNAL_ONLY_V1,
        PolicyConfigOptions.EXTERNAL_ONLY_LATEST,
        PolicyConfigOptions.NONE,
    ])
    def test_allow_plain_text_http_defaults_false(self, config):
        policy = AntiSSRFPolicy(config)
        assert policy.allow_plain_text_http is False


class TestPolicyScheme:
    """Scheme enforcement through an AntiSSRFSession. Rejections happen at the policy
    check before any network I/O, so these remain fast, deterministic unit tests."""
    
    TEST_DOMAIN = "ambitious-flower-0611c910f.2.azurestaticapps.net"
    
    def test_allow_plain_text_http_on_true(self):
        """When allow_plain_text_http is set to True, HTTP requests are allowed."""
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.allow_plain_text_http = True
        session = policy.get_antissrf_session()
        response = session.get(f"http://{self.TEST_DOMAIN}")
        assert response.status_code == 200
        response = session.get(f"https://{self.TEST_DOMAIN}")
        assert response.status_code == 200
        
    def test_allow_plain_text_http_on_false(self):
        """When allow_plain_text_http is set to False, HTTP requests are rejected."""
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.allow_plain_text_http = False
        session = policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="HTTP request is not allowed by policy"):
            session.get(f"http://{self.TEST_DOMAIN}")
        response = session.get(f"https://{self.TEST_DOMAIN}")
        assert response.status_code == 200
        

    def test_http_rejected_when_not_allowed(self):
        """An http request is rejected before connecting when plain-text HTTP is not allowed."""
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        session = policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="HTTP request is not allowed by policy"):
            session.get("http://example.com")

    @pytest.mark.parametrize("url", [
        "ws://example.com",
        "wss://example.com",
        "ftp://example.com",
        "gopher://example.com",
        "file:///etc/passwd",
        "ldap://example.com",
        "ldaps://example.com",
        "mailto:test@example.com",
        "tel:+1234567890",
        "data:text/plain;base64,SGVsbG8=",
        "javascript:alert('xss')",
        "custom://example.com"
    ])
    def test_non_http_schemes_rejected(self, url):
        """Non-http(s) schemes have no mounted adapter, so the session rejects them."""
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.allow_plain_text_http = True
        session = policy.get_antissrf_session()
        with pytest.raises(InvalidSchema):
            session.get(url)

    def test_none_raises(self):
        """Setting allow_plain_text_http to None should raise ValueError"""
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        with pytest.raises(ValueError, match="Null or empty argument"):
            policy.allow_plain_text_http = None

    def test_no_edits_after_session(self):
        """Mutating allow_plain_text_http after a session is created should raise"""
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="Policy can't be modified after it has been used to create a session"):
            policy.allow_plain_text_http = True
