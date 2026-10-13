# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest
from requests import PreparedRequest

from AntiSSRF import AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError

TEST_DOMAIN = "ambitious-flower-0611c910f.2.azurestaticapps.net"

class TestPolicyHeadersBadInputs:
    """None and empty-string header lists both raise."""

    def test_add_denied_headers_none(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        with pytest.raises(ValueError, match="Null or empty argument"):
            policy.add_denied_headers(None)

    def test_add_required_headers_none(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        with pytest.raises(ValueError, match="Null or empty argument"):
            policy.add_required_headers(None)

    def test_add_denied_headers_empty_string(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        with pytest.raises(ValueError, match="Headers cannot be an empty string"):
            policy.add_denied_headers([""])

    def test_add_required_headers_empty_string(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        with pytest.raises(ValueError, match="Headers cannot be an empty string"):
            policy.add_required_headers([""])

    def test_no_edits_after_session(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="Policy can't be modified after it has been used to create a session"):
            policy.add_required_headers(["X-Test-Header"])
        with pytest.raises(AntiSSRFError, match="Policy can't be modified after it has been used to create a session"):
            policy.add_denied_headers(["X-Test-Header"])


class TestPolicyHeadersCheckDefaults:
    """All config options start with empty required and denied header lists."""

    @pytest.mark.parametrize("config", [
        PolicyConfigOptions.INTERNAL_ONLY,
        PolicyConfigOptions.EXTERNAL_ONLY_V1,
        PolicyConfigOptions.EXTERNAL_ONLY_LATEST,
        PolicyConfigOptions.NONE,
    ])
    def test_config_option_has_empty_headers(self, config):
        policy = AntiSSRFPolicy(config)
        assert len(policy.required_headers) == 0
        assert len(policy.denied_headers) == 0


class TestPolicyRequiredHeader:
    """A request is allowed only when it carries the configured required header."""

    def setup_method(self):
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)

    def test_has_required_header(self):
        """Request with required header should be allowed"""
        self.policy.add_required_headers(["X-Test-Header"])
        session = self.policy.get_antissrf_session()
        try:
            session.get(f"https://{TEST_DOMAIN}/api/header-check?header=X-Test-Header", headers={ "X-Test-Header": "test-value"}).status_code == 200
        except AntiSSRFError:
            raise
        except Exception:
            pass

    def test_does_not_have_required_header(self):
        """Request without required header should be rejected"""
        self.policy.add_required_headers(["X-Test-Header"])
        session = self.policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="HTTP request is not allowed by policy"):
            session.get(f"https://{TEST_DOMAIN}/api/header-check?header=X-Test-Header", headers={ "Not-X-Test-Header": "test-value"})


class TestPolicyDeniedHeader:
    """A request is rejected when it carries a configured denied header."""

    def setup_method(self):
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)

    def test_has_denied_header(self):
        """Request with denied header should be rejected"""
        self.policy.add_denied_headers(["X-Test-Header"])
        session = self.policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="HTTP request is not allowed by policy"):
            session.get(f"https://{TEST_DOMAIN}/api/header-check?header=X-Test-Header", headers={ "X-Test-Header": "test-value"})

    def test_does_not_have_denied_header(self):
        """Request without denied header should be allowed"""
        self.policy.add_denied_headers(["X-Test-Header"])
        session = self.policy.get_antissrf_session()
        try:
            session.get(f"https://{TEST_DOMAIN}/api/header-check?header=X-Test-Header", headers={ "Not-X-Test-Header": "test-value"}).status_code == 200
        except AntiSSRFError:
            raise
        except Exception:
            pass

class TestPolicyHeadersBothRequiredAndDenied:
    """When a header is both required and denied, the request is rejected either way."""

    def setup_method(self):
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        self.policy.add_required_headers(["X-Test-Header"])
        self.policy.add_denied_headers(["X-Test-Header"])

    def test_with_header_present_denied_wins(self):
        """When header is both required and denied, having it should be rejected (denied check)"""
        session = self.policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="HTTP request is not allowed by policy"):
            session.get(f"https://{TEST_DOMAIN}/api/header-check?header=X-Test-Header", headers={ "X-Test-Header": "test-value"})

    def test_without_header_missing_required(self):
        """When header is both required and denied, not having it should be rejected (missing required)"""
        session = self.policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="HTTP request is not allowed by policy"):
            session.get(f"https://{TEST_DOMAIN}/api/header-check?header=X-Test-Header", headers={ "Not-X-Test-Header": "test-value"})


class TestPolicyHeadersWithXFF:
    """An auto-added X-Forwarded-For satisfies a required rule and triggers a denied rule."""

    def test_xff_satisfies_required_header(self):
        """XFF auto-added should satisfy required X-Forwarded-For header"""
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.add_xff_header = True
        policy.add_required_headers(["X-Forwarded-For", "X-Test-Header"])
        session = policy.get_antissrf_session()
        try:
            session.get(f"https://{TEST_DOMAIN}/api/header-check?header=X-Forwarded-For", headers={"X-Test-Header": "test-value"}).status_code == 200
        except AntiSSRFError:
            raise
        except Exception:
            pass

    def test_xff_triggers_denied_header(self):
        """XFF auto-added should trigger denied X-Forwarded-For header"""
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.add_xff_header = True
        policy.add_denied_headers(["X-Forwarded-For", "Not-X-Test-Header"])
        session = policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="HTTP request is not allowed by policy"):
            session.get(f"https://{TEST_DOMAIN}/api/header-check?header=X-Forwarded-For", headers={"X-Test-Header": "test-value"})

class TestPolicyHoldsOnRedirect:
    """Tests to ensure that policy rules are enforced even when redirects occur."""

    def test_required_header_on_redirect(self):
        """Required headers should still be checked on redirects"""
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.add_required_headers(["X-Required-Header"])
        session = policy.get_antissrf_session()
        try: 
            session.get(f"https://{TEST_DOMAIN}/api/redirect?num=3", headers={"X-Required-Header": "test-value"}).status_code == 200
        except AntiSSRFError:
            raise
        except Exception:
            pass

class TestPolicyHeadersCaseInsensitive:
    """Required and denied header names match case-insensitively."""

    def test_required_header_case_insensitive(self):
        """Required headers should match case-insensitively"""
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.add_required_headers(["X-Test-Header"])
        session = policy.get_antissrf_session() 
        try:
            session.get(f"https://{TEST_DOMAIN}/api/header-check?header=X-Test-Header", headers={"x-test-header": "test-value"}).status_code == 200
        except AntiSSRFError:
            raise
        except Exception:
            pass

    def test_denied_header_case_insensitive(self):
        """Denied headers should match case-insensitively"""
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.add_denied_headers(["X-Test-Header"])
        session = policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="HTTP request is not allowed by policy"):
            session.get(f"https://{TEST_DOMAIN}/api/header-check?header=X-Test-Header", headers={"x-test-header": "test-value"})
