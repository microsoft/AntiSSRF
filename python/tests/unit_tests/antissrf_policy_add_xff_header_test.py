# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest
from requests import PreparedRequest

from AntiSSRF import AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError


class TestAddXFFHeaderCheckDefaults:
    """add_xff_header defaults off for InternalOnly/None and on for External policies."""

    @pytest.mark.parametrize("config,expected", [
        (PolicyConfigOptions.INTERNAL_ONLY, False),
        (PolicyConfigOptions.EXTERNAL_ONLY_V1, True),
        (PolicyConfigOptions.EXTERNAL_ONLY_LATEST, True),
        (PolicyConfigOptions.NONE, False),
    ])
    def test_add_xff_header_defaults(self, config, expected):
        policy = AntiSSRFPolicy(config)
        assert policy.add_xff_header is expected


class TestAddXFFHeader:
    """X-Forwarded-For injection when add_xff is enabled, disabled, or defaulted."""
    
    TEST_DOMAIN = "ambitious-flower-0611c910f.2.azurestaticapps.net";

    def setup_method(self):
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)

    def test_on_true_adds_header(self):
        """XFF header should be added when add_xff_header is True"""
        self.policy.add_xff_header = True
        session = self.policy.get_antissrf_session()
        response = session.get(f"https://{self.TEST_DOMAIN}/api/header-check?header=X-Forwarded-For")
        assert response.status_code == 200
        assert response.request.headers.get("X-Forwarded-For") == "true"

    def test_on_false_does_not_add_header(self):
        """XFF header should not be added when add_xff_header is False"""
        self.policy.add_xff_header = False
        session = self.policy.get_antissrf_session()
        response = session.get(f"https://{self.TEST_DOMAIN}/api/header-check?header=X-Forwarded-For")
        assert response.status_code == 200
        assert response.request.headers.get("X-Forwarded-For") is None

    def test_none_raises(self):
        """Setting add_xff_header to None should raise ValueError"""
        with pytest.raises(ValueError, match="Null or empty argument"):
            self.policy.add_xff_header = None

    def test_does_not_overwrite_header(self):
        """Pre-existing X-Forwarded-For header should be preserved"""
        self.policy.add_xff_header = True
        session = self.policy.get_antissrf_session()
        response = session.get(f"https://{self.TEST_DOMAIN}/api/header-check?header=X-Forwarded-For", headers={"X-Forwarded-For": "1.2.3.4"})
        assert response.status_code == 200
        assert response.request.headers.get("X-Forwarded-For") == "1.2.3.4"

    def test_no_edits_after_session(self):
        """Mutating add_xff_header after a session is created should raise"""
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="Policy can't be modified after it has been used to create a session"):
            policy.add_xff_header = True
