# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Tests for AntiSSRF integration with the requests library.

These tests verify that the AntiSSRFSession properly integrates with the
requests library API and maintains compatibility with standard requests usage.
"""

import pytest
from AntiSSRF import AntiSSRFPolicy, PolicyConfigOptions
from AntiSSRF import AntiSSRFError
from AntiSSRF._antissrf_agent import _AntiSSRFAdapter, AntiSSRFSession
import requests
import socket


# ===========================================================================
# Session API Compatibility Tests
# ===========================================================================
class TestSessionAPICompatibility:
    """Test that AntiSSRFSession is compatible with requests.Session API."""
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_session_has_get_method(self):
        """Session should have get() method."""
        assert hasattr(self.session, 'get')
        assert callable(self.session.get)
    
    def test_session_has_post_method(self):
        """Session should have post() method."""
        assert hasattr(self.session, 'post')
        assert callable(self.session.post)
    
    def test_session_has_put_method(self):
        """Session should have put() method."""
        assert hasattr(self.session, 'put')
        assert callable(self.session.put)
    
    def test_session_has_delete_method(self):
        """Session should have delete() method."""
        assert hasattr(self.session, 'delete')
        assert callable(self.session.delete)
    
    def test_session_has_head_method(self):
        """Session should have head() method."""
        assert hasattr(self.session, 'head')
        assert callable(self.session.head)
    
    def test_session_has_options_method(self):
        """Session should have options() method."""
        assert hasattr(self.session, 'options')
        assert callable(self.session.options)
    
    def test_session_has_patch_method(self):
        """Session should have patch() method."""
        assert hasattr(self.session, 'patch')
        assert callable(self.session.patch)
    
    def test_session_has_request_method(self):
        """Session should have request() method."""
        assert hasattr(self.session, 'request')
        assert callable(self.session.request)
    
    def test_session_has_headers_attribute(self):
        """Session should have headers attribute."""
        assert hasattr(self.session, 'headers')
    
    def test_session_has_cookies_attribute(self):
        """Session should have cookies attribute."""
        assert hasattr(self.session, 'cookies')
    
    def test_session_has_auth_attribute(self):
        """Session should have auth attribute."""
        assert hasattr(self.session, 'auth')
    
    def test_session_has_proxies_attribute(self):
        """Session should have proxies attribute."""
        assert hasattr(self.session, 'proxies')
    
    def test_session_has_verify_attribute(self):
        """Session should have verify attribute."""
        assert hasattr(self.session, 'verify')
    
    def test_session_has_cert_attribute(self):
        """Session should have cert attribute."""
        assert hasattr(self.session, 'cert')
    
    def test_session_is_context_manager(self):
        """Session should support context manager protocol."""
        assert hasattr(self.session, '__enter__')
        assert hasattr(self.session, '__exit__')
    
    def test_session_context_manager_usage(self):
        """Session should work as context manager."""
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        with AntiSSRFSession(policy) as session:
            assert session is not None
            response = session.get("https://www.google.com")
            assert response.status_code == 200


# ===========================================================================
# Request Parameters Tests
# ===========================================================================

class TestRequestParameters:
    """Test that request parameters work correctly."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_custom_headers(self):
        """Custom headers should be passed through."""
        response = self.session.get(
            "https://httpbin.org/headers",
            headers={"X-Custom-Header": "test-value"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["headers"].get("X-Custom-Header") == "test-value"
    
    def test_query_parameters(self):
        """Query parameters should be passed through."""
        response = self.session.get(
            "https://httpbin.org/get",
            params={"key": "value", "foo": "bar"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["args"]["key"] == "value"
        assert data["args"]["foo"] == "bar"
    
    def test_post_data(self):
        """POST data should be passed through."""
        response = self.session.post(
            "https://httpbin.org/post",
            data={"username": "test", "password": "secret"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["form"]["username"] == "test"
        assert data["form"]["password"] == "secret"
    
    def test_json_data(self):
        """JSON data should be passed through."""
        response = self.session.post(
            "https://httpbin.org/post",
            json={"key": "value", "number": 42}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["json"]["key"] == "value"
        assert data["json"]["number"] == 42
    
    def test_timeout_parameter(self):
        """Timeout parameter should work."""
        # Should not raise - just verify it accepts the parameter
        response = self.session.get("https://www.google.com", timeout=10)
        assert response.status_code == 200
    
    def test_allow_redirects_true(self):
        """allow_redirects=True should follow redirects."""
        response = self.session.get(
            "https://ambitious-flower-0611c910f.2.azurestaticapps.net/api/redirect?num=3",
            allow_redirects=True
        )
        assert response.status_code == 200
        assert response.url == "https://ambitious-flower-0611c910f.2.azurestaticapps.net/api/redirect?num=1"
    
    def test_allow_redirects_false(self):
        """allow_redirects=False should not follow redirects."""
        response = self.session.get(
            "https://ambitious-flower-0611c910f.2.azurestaticapps.net/api/redirect?num=2",
            allow_redirects=False
        )
        assert response.status_code in {301, 302}

    def test_required_header_holds_on_redirect(self):
        """A required header must be enforced on every redirect hop, so a request
        that carries it should succeed through the entire redirect chain."""
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.add_required_headers(["X-Required-Header"])
        session = policy.get_antissrf_session()

        response = session.get(
            "https://ambitious-flower-0611c910f.2.azurestaticapps.net/api/redirect?num=3",
            headers={"X-Required-Header": "test-value"},
            allow_redirects=True,
        )
        assert response.status_code == 200


# ===========================================================================
# HTTP Methods Tests
# ===========================================================================

class TestHTTPMethods:
    """Test all HTTP methods work correctly with AntiSSRF."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    # ----- GET Method Tests -----
    
    def test_get_request(self):
        """GET request should work."""
        response = self.session.get("https://httpbin.org/get")
        assert response.status_code == 200
        data = response.json()
        assert "args" in data
        assert "headers" in data
    
    def test_get_with_query_params(self):
        """GET request with query parameters should work."""
        response = self.session.get(
            "https://httpbin.org/get",
            params={"foo": "bar", "baz": "qux"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["args"]["foo"] == "bar"
        assert data["args"]["baz"] == "qux"
    
    # ----- POST Method Tests -----
    
    def test_post_request(self):
        """POST request should work."""
        response = self.session.post("https://httpbin.org/post")
        assert response.status_code == 200
        data = response.json()
        assert "form" in data
        assert "json" in data
    
    def test_post_with_form_data(self):
        """POST request with form data should work."""
        response = self.session.post(
            "https://httpbin.org/post",
            data={"username": "testuser", "password": "testpass"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["form"]["username"] == "testuser"
        assert data["form"]["password"] == "testpass"
    
    def test_post_with_json_data(self):
        """POST request with JSON data should work."""
        response = self.session.post(
            "https://httpbin.org/post",
            json={"name": "test", "value": 123, "nested": {"key": "val"}}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["json"]["name"] == "test"
        assert data["json"]["value"] == 123
        assert data["json"]["nested"]["key"] == "val"
    
    def test_post_with_raw_body(self):
        """POST request with raw body should work."""
        response = self.session.post(
            "https://httpbin.org/post",
            data="raw text body",
            headers={"Content-Type": "text/plain"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["data"] == "raw text body"
    
    def test_post_with_files(self):
        """POST request with file upload should work."""
        files = {"file": ("test.txt", "file content", "text/plain")}
        response = self.session.post(
            "https://httpbin.org/post",
            files=files
        )
        assert response.status_code == 200
        data = response.json()
        assert "test.txt" in data["files"]["file"] or data["files"].get("file") == "file content"
    
    # ----- PUT Method Tests -----
    
    def test_put_request(self):
        """PUT request should work."""
        response = self.session.put("https://httpbin.org/put")
        assert response.status_code == 200
        data = response.json()
        assert "form" in data
    
    def test_put_with_json_data(self):
        """PUT request with JSON data should work."""
        response = self.session.put(
            "https://httpbin.org/put",
            json={"id": 1, "name": "updated", "active": True}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["json"]["id"] == 1
        assert data["json"]["name"] == "updated"
        assert data["json"]["active"] is True
    
    def test_put_with_form_data(self):
        """PUT request with form data should work."""
        response = self.session.put(
            "https://httpbin.org/put",
            data={"field1": "value1", "field2": "value2"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["form"]["field1"] == "value1"
        assert data["form"]["field2"] == "value2"
    
    # ----- PATCH Method Tests -----
    
    def test_patch_request(self):
        """PATCH request should work."""
        response = self.session.patch("https://httpbin.org/patch")
        assert response.status_code == 200
        data = response.json()
        assert "form" in data
    
    def test_patch_with_json_data(self):
        """PATCH request with JSON data should work."""
        response = self.session.patch(
            "https://httpbin.org/patch",
            json={"field": "patched_value"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["json"]["field"] == "patched_value"
    
    def test_patch_with_partial_update(self):
        """PATCH request for partial update should work."""
        response = self.session.patch(
            "https://httpbin.org/patch",
            json={"name": "new_name"}  # Only updating name field
        )
        assert response.status_code == 200
        data = response.json()
        assert data["json"]["name"] == "new_name"
    
    # ----- DELETE Method Tests -----
    
    def test_delete_request(self):
        """DELETE request should work."""
        response = self.session.delete("https://httpbin.org/delete")
        assert response.status_code == 200
        data = response.json()
        assert "args" in data
    
    def test_delete_with_query_params(self):
        """DELETE request with query parameters should work."""
        response = self.session.delete(
            "https://httpbin.org/delete",
            params={"id": "123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["args"]["id"] == "123"
    
    # ----- HEAD Method Tests -----
    
    def test_head_request(self):
        """HEAD request should work."""
        response = self.session.head("https://httpbin.org/get")
        assert response.status_code == 200
        # HEAD should not return body
        assert response.text == ""
    
    def test_head_returns_headers(self):
        """HEAD request should return headers."""
        response = self.session.head("https://httpbin.org/get")
        assert response.status_code == 200
        assert "Content-Type" in response.headers
        assert "Content-Length" in response.headers or "content-length" in response.headers.keys()
    
    def test_head_content_length_matches_get(self):
        """HEAD Content-Length should match GET response size."""
        head_response = self.session.head("https://httpbin.org/html")
        get_response = self.session.get("https://httpbin.org/html")
        
        # Some servers may not include Content-Length, so we check if present
        if "Content-Length" in head_response.headers:
            assert head_response.headers["Content-Length"] == str(len(get_response.content))
    
    # ----- OPTIONS Method Tests -----
    
    def test_options_request(self):
        """OPTIONS request should work."""
        response = self.session.options("https://httpbin.org/get")
        # httpbin returns 200 for OPTIONS
        assert response.status_code == 200
    
    # ----- Generic request() Method Tests -----
    
    def test_request_method_get(self):
        """Generic request() with GET method should work."""
        response = self.session.request("GET", "https://httpbin.org/get")
        assert response.status_code == 200
        data = response.json()
        assert "headers" in data
    
    def test_request_method_post(self):
        """Generic request() with POST method should work."""
        response = self.session.request(
            "POST",
            "https://httpbin.org/post",
            json={"test": "value"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["json"]["test"] == "value"
    
    def test_request_method_put(self):
        """Generic request() with PUT method should work."""
        response = self.session.request(
            "PUT",
            "https://httpbin.org/put",
            json={"update": True}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["json"]["update"] is True
    
    def test_request_method_delete(self):
        """Generic request() with DELETE method should work."""
        response = self.session.request("DELETE", "https://httpbin.org/delete")
        assert response.status_code == 200


# ===========================================================================
# Response Object Tests
# ===========================================================================

class TestResponseObject:
    """Test that response objects have expected attributes."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_response_has_status_code(self):
        """Response should have status_code attribute."""
        response = self.session.get("https://httpbin.org/get")
        assert hasattr(response, 'status_code')
        assert response.status_code == 200
    
    def test_response_has_headers(self):
        """Response should have headers attribute."""
        response = self.session.get("https://httpbin.org/get")
        assert hasattr(response, 'headers')
        assert 'Content-Type' in response.headers
    
    def test_response_has_text(self):
        """Response should have text attribute."""
        response = self.session.get("https://httpbin.org/get")
        assert hasattr(response, 'text')
        assert isinstance(response.text, str)
    
    def test_response_has_content(self):
        """Response should have content attribute."""
        response = self.session.get("https://httpbin.org/get")
        assert hasattr(response, 'content')
        assert isinstance(response.content, bytes)
    
    def test_response_has_json_method(self):
        """Response should have json() method."""
        response = self.session.get("https://httpbin.org/get")
        assert hasattr(response, 'json')
        assert callable(response.json)
        data = response.json()
        assert isinstance(data, dict)
    
    def test_response_has_url(self):
        """Response should have url attribute."""
        response = self.session.get("https://httpbin.org/get")
        assert hasattr(response, 'url')
        assert "httpbin.org" in response.url
    
    def test_response_has_ok(self):
        """Response should have ok attribute."""
        response = self.session.get("https://httpbin.org/get")
        assert hasattr(response, 'ok')
        assert response.ok is True
    
    def test_response_has_reason(self):
        """Response should have reason attribute."""
        response = self.session.get("https://httpbin.org/get")
        assert hasattr(response, 'reason')
        # Reason should be a non-empty string corresponding to status code
        assert isinstance(response.reason, str)
        assert len(response.reason) > 0
        # If we got 200, reason should be OK
        if response.status_code == 200:
            assert response.reason == "OK"
    
    def test_response_has_elapsed(self):
        """Response should have elapsed attribute."""
        response = self.session.get("https://httpbin.org/get")
        assert hasattr(response, 'elapsed')
    
    def test_response_has_request(self):
        """Response should have request attribute."""
        response = self.session.get("https://httpbin.org/get")
        assert hasattr(response, 'request')
        assert response.request.method == "GET"


# ===========================================================================
# Session State Tests
# ===========================================================================

class TestSessionState:
    """Test that session maintains state correctly."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_session_persists_cookies(self):
        """Session should persist cookies across requests."""
        # Set a cookie
        self.session.get("https://httpbin.org/cookies/set/test_cookie/test_value")
        
        # Verify cookie is sent in next request
        response = self.session.get("https://httpbin.org/cookies")
        data = response.json()
        assert data["cookies"].get("test_cookie") == "test_value"
    
    def test_session_default_headers(self):
        """Session default headers should be sent with all requests."""
        self.session.headers["X-Session-Header"] = "session-value"
        
        response = self.session.get("https://httpbin.org/headers")
        data = response.json()
        assert data["headers"].get("X-Session-Header") == "session-value"
    
    def test_request_headers_override_session_headers(self):
        """Request headers should override session headers."""
        self.session.headers["X-Test-Header"] = "session-value"
        
        response = self.session.get(
            "https://httpbin.org/headers",
            headers={"X-Test-Header": "request-value"}
        )
        data = response.json()
        assert data["headers"].get("X-Test-Header") == "request-value"
    
    def test_headers_maintained_across_multiple_requests(self):
        """Session headers should be maintained correctly across multiple requests."""
        # Set session-level headers
        self.session.headers["X-Session-Header"] = "persistent-value"
        
        # First request with additional request-specific header
        response1 = self.session.get(
            "https://httpbin.org/headers",
            headers={"X-Request-Only": "first-request"}
        )
        data1 = response1.json()
        assert data1["headers"].get("X-Session-Header") == "persistent-value"
        assert data1["headers"].get("X-Request-Only") == "first-request"
        
        # Second request - session header should still be there, 
        # but request-specific header from first request should NOT be present
        response2 = self.session.get("https://httpbin.org/headers")
        data2 = response2.json()
        assert data2["headers"].get("X-Session-Header") == "persistent-value"
        assert data2["headers"].get("X-Request-Only") is None
        
        # Third request with different request-specific header
        response3 = self.session.get(
            "https://httpbin.org/headers",
            headers={"X-Different-Header": "third-request"}
        )
        data3 = response3.json()
        assert data3["headers"].get("X-Session-Header") == "persistent-value"
        assert data3["headers"].get("X-Different-Header") == "third-request"
        assert data3["headers"].get("X-Request-Only") is None
    
    def test_headers_case_insensitive_across_requests(self):
        """Session headers should be case-insensitive across multiple requests."""
        self.session.headers["X-Custom-Header"] = "original-value"
        
        # First request - verify header is sent
        response1 = self.session.get("https://httpbin.org/headers")
        data1 = response1.json()
        assert data1["headers"].get("X-Custom-Header") == "original-value"
        
        # Override with different case in request
        response2 = self.session.get(
            "https://httpbin.org/headers",
            headers={"x-custom-header": "overridden-value"}
        )
        data2 = response2.json()
        assert data2["headers"].get("X-Custom-Header") == "overridden-value"
        
        # Session header should still have original value for next request
        response3 = self.session.get("https://httpbin.org/headers")
        data3 = response3.json()
        assert data3["headers"].get("X-Custom-Header") == "original-value"


# ===========================================================================
# Multiple Requests Tests
# ===========================================================================

class TestMultipleRequests:
    """Test behavior with multiple requests."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_multiple_requests_same_host(self):
        """Multiple requests to the same host should work."""
        for _ in range(3):
            response = self.session.get("https://httpbin.org/get")
            assert response.status_code == 200
    
    def test_multiple_requests_different_hosts(self):
        """Multiple requests to different hosts should work."""
        hosts = [
            "https://www.google.com",
            "https://www.bing.com",
            "https://httpbin.org/get",
        ]
        
        for host in hosts:
            response = self.session.get(host)
            assert response.status_code == 200


# ===========================================================================
# Certificate and TLS Tests
# ===========================================================================

class TestCertificatesAndTLS:
    """Test certificate handling and TLS configuration."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    # ----- Session cert attribute tests -----
    
    def test_session_has_cert_attribute(self):
        """Session should have cert attribute."""
        assert hasattr(self.session, 'cert')
    
    def test_session_cert_default_is_none(self):
        """Session cert should default to None."""
        assert self.session.cert is None
    
    def test_session_cert_can_be_set(self):
        """Session cert attribute can be set."""
        self.session.cert = '/path/to/cert.pem'
        assert self.session.cert == '/path/to/cert.pem'
    
    def test_session_cert_can_be_tuple(self):
        """Session cert can be set as tuple (cert, key)."""
        self.session.cert = ('/path/to/cert.pem', '/path/to/key.pem')
        assert self.session.cert == ('/path/to/cert.pem', '/path/to/key.pem')
    
    # ----- Session verify attribute tests -----
    
    def test_session_has_verify_attribute(self):
        """Session should have verify attribute."""
        assert hasattr(self.session, 'verify')
    
    def test_session_verify_default_is_true(self):
        """Session verify should default to True."""
        assert self.session.verify is True
    
    def test_session_verify_can_be_set_false(self):
        """Session verify can be set to False."""
        self.session.verify = False
        assert self.session.verify is False
    
    def test_session_verify_can_be_path(self):
        """Session verify can be set to CA bundle path."""
        self.session.verify = '/path/to/ca-bundle.crt'
        assert self.session.verify == '/path/to/ca-bundle.crt'
    
    # ----- Certificate validation tests -----
    
    def test_valid_certificate_succeeds(self):
        """Valid certificate should succeed."""
        response = self.session.get("https://www.google.com")
        assert response.status_code == 200
    
    def test_expired_certificate_fails_with_verify(self):
        """Expired certificate should fail when verify=True."""
        from requests.exceptions import SSLError
        with pytest.raises(SSLError):
            self.session.get("https://expired.badssl.com/", verify=True)
    
    def test_expired_certificate_succeeds_without_verify(self):
        """Expired certificate should succeed when verify=False."""
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            response = self.session.get("https://expired.badssl.com/", verify=False)
        assert response.status_code == 200
    
    def test_wrong_host_certificate_fails_with_verify(self):
        """Wrong host certificate should fail when verify=True."""
        from requests.exceptions import SSLError
        with pytest.raises(SSLError):
            self.session.get("https://wrong.host.badssl.com/", verify=True)
    
    def test_wrong_host_certificate_succeeds_without_verify(self):
        """Wrong host certificate should succeed when verify=False."""
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            response = self.session.get("https://wrong.host.badssl.com/", verify=False)
        assert response.status_code == 200
    
    def test_self_signed_certificate_fails_with_verify(self):
        """Self-signed certificate should fail when verify=True."""
        from requests.exceptions import SSLError
        with pytest.raises(SSLError):
            self.session.get("https://self-signed.badssl.com/", verify=True)
    
    def test_self_signed_certificate_succeeds_without_verify(self):
        """Self-signed certificate should succeed when verify=False."""
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            response = self.session.get("https://self-signed.badssl.com/", verify=False)
        assert response.status_code == 200
    
    def test_untrusted_root_certificate_fails_with_verify(self):
        """Untrusted root certificate should fail when verify=True."""
        from requests.exceptions import SSLError
        with pytest.raises(SSLError):
            self.session.get("https://untrusted-root.badssl.com/", verify=True)
    
    def test_untrusted_root_certificate_succeeds_without_verify(self):
        """Untrusted root certificate should succeed when verify=False."""
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            response = self.session.get("https://untrusted-root.badssl.com/", verify=False)
        assert response.status_code == 200
    
    # ----- Session-level verify setting tests -----
    
    def test_session_verify_false_applies_to_all_requests(self):
        """Setting session.verify=False should apply to all requests."""
        import warnings
        self.session.verify = False
        
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            # These should all succeed now
            response = self.session.get("https://expired.badssl.com/")
            assert response.status_code == 200
            
            response = self.session.get("https://self-signed.badssl.com/")
            assert response.status_code == 200
    
    def test_request_verify_overrides_session_verify(self):
        """Request-level verify should override session-level verify."""
        from requests.exceptions import SSLError
        
        # Set session to not verify
        self.session.verify = False
        
        # But request with verify=True should still fail for bad certs
        with pytest.raises(SSLError):
            self.session.get("https://expired.badssl.com/", verify=True)
    
    # ----- Certificate with IP address tests -----
    
    def test_https_to_ip_with_valid_cert(self):
        """HTTPS to IP with matching certificate should work."""
        # Most servers won't have IP SANs, so we test that the connection
        # attempt is made (not blocked by AntiSSRF) even if TLS fails
        from requests.exceptions import SSLError
        
        # 8.8.8.8 is Google DNS - won't have a valid HTTPS cert for IP
        try:
            self.session.get("https://8.8.8.8/", timeout=5)
        except SSLError:
            # Expected - no valid cert for IP address
            pass
    
    def test_https_to_blocked_ip_raises_antissrf_error(self):
        """HTTPS to blocked IP should raise AntiSSRFError, not SSLError."""
        # The AntiSSRF check should happen before TLS handshake
        with pytest.raises(AntiSSRFError):
            self.session.get("https://127.0.0.1/")


# ===========================================================================
# Client Certificate Tests
# ===========================================================================

class TestClientCertificates:
    """Test client certificate (mutual TLS) functionality."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_cert_parameter_accepts_string(self):
        """cert parameter should accept string path."""
        # We can't actually test with real certs easily, but we can verify
        # the parameter is accepted without error before connection
        # The request will fail but not due to parameter issues
        try:
            self.session.get(
                "https://httpbin.org/get",
                cert="/nonexistent/cert.pem",
                timeout=1
            )
        except FileNotFoundError:
            # Expected - file doesn't exist
            pass
        except Exception as e:
            # Other errors are acceptable, but not TypeError
            assert not isinstance(e, TypeError)
    
    def test_cert_parameter_accepts_tuple(self):
        """cert parameter should accept tuple (cert, key)."""
        try:
            self.session.get(
                "https://httpbin.org/get",
                cert=("/nonexistent/cert.pem", "/nonexistent/key.pem"),
                timeout=1
            )
        except FileNotFoundError:
            # Expected - files don't exist
            pass
        except Exception as e:
            # Other errors are acceptable, but not TypeError
            assert not isinstance(e, TypeError)
    
    def test_session_cert_attribute_used_in_requests(self):
        """Session cert attribute should be used in requests."""
        # Set a cert path on session
        self.session.cert = "/nonexistent/cert.pem"
        
        try:
            self.session.get("https://httpbin.org/get", timeout=1)
        except FileNotFoundError:
            # Expected - file doesn't exist, but this proves the cert attr is used
            pass
        except OSError:
            # Some systems may raise OSError instead
            pass


# ===========================================================================
# Session Methods Tests (requests.Session API)
# ===========================================================================

class TestSessionMethods:
    """Test all Session methods from requests.Session API."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    # ----- close() method -----
    
    def test_session_has_close_method(self):
        """Session should have close() method."""
        assert hasattr(self.session, 'close')
        assert callable(self.session.close)
    
    def test_session_close_can_be_called(self):
        """Session close() should be callable without error."""
        self.session.close()
        # Should not raise any exception
    
    def test_session_close_multiple_times(self):
        """Session close() can be called multiple times."""
        self.session.close()
        self.session.close()
        # Should not raise any exception
    
    # ----- get_adapter() method -----
    
    def test_session_has_get_adapter_method(self):
        """Session should have get_adapter() method."""
        assert hasattr(self.session, 'get_adapter')
        assert callable(self.session.get_adapter)
    
    def test_get_adapter_returns_adapter_for_http(self):
        """get_adapter() should return adapter for http://."""
        adapter = self.session.get_adapter("http://example.com")
        assert adapter is not None
        assert isinstance(adapter, _AntiSSRFAdapter)
    
    def test_get_adapter_returns_adapter_for_https(self):
        """get_adapter() should return adapter for https://."""
        adapter = self.session.get_adapter("https://example.com")
        assert adapter is not None
        assert isinstance(adapter, _AntiSSRFAdapter)
    
    # ----- mount() method -----
    
    def test_session_has_mount_method(self):
        """Session should have mount() method."""
        assert hasattr(self.session, 'mount')
        assert callable(self.session.mount)
    
    def test_mount_custom_adapter(self):
        """mount() should allow mounting custom adapters."""
        custom_adapter = _AntiSSRFAdapter(self.policy)
        self.session.mount("https://custom.example.com", custom_adapter)
        
        retrieved = self.session.get_adapter("https://custom.example.com/path")
        assert retrieved is custom_adapter
    
    # ----- prepare_request() method -----
    
    def test_session_has_prepare_request_method(self):
        """Session should have prepare_request() method."""
        assert hasattr(self.session, 'prepare_request')
        assert callable(self.session.prepare_request)
    
    def test_prepare_request_returns_prepared_request(self):
        """prepare_request() should return a PreparedRequest."""
        req = requests.Request('GET', 'https://httpbin.org/get')
        prepared = self.session.prepare_request(req)
        
        assert prepared is not None
        assert hasattr(prepared, 'method')
        assert hasattr(prepared, 'url')
        assert hasattr(prepared, 'headers')
        assert prepared.method == 'GET'
    
    def test_prepare_request_merges_session_headers(self):
        """prepare_request() should merge session headers."""
        self.session.headers['X-Session-Header'] = 'session-value'
        
        req = requests.Request('GET', 'https://httpbin.org/get')
        prepared = self.session.prepare_request(req)
        
        assert 'X-Session-Header' in prepared.headers
        assert prepared.headers['X-Session-Header'] == 'session-value'
    
    # ----- send() method -----
    
    def test_session_has_send_method(self):
        """Session should have send() method."""
        assert hasattr(self.session, 'send')
        assert callable(self.session.send)
    
    def test_send_prepared_request(self):
        """send() should send a PreparedRequest."""
        req = requests.Request('GET', 'https://httpbin.org/get')
        prepared = self.session.prepare_request(req)
        
        response = self.session.send(prepared)
        assert response.status_code == 200
    
    def test_send_with_timeout(self):
        """send() should accept timeout parameter."""
        req = requests.Request('GET', 'https://httpbin.org/get')
        prepared = self.session.prepare_request(req)
        
        response = self.session.send(prepared, timeout=10)
        assert response.status_code == 200
    
    # ----- merge_environment_settings() method -----
    
    def test_session_has_merge_environment_settings_method(self):
        """Session should have merge_environment_settings() method."""
        assert hasattr(self.session, 'merge_environment_settings')
        assert callable(self.session.merge_environment_settings)
    
    def test_merge_environment_settings_returns_dict(self):
        """merge_environment_settings() should return a dict."""
        result = self.session.merge_environment_settings(
            url='https://example.com',
            proxies={},
            stream=False,
            verify=True,
            cert=None
        )
        assert isinstance(result, dict)
        assert 'verify' in result
        assert 'proxies' in result
        assert 'stream' in result
        assert 'cert' in result


# ===========================================================================
# Session Attributes Tests (requests.Session API)
# ===========================================================================

class TestSessionAttributes:
    """Test all Session attributes from requests.Session API."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    # ----- auth attribute -----
    
    def test_session_has_auth_attribute(self):
        """Session should have auth attribute."""
        assert hasattr(self.session, 'auth')
    
    def test_session_auth_default_is_none(self):
        """Session auth should default to None."""
        assert self.session.auth is None
    
    def test_session_auth_can_be_set_tuple(self):
        """Session auth can be set as tuple (user, pass)."""
        self.session.auth = ('user', 'pass')
        assert self.session.auth == ('user', 'pass')
    
    def test_session_auth_used_in_request(self):
        """Session auth should be used in requests."""
        self.session.auth = ('user', 'pass')
        response = self.session.get("https://httpbin.org/basic-auth/user/pass")
        assert response.status_code == 200
    
    # ----- cookies attribute -----
    
    def test_session_has_cookies_attribute(self):
        """Session should have cookies attribute."""
        assert hasattr(self.session, 'cookies')
    
    def test_session_cookies_is_cookiejar(self):
        """Session cookies should be a CookieJar."""
        from http.cookiejar import CookieJar
        assert isinstance(self.session.cookies, CookieJar)
    
    def test_session_cookies_can_be_set(self):
        """Session cookies can be set."""
        self.session.cookies.set('test_cookie', 'test_value')
        assert 'test_cookie' in self.session.cookies
    
    def test_session_cookies_sent_with_request(self):
        """Session cookies should be sent with requests."""
        self.session.cookies.set('my_cookie', 'cookie_value', domain='httpbin.org')
        response = self.session.get("https://httpbin.org/cookies")
        data = response.json()
        assert data["cookies"].get("my_cookie") == "cookie_value"
    
    # ----- headers attribute -----
    
    def test_session_has_headers_attribute(self):
        """Session should have headers attribute."""
        assert hasattr(self.session, 'headers')
    
    def test_session_headers_is_dict_like(self):
        """Session headers should be dict-like."""
        assert hasattr(self.session.headers, '__getitem__')
        assert hasattr(self.session.headers, '__setitem__')
    
    def test_session_headers_case_insensitive(self):
        """Session headers should be case-insensitive."""
        self.session.headers['Content-Type'] = 'application/json'
        assert self.session.headers['content-type'] == 'application/json'
    
    def test_session_headers_sent_with_request(self):
        """Session headers should be sent with requests."""
        self.session.headers['X-Custom-Session-Header'] = 'custom-value'
        response = self.session.get("https://httpbin.org/headers")
        data = response.json()
        assert data["headers"].get("X-Custom-Session-Header") == "custom-value"
    
    # ----- hooks attribute -----
    
    def test_session_has_hooks_attribute(self):
        """Session should have hooks attribute."""
        assert hasattr(self.session, 'hooks')
    
    def test_session_hooks_is_dict(self):
        """Session hooks should be a dict."""
        assert isinstance(self.session.hooks, dict)
    
    def test_session_hooks_has_response_key(self):
        """Session hooks should have 'response' key."""
        assert 'response' in self.session.hooks
    
    def test_session_hooks_callback_executed(self):
        """Session hooks callback should be executed."""
        hook_called = []
        
        def hook(response, *args, **kwargs):
            hook_called.append(True)
            return response
        
        self.session.hooks['response'].append(hook)
        self.session.get("https://httpbin.org/get")
        
        assert len(hook_called) == 1
    
    # ----- max_redirects attribute -----
    
    def test_session_has_max_redirects_attribute(self):
        """Session should have max_redirects attribute."""
        assert hasattr(self.session, 'max_redirects')
    
    def test_session_max_redirects_is_integer(self):
        """Session max_redirects should be an integer."""
        assert isinstance(self.session.max_redirects, int)
    
    def test_session_max_redirects_default_is_30(self):
        """Session max_redirects should default to 30."""
        assert self.session.max_redirects == 30
    
    def test_session_max_redirects_can_be_changed(self):
        """Session max_redirects can be changed."""
        self.session.max_redirects = 5
        assert self.session.max_redirects == 5
    
    def test_session_max_redirects_enforced(self):
        """Session max_redirects should be enforced."""
        self.session.max_redirects = 1
        
        from requests.exceptions import TooManyRedirects
        with pytest.raises(TooManyRedirects):
            # This endpoint redirects multiple times
            self.session.get("https://ambitious-flower-0611c910f.2.azurestaticapps.net/api/redirect?num=3")
    
    # ----- params attribute -----
    
    def test_session_has_params_attribute(self):
        """Session should have params attribute."""
        assert hasattr(self.session, 'params')
    
    def test_session_params_can_be_set(self):
        """Session params can be set."""
        self.session.params = {'session_param': 'session_value'}
        assert self.session.params['session_param'] == 'session_value'
    
    def test_session_params_merged_with_request(self):
        """Session params should be merged with request params."""
        self.session.params = {'session_param': 'session_value'}
        response = self.session.get(
            "https://httpbin.org/get",
            params={'request_param': 'request_value'}
        )
        data = response.json()
        assert data["args"].get("session_param") == "session_value"
        assert data["args"].get("request_param") == "request_value"
    
    # ----- proxies attribute -----
    
    def test_session_has_proxies_attribute(self):
        """Session should have proxies attribute."""
        assert hasattr(self.session, 'proxies')
    
    def test_session_proxies_is_dict(self):
        """Session proxies should be a dict."""
        assert isinstance(self.session.proxies, dict)
    
    def test_session_proxies_can_be_set(self):
        """Session proxies can be set."""
        self.session.proxies = {'http': 'http://proxy:8080'}
        assert self.session.proxies['http'] == 'http://proxy:8080'
    
    # ----- stream attribute -----
    
    def test_session_has_stream_attribute(self):
        """Session should have stream attribute."""
        assert hasattr(self.session, 'stream')
    
    def test_session_stream_default_is_false(self):
        """Session stream should default to False."""
        assert self.session.stream is False
    
    def test_session_stream_can_be_set(self):
        """Session stream can be set."""
        self.session.stream = True
        assert self.session.stream is True
    
    # ----- trust_env attribute -----
    
    def test_session_has_trust_env_attribute(self):
        """Session should have trust_env attribute."""
        assert hasattr(self.session, 'trust_env')
    
    def test_session_trust_env_is_boolean(self):
        """Session trust_env should be boolean."""
        assert isinstance(self.session.trust_env, bool)
    
    def test_session_trust_env_can_be_set(self):
        """Session trust_env can be set."""
        self.session.trust_env = False
        assert self.session.trust_env is False


# ===========================================================================
# Request Object Tests (requests.Request API)
# ===========================================================================

class TestRequestObject:
    """Test requests.Request object usage with AntiSSRFSession."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_request_object_can_be_created(self):
        """Request object can be created."""
        req = requests.Request('GET', 'https://httpbin.org/get')
        assert req.method == 'GET'
        assert req.url == 'https://httpbin.org/get'
    
    def test_request_object_with_headers(self):
        """Request object can include headers."""
        req = requests.Request(
            'GET',
            'https://httpbin.org/get',
            headers={'X-Custom': 'value'}
        )
        assert req.headers['X-Custom'] == 'value'
    
    def test_request_object_with_data(self):
        """Request object can include data."""
        req = requests.Request(
            'POST',
            'https://httpbin.org/post',
            data={'key': 'value'}
        )
        assert req.data == {'key': 'value'}
    
    def test_request_object_with_json(self):
        """Request object can include json."""
        req = requests.Request(
            'POST',
            'https://httpbin.org/post',
            json={'key': 'value'}
        )
        assert req.json == {'key': 'value'}
    
    def test_request_object_with_params(self):
        """Request object can include params."""
        req = requests.Request(
            'GET',
            'https://httpbin.org/get',
            params={'key': 'value'}
        )
        assert req.params == {'key': 'value'}
    
    def test_request_object_with_auth(self):
        """Request object can include auth."""
        req = requests.Request(
            'GET',
            'https://httpbin.org/get',
            auth=('user', 'pass')
        )
        assert req.auth == ('user', 'pass')
    
    def test_request_object_with_cookies(self):
        """Request object can include cookies."""
        req = requests.Request(
            'GET',
            'https://httpbin.org/get',
            cookies={'session': 'abc123'}
        )
        assert req.cookies == {'session': 'abc123'}
    
    def test_request_prepare_method(self):
        """Request object has prepare() method."""
        req = requests.Request('GET', 'https://httpbin.org/get')
        prepared = req.prepare()
        
        assert hasattr(prepared, 'method')
        assert hasattr(prepared, 'url')
        assert hasattr(prepared, 'headers')
    
    def test_prepared_request_can_be_sent(self):
        """PreparedRequest can be sent via session."""
        req = requests.Request('GET', 'https://httpbin.org/get')
        prepared = self.session.prepare_request(req)
        
        response = self.session.send(prepared)
        assert response.status_code == 200


# ===========================================================================
# Response Object Tests (requests.Response API)
# ===========================================================================

class TestResponseObjectAPI:
    """Test requests.Response object attributes and methods."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
        self.response = self.session.get("https://httpbin.org/get")
    
    # ----- Response attributes -----
    
    def test_response_status_code(self):
        """Response should have status_code."""
        assert self.response.status_code == 200
    
    def test_response_headers(self):
        """Response should have headers."""
        assert 'Content-Type' in self.response.headers
    
    def test_response_url(self):
        """Response should have url."""
        assert 'httpbin.org' in self.response.url
    
    def test_response_encoding(self):
        """Response should have encoding."""
        assert hasattr(self.response, 'encoding')
    
    def test_response_reason(self):
        """Response should have reason."""
        assert self.response.reason == "OK"
    
    def test_response_cookies(self):
        """Response should have cookies."""
        assert hasattr(self.response, 'cookies')
    
    def test_response_elapsed(self):
        """Response should have elapsed time."""
        from datetime import timedelta
        assert isinstance(self.response.elapsed, timedelta)
    
    def test_response_history(self):
        """Response should have history."""
        assert hasattr(self.response, 'history')
        assert isinstance(self.response.history, list)
    
    def test_response_request(self):
        """Response should have request attribute."""
        assert self.response.request is not None
        assert self.response.request.method == 'GET'
    
    def test_response_raw(self):
        """Response should have raw attribute."""
        assert hasattr(self.response, 'raw')
    
    # ----- Response properties -----
    
    def test_response_ok_property(self):
        """Response should have ok property."""
        assert self.response.ok is True
    
    def test_response_ok_false_for_error(self):
        """Response ok should be False for error status."""
        response = self.session.get("https://httpbin.org/status/404")
        assert response.ok is False
    
    def test_response_is_redirect_property(self):
        """Response should have is_redirect property."""
        assert hasattr(self.response, 'is_redirect')
        assert self.response.is_redirect is False
    
    def test_response_is_permanent_redirect_property(self):
        """Response should have is_permanent_redirect property."""
        assert hasattr(self.response, 'is_permanent_redirect')
    
    def test_response_links_property(self):
        """Response should have links property."""
        assert hasattr(self.response, 'links')
    
    def test_response_next_property(self):
        """Response should have next property."""
        assert hasattr(self.response, 'next')
    
    def test_response_apparent_encoding_property(self):
        """Response should have apparent_encoding property."""
        assert hasattr(self.response, 'apparent_encoding')
    
    # ----- Response methods -----
    
    def test_response_json_method(self):
        """Response should have json() method."""
        data = self.response.json()
        assert isinstance(data, dict)
        assert 'headers' in data
    
    def test_response_json_raises_on_invalid_json(self):
        """Response json() should raise on invalid JSON."""
        response = self.session.get("https://httpbin.org/html")
        with pytest.raises(requests.exceptions.JSONDecodeError):
            response.json()
    
    def test_response_text_property(self):
        """Response should have text property."""
        assert isinstance(self.response.text, str)
        assert len(self.response.text) > 0
    
    def test_response_content_property(self):
        """Response should have content property."""
        assert isinstance(self.response.content, bytes)
        assert len(self.response.content) > 0
    
    def test_response_raise_for_status_success(self):
        """Response raise_for_status() should not raise for 200."""
        self.response.raise_for_status()  # Should not raise
    
    def test_response_raise_for_status_error(self):
        """Response raise_for_status() should raise for error status."""
        response = self.session.get("https://httpbin.org/status/404")
        with pytest.raises(requests.exceptions.HTTPError):
            response.raise_for_status()
    
    def test_response_close_method(self):
        """Response should have close() method."""
        assert hasattr(self.response, 'close')
        assert callable(self.response.close)
    
    def test_response_iter_content_method(self):
        """Response should have iter_content() method."""
        assert hasattr(self.response, 'iter_content')
        assert callable(self.response.iter_content)
    
    def test_response_iter_lines_method(self):
        """Response should have iter_lines() method."""
        assert hasattr(self.response, 'iter_lines')
        assert callable(self.response.iter_lines)


# ===========================================================================
# Streaming Response Tests
# ===========================================================================

class TestStreamingResponse:
    """Test streaming response functionality."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_stream_parameter_accepted(self):
        """stream parameter should be accepted."""
        response = self.session.get("https://httpbin.org/get", stream=True)
        assert response.status_code == 200
        response.close()
    
    def test_iter_content_with_stream(self):
        """iter_content() should work with stream=True."""
        response = self.session.get("https://httpbin.org/bytes/1024", stream=True)
        
        chunks = list(response.iter_content(chunk_size=256))
        total_size = sum(len(chunk) for chunk in chunks)
        assert total_size == 1024
        response.close()
    
    def test_iter_lines_with_stream(self):
        """iter_lines() should work with stream=True."""
        response = self.session.get(
            "https://httpbin.org/stream/5",
            stream=True
        )
        
        lines = list(response.iter_lines())
        assert len(lines) == 5
        response.close()


# ===========================================================================
# Authentication Tests
# ===========================================================================

class TestAuthentication:
    """Test authentication functionality."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_basic_auth_tuple(self):
        """Basic auth with tuple should work."""
        response = self.session.get(
            "https://httpbin.org/basic-auth/user/pass",
            auth=('user', 'pass')
        )
        assert response.status_code == 200
    
    def test_basic_auth_object(self):
        """Basic auth with HTTPBasicAuth should work."""
        from requests.auth import HTTPBasicAuth
        response = self.session.get(
            "https://httpbin.org/basic-auth/user/pass",
            auth=HTTPBasicAuth('user', 'pass')
        )
        assert response.status_code == 200
    
    def test_basic_auth_failure(self):
        """Basic auth with wrong credentials should fail."""
        response = self.session.get(
            "https://httpbin.org/basic-auth/user/pass",
            auth=('wrong', 'credentials')
        )
        assert response.status_code == 401
    
    def test_session_auth_persists(self):
        """Session auth should persist across requests."""
        self.session.auth = ('user', 'pass')
        
        response1 = self.session.get("https://httpbin.org/basic-auth/user/pass")
        response2 = self.session.get("https://httpbin.org/basic-auth/user/pass")
        
        assert response1.status_code == 200
        assert response2.status_code == 200
    
    def test_digest_auth(self):
        """Digest auth should work."""
        from requests.auth import HTTPDigestAuth
        response = self.session.get(
            "https://httpbin.org/digest-auth/auth/user/pass",
            auth=HTTPDigestAuth('user', 'pass')
        )
        assert response.status_code == 200


# ===========================================================================
# Timeout Tests
# ===========================================================================

class TestTimeouts:
    """Test timeout functionality."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_timeout_float(self):
        """Timeout as float should work."""
        response = self.session.get("https://httpbin.org/get", timeout=10.0)
        assert response.status_code == 200
    
    def test_timeout_tuple(self):
        """Timeout as tuple (connect, read) should work."""
        response = self.session.get("https://httpbin.org/get", timeout=(5, 10))
        assert response.status_code == 200
    
    def test_read_timeout_raises(self):
        """Read timeout should raise ReadTimeout."""
        from requests.exceptions import ReadTimeout
        with pytest.raises(ReadTimeout):
            self.session.get("https://httpbin.org/delay/10", timeout=1)
    
    def test_connect_timeout_raises(self):
        """Connect timeout should raise ConnectTimeout or Timeout."""
        from requests.exceptions import ConnectTimeout, Timeout
        # Use a non-routable IP to trigger connect timeout
        try:
            self.session.get("https://10.255.255.1/", timeout=0.001)
            pytest.fail("Expected timeout exception")
        except (ConnectTimeout, Timeout, AntiSSRFError):
            # Any of these is acceptable
            pass


# ===========================================================================
# Proxy Tests
# ===========================================================================

class TestProxies:
    """Test proxy configuration."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_proxies_parameter_accepted(self):
        """proxies parameter should be accepted."""
        # We can't actually test proxy functionality without a proxy server,
        # but we can verify the parameter is accepted
        try:
            self.session.get(
                "https://httpbin.org/get",
                proxies={'https': 'http://invalid-proxy:8080'},
                timeout=1
            )
        except requests.exceptions.ProxyError:
            # Expected - invalid proxy
            pass
  
    def test_session_proxies_can_be_set(self):
        """Session proxies can be set."""
        self.session.proxies = {
            'http': 'http://proxy:8080',
            'https': 'https://proxy:8080'
        }
        assert self.session.proxies['http'] == 'http://proxy:8080'


# ===========================================================================
# Exception Handling Tests
# ===========================================================================

class TestExceptions:
    """Test exception handling."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up policy and session for each test."""
        self.policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        self.session = AntiSSRFSession(self.policy)
    
    def test_connection_error_for_invalid_host(self):
        """ConnectionError should be raised for invalid host."""
        from requests.exceptions import ConnectionError
        with pytest.raises((ConnectionError, AntiSSRFError, socket.gaierror)):
            self.session.get("https://this-domain-does-not-exist-12345.com/", timeout=5)
    
    def test_too_many_redirects(self):
        """TooManyRedirects should be raised for redirect loop."""
        from requests.exceptions import TooManyRedirects
        self.session.max_redirects = 1
        
        with pytest.raises(TooManyRedirects):
            # Use absolute-redirect which is more reliable
            self.session.get("https://ambitious-flower-0611c910f.2.azurestaticapps.net/api/redirect?num=3")
    
    def test_antissrf_error_for_blocked_ip(self):
        """AntiSSRFError should be raised for blocked IP."""
        with pytest.raises(AntiSSRFError):
            self.session.get("https://127.0.0.1/")
    
    def test_antissrf_error_for_private_network(self):
        """AntiSSRFError should be raised for private network."""
        with pytest.raises(AntiSSRFError):
            self.session.get("https://192.168.1.1/")
    
    def test_antissrf_error_for_link_local(self):
        """AntiSSRFError should be raised for link-local (IMDS)."""
        with pytest.raises(AntiSSRFError):
            self.session.get("https://169.254.169.254/")
    