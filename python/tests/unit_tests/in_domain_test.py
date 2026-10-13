# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

from AntiSSRF import URIValidator


class TestInDomain:
    
    @pytest.mark.parametrize("url,domain", [
        (None, "bing.com"),
        (None, ["bing.com"]),
        ("http://bing.com", None),
        ("http://bing.com", ""),
        ("http://bing.com", []),
    ])
    def test_should_return_false_for_null_and_empty_inputs(self, url, domain):
        assert URIValidator.in_domain(url, domain) is False

    @pytest.mark.parametrize("url,domain", [
        ("http://office.com", "office.com"),
        ("https://office.com", "office.com"),
        ("https://azure.com", ".azure.com"),
        ("https://subdomain.microsoft.com", "microsoft.com"),
        ("https://subdomain.microsoft.com", ".microsoft.com"),
    ])
    def test_accepts_urls_in_trusted_single_domains(self, url, domain):
        assert URIValidator.in_domain(url, domain) is True

    @pytest.mark.parametrize("url,domains", [
        ("https://subdomain.one.com", ["one.com", ".two.com"]),
        ("http://subdomain.two.com", ["one.com", ".two.com"]),
        ("https://one.com", ["one.com", ".two.com"]),
        ("https://two.net", ["one.com", ".two.net"]),
    ])
    def test_accepts_urls_in_trusted_domain_arrays(self, url, domains):
        assert URIValidator.in_domain(url, domains) is True

    @pytest.mark.parametrize("url,domain", [
        ("http://azure.com", "office.com"),
        ("https://office.com", "subdomain.office.com"),
        ("https://azure.com", ".office.com"),
        ("https://subdomain.microsoft.com", "differentsubdomain.microsoft.com"),
    ])
    def test_rejects_urls_not_in_trusted_single_domains(self, url, domain):
        assert URIValidator.in_domain(url, domain) is False

    @pytest.mark.parametrize("url,domains", [
        ("http://azure.com", ["one.com", "office.com"]),
        ("https://office.com", ["subdomain.office.com"]),
        ("https://azure.com", [".office.com", "two.com"]),
        ("https://subdomain.microsoft.com", ["differentsubdomain.microsoft.com"]),
    ])
    def test_rejects_urls_not_in_trusted_domain_arrays(self, url, domains):
        assert URIValidator.in_domain(url, domains) is False

    @pytest.mark.parametrize("url", [
        "http://username@bing.com:/",
        "http://username:password@bing.com",
        "http://bing.com:45",
        "http://bing.com/some/path",
        "http://bing.com#fragment",
        "http://bing.com/?query=hi",
    ])
    def test_correctly_parses_various_url_components(self, url):
        assert URIValidator.in_domain(url, "bing.com") is True
        assert URIValidator.in_domain(url, ["bing.com"]) is True

    @pytest.mark.parametrize("url", [
        "http://bing.com:badPort",
        "http://:bing.com",
        "http:/\\bing.com",
        "http:\\/bing.com"
    ])
    def test_correctly_rejects_invalid_url_components(self, url):
        assert URIValidator.in_domain(url, "bing.com") is False
        assert URIValidator.in_domain(url, ["bing.com"]) is False

    @pytest.mark.parametrize("url,domain", [
        ("http://español.test.net/", "test.net"),
        ("http://español.test.net/", "xn--espaol-zwa.test.net"),
        ("http://你好/", "xn--6qq79v"),
        ("http://test.你好/", "你好"),
        ("http://bing.hi.com/", "hi.com"),
        ("http://bing.hı.com/", "hı.com"),
        ("http://bing.hí.com/", "hí.com"),
    ])
    def test_correctly_handles_unicode_in_single_domains(self, url, domain):
        assert URIValidator.in_domain(url, domain) is True

    @pytest.mark.parametrize("url,domains", [
        ("http://español.test.net/", ["notempty", "test.net"]),
        ("http://español.test.net/", ["hello", "xn--espaol-zwa.test.net"]),
        ("http://你好/", ["xn--6qq79v", "not_the_domain.com"]),
        ("http://bing.hı.com/", ["hi.com", "hı.com"]),
        ("http://bing.hí.com/", ["hí.com", "notempty"]),
        ("http://test.你好/", ["你好", "bing.com"]),
    ])
    def test_correctly_handles_unicode_in_domain_arrays(self, url, domains):
        assert URIValidator.in_domain(url, domains) is True

    @pytest.mark.parametrize("url,domain", [
        ("http://bing.hı.com/", "hi.com"),
        ("http://bing.hí.com/", "hi.com"),
        ("http://😉", "🔨"),
        ("http://😉", "😉"),
    ])
    def test_correctly_rejects_invalid_unicode_single_domains(self, url, domain):
        assert URIValidator.in_domain(url, domain) is False

    @pytest.mark.parametrize("url,domains", [
        ("http://bing.hı.com/", ["hi.com", "hí.com"]),
        ("http://bing.hí.com/", ["hi.com", "hı.com"]),
        ("http://😉", ["🔨", ""]),
    ])
    def test_correctly_rejects_invalid_unicode_domain_arrays(self, url, domains):
        assert URIValidator.in_domain(url, domains) is False

    def test_correctly_rejects_invalid_unicode_strings(self):
        assert URIValidator.in_domain("http://evil.c℁.core.azure.net", "azure.net") is False

    @pytest.mark.parametrize("url,domain", [
        ("hTtP://test.net", "test.net"),
        ("wSS://test.net", "test.net"),
        ("http://HELLO.com", "hello.com"),
        ("http://Hello.你好/", "xn--6qq79v"),
        ("http://español.test.net/", "TeSt.net"),
        ("http://hello.COM", "HELLO.com"),
    ])
    def test_correctly_handles_upper_lowercase(self, url, domain):
        assert URIValidator.in_domain(url, domain) is True

    @pytest.mark.parametrize("url,domains", [
        ("http://HELLO.com", ["notempty", "hello.com"]),
        ("http://Hello.你好/", ["xn--6qq79v", "not_the_domain.com"]),
        ("http://español.test.net/", ["TeSt.net", "asdf"]),
        ("http://hello.COM", ["HELLO.com"]),
    ])
    def test_correctly_handles_upper_lowercase_in_domain_arrays(self, url, domains):
        assert URIValidator.in_domain(url, domains) is True

    @pytest.mark.parametrize("url", [
        "http://bing.com",
        "https://bing.com",
        "ws://bing.com",
        "wss://bing.com",
    ])
    def test_correctly_enforces_allowed_protocols(self, url):
        assert URIValidator.in_domain(url, "bing.com") is True

    @pytest.mark.parametrize("url", [
        "ftp://bing.com",
        "file://bing.com",
        "gopher://bing.com",
        "mailto:bing.com",
        "data://bing.com",
        "javascript:alert('XSS')",
        "evil.com://bing.com",
    ])
    def test_correctly_rejects_disallowed_protocols(self, url):
        assert URIValidator.in_domain(url, "bing.com") is False

    @pytest.mark.parametrize("url", [
        "c:\\foo\\bar",
        "file:///filepath",
        "CCCCCCCCCCCCCCCCCCCCCCC:\\\\\\\\\\\\foo\\bar",
        "/foo/bar",
        "//////////////////////////////////////",
        "\\\\.\\a\\a\\a\\",
        "\\\\\\.\\a\\a\\a\\",
    ])
    def test_correctly_rejects_file_path_strings(self, url):
        assert URIValidator.in_domain(url, "somedomain.com") is False
