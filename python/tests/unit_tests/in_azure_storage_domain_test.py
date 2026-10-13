# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

from AntiSSRF import URIValidator


class TestInAzureStorageDomain:
    """Tests URIValidator.in_azure_storage_domain against valid and invalid Storage hostnames."""

    @pytest.mark.parametrize("uri", [None, ""])
    def test_should_return_false_for_null_and_empty_inputs(self, uri):
        assert URIValidator.in_azure_storage_domain(uri) is False

    @pytest.mark.parametrize("uri", [
        "https://myapp.blob.core.windows.net",
        "https://frontend3.web.core.windows.net",
        "https://data-lake.dfs.core.windows.net",
        "https://files123.file.core.windows.net",
        "https://queue-svc.queue.core.windows.net",
        "https://tables01.table.core.windows.net",
        "https://secure.blob.storage.azure.net",
        "https://internal9.web.storage.azure.net",
        "https://private-ep.dfs.storage.azure.net",
        "https://corp-files.file.storage.azure.net",
        "https://company2.queue.storage.azure.net",
        "https://enterprise.table.storage.azure.net",
        "https://gov-data.blob.core.usgovcloudapi.net",
        "https://portal456.web.core.usgovcloudapi.net",
        "https://analytics.dfs.core.usgovcloudapi.net",
        "https://docs-gov.file.core.usgovcloudapi.net",
        "https://notify123.queue.core.usgovcloudapi.net",
        "https://records.table.core.usgovcloudapi.net",
        "https://china-app.blob.core.chinacloudapi.cn",
        "https://website7.web.core.chinacloudapi.cn",
        "https://bigdata99.dfs.core.chinacloudapi.cn",
        "https://storage.file.core.chinacloudapi.cn",
        "https://events-cn.queue.core.chinacloudapi.cn",
        "https://metadata2.table.core.chinacloudapi.cn"
    ])
    def test_accepts_urls_in_storage_domains(self, uri):
        assert URIValidator.in_azure_storage_domain(uri) is True

    @pytest.mark.parametrize("uri", [
        "https://myapp-secondary.blob.storage.azure.net",
        "https://website-secondary.web.core.windows.net",
        "https://files5-secondary.dfs.core.usgovcloudapi.net",
        "https://messages-secondary.queue.core.chinacloudapi.cn",
        "https://corp99-secondary.table.storage.azure.net",
        "https://backup-secondary.file.core.windows.net"
    ])
    def test_supports_secondary_storage_endpoints(self, uri):
        assert URIValidator.in_azure_storage_domain(uri) is True

    @pytest.mark.parametrize("uri", [
        "https://acct.privatelink.blob.storage.azure.net",
        "https://web12.privatelink.web.core.windows.net",
        "https://data.privatelink.dfs.storage.azure.net",
        "https://files99.privatelink.file.core.usgovcloudapi.net",
        "https://queue.privatelink.queue.core.chinacloudapi.cn",
        "https://tables5-secondary.privatelink.table.storage.azure.net"
    ])
    def test_supports_private_link_storage_domains(self, uri):
        assert URIValidator.in_azure_storage_domain(uri) is True

    @pytest.mark.parametrize("uri", [
        "https://contosostaticsite.z22.web.core.windows.net",
        "https://webapp5.z03.web.storage.azure.net",
        "https://frontend.z45.blob.core.usgovcloudapi.net",
        "https://portal99.z01.web.core.chinacloudapi.cn",
        "https://static-site.privatelink.z88.dfs.storage.azure.net",
        "https://demo-secondary.z0.web.core.windows.net"
    ])
    def test_supports_static_sites_and_dns_zones(self, uri):
        assert URIValidator.in_azure_storage_domain(uri) is True

    @pytest.mark.parametrize("uri", [
        "https://my--app.blob.core.windows.net",
        "https://data--lake.dfs.storage.azure.net",
        "https://web--site.web.core.usgovcloudapi.net",
        "https://myapp.blob.core.windwos.net",
        "https://storage.table.core.windoes.net",
        "https://files.dfs.core.chinacloudapi.com",
        "https://queue.queue.stoarge.azure.net",
        "https://myapp.database.core.windows.net",
        "https://storage.cache.storage.azure.net",
        "https://files.storage.core.usgovcloudapi.net",
        "https://myapp.core.blob.windows.net",
        "https://storage.azure.storage.net",
        "https://files.windows.core.net",
        "https://myapp.blob.core.blob.windows.net",
        "https://storage.web.core.windows.net.storage.azure.net",
        "https://myapp.blob.core.windows.net.evil.com",
        "https://storage.table.core.windows.netmalicious",
        "https://files.dfs.storage.azure.net.attacker.org",
        "https://queue.queue.core.chinacloudapi.cnbad",
        "https://secure.web.storage.azure.netphishing",
        "https://corp.file.core.usgovcloudapi.net.fake"
    ])
    def test_rejects_urls_not_in_storage_domains(self, uri):
        assert URIValidator.in_azure_storage_domain(uri) is False

    @pytest.mark.parametrize("uri,expected", [
        # Various URL components are accepted.
        ("http://accountname.blob.core.windows.net/some/path", True),
        ("http://accountname.blob.core.windows.net#fragment", True),
        ("http://accountname.blob.core.windows.net/?query=hi", True),
        ("http://accountname.blob.core.windows.net:45", True),
        ("https://username@accountname.blob.core.windows.net", True),
        ("https://username:password@accountname.blob.core.windows.net", True),
        # Malformed schemes and authorities are rejected.
        ("http:/accountname.blob.core.windows.net", False),
        ("http:/\accountname.blob.core.windows.net", False),
        (r"http:\/accountname.blob.core.windows.net", False),
        ("http://accountname.blob.core.windows.net:badPort", False),
        ("http://:accountname.blob.core.windows.net", False)
        
    ])
    def test_correctly_parses_various_url_components(self, uri, expected):
        assert URIValidator.in_azure_storage_domain(uri) is expected

    @pytest.mark.parametrize("uri", [
        "http://ñame.blob.core.windows.net/",
        "http://name.blob.core.wiñdows.net/",
        "http://evil.c℁.blob.core.windows.net",
        "https://tëst.web.storage.azure.net",
        "https://app.blob.core.windöws.net",
        "https://файлы.file.core.chinacloudapi.cn",
        "https://データ.dfs.core.usgovcloudapi.net",
        "https://myapp.bløb.core.windows.net"
    ])
    def test_correctly_rejects_unicode(self, uri):
        assert URIValidator.in_azure_storage_domain(uri) is False

    @pytest.mark.parametrize("uri", [
        "http://ACCOUNTNAME.blob.core.windows.net",
        "http://accountname.BLOB.core.windows.net",
        "http://ACCOUNTNAME.BLOB.CORE.WINDOWS.NET",
        "hTtP://test.blob.core.windows.net/",
        "HTTPS://myapp.WEB.storage.azure.net",
        "https://DATA.dfs.STORAGE.AZURE.NET",
        "HtTpS://files.FILE.core.usgovcloudapi.net",
        "http://QUEUE.queue.CORE.chinacloudapi.cn",
        "https://TABLES.table.core.WINDOWS.net",
    ])
    def test_correctly_handles_upper_lowercase(self, uri):
        assert URIValidator.in_azure_storage_domain(uri) is True
        
    @pytest.mark.parametrize("uri,expected", [
        ("http://accountname.blob.core.windows.net", True),
        ("https://accountname.blob.core.windows.net", True),
        ("ws://accountname.blob.core.windows.net", False),
        ("wss://accountname.blob.core.windows.net", False),
        ("ftp://accountname.blob.core.windows.net", False),
        ("file://accountname.blob.core.windows.net", False),
        ("gopher://accountname.blob.core.windows.net", False),
        ("mailto:ccountname.blob.core.windows.net", False),
        ("data://accountname.blob.core.windows.net", False),
        ("javascript:alert('XSS')", False),
        ("evil.com://accountname.blob.core.windows.net", False),
        ("evil.com:/accountname.blob.core.windows.net", False),
        ("evil.com:\\accountname.blob.core.windows.net", False),
        ("evil.com:/\\accountname.blob.core.windows.net", False),
        ("evil.com:\\/accountname.blob.core.windows.net", False),
        ("evil.com://\\accountname.blob.core.windows.net", False),
        ("evil.com://///accountname.blob.core.windows.net", False),
        ("evil.com:\\\\accountname.blob.core.windows.net", False),
        ("evil.com:accountname.blob.core.windows.net", False),
    ])
    def test_correctly_enforces_allowed_protocols(self, uri, expected):
        assert URIValidator.in_azure_storage_domain(uri) is expected

    @pytest.mark.parametrize("uri", [
        "https://[0::0%25.blob.core.windows.net]/",
        "https://[fe80::1%25eth0]/",
        "https://[::1]/",
        "https://[::ffff:127.0.0.1]/",
        "https://169.254.169.254/",
        "https://10.0.0.1/",
        "https://127.0.0.1/blob.core.windows.net",
    ])
    def test_rejects_ip_literals_and_scope_smuggling(self, uri):
        assert URIValidator.in_azure_storage_domain(uri) is False