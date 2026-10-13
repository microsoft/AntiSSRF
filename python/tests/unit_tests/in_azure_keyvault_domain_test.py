# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

from AntiSSRF import URIValidator


class TestInAzureKeyVaultDomain:
    """Tests URIValidator.in_azure_keyvault_domain against valid and invalid Key Vault hostnames."""

    @pytest.mark.parametrize("uri", [None, ""])
    def test_should_return_false_for_null_and_empty_inputs(self, uri):
        assert URIValidator.in_azure_keyvault_domain(uri) is False

    @pytest.mark.parametrize("uri", [
        "https://contoso.vault.azure.net",
        "https://fabrikam42.managedhsm.azure.net",
        "https://corp-hsm.vault.azure.cn",
        "https://devkeys99.managedhsm.azure.cn",
        "https://govvault1.vault.usgovcloudapi.net",
        "https://securehsm.managedhsm.usgovcloudapi.net",
        # exact service domain
        "https://vault.azure.net",
    ])
    def test_accepts_urls_in_key_vault_domains(self, uri):
        assert URIValidator.in_azure_keyvault_domain(uri) is True

    @pytest.mark.parametrize("uri", [
        "https://contoso.privatelink.vault.azure.net",
        "https://fabrikam42.privatelink.managedhsm.azure.net",
        "https://corp-hsm.privatelink.vault.azure.cn",
        "https://devkeys99.privatelink.managedhsm.azure.cn",
        "https://govvault1.privatelink.vault.usgovcloudapi.net",
        "https://securehsm.privatelink.managedhsm.usgovcloudapi.net"
    ])
    def test_supports_private_link_key_vault_domains(self, uri):
        assert URIValidator.in_azure_keyvault_domain(uri) is True

    @pytest.mark.parametrize("uri", [
        "https://my--vault.vault.azure.net",
        "https://contoso.managedhsm.azure.net.evil.com",
        "https://fabrikam.vault.azure.net.attacker.org",
        "https://corp.vault.azuree.net",
        "https://devkeys.vault.azure.nett",
        "https://contoso.vault.azure.netmalicious",
        "https://contoso.managedhsm.azure.usgovcloudapi.net",
        "https://contoso.azure.vault.net",
        "https://contoso.vault.azure.cn.fake",
        "https://securehsm.managedhsm.usgovcloudapi.net.phishing",
        "https://corp.managedhsm.azure.cnn",
        "https://contoso.vaultazure.net",
        "https://contoso.vault.azure",
        "https://yahoo.com",
    ])
    def test_rejects_urls_not_in_key_vault_domains(self, uri):
        assert URIValidator.in_azure_keyvault_domain(uri) is False

    @pytest.mark.parametrize("uri,expected", [
        # Various URL components are accepted.
        ("http://accountname.vault.azure.net/some/path", True),
        ("http://accountname.vault.azure.net#fragment", True),
        ("http://accountname.vault.azure.net/?query=hi", True),
        ("http://accountname.vault.azure.net:45", True),
        ("https://username@accountname.vault.azure.net", True),
        ("https://username:password@accountname.vault.azure.net", True),
        ("http:accountname.vault.azure.net", False),
        ("http:/accountname.vault.azure.net", False),
        ("http:/\\accountname.vault.azure.net", False),
        ("http:\\/accountname.vault.azure.net", False),
        ("http://accountname.vault.azure.net:badPort", False),
        ("http://:accountname.vault.azure.net", False),
    ])
    def test_correctly_parses_various_url_components(self, uri, expected):
        assert URIValidator.in_azure_keyvault_domain(uri) is expected

    
    @pytest.mark.parametrize("uri", [
        "http://ñame.vault.azure.net/",
        "https://contøso.managedhsm.azure.net",
        "https://fabrikäm.vault.azure.cn/",
        "https://corp.vàult.azure.net",
        "https://devkeys.vault.àzure.net",
        "https://contoso.vault.azure.cñ",
        "https://сontoso.vault.usgovcloudapi.net",
        "https://myapp.mànagedhsm.azure.cn",
        "http://evil.c℁.vault.azure.net",
        "https://データ.vault.usgovcloudapi.net",
        "https://файлы.managedhsm.usgovcloudapi.net"
    ])
    def test_correctly_rejects_unicode(self, uri):
        assert URIValidator.in_azure_keyvault_domain(uri) is False
        
    @pytest.mark.parametrize("uri", [
        "http://CONTOSO.vault.azure.net",
        "https://fabrikam42.VAULT.azure.net",
        "https://corp-hsm.vault.AZURE.net",
        "https://DEVKEYS99.managedhsm.azure.cn/",
        "https://govvault1.MANAGEDHSM.azure.cn",
        "https://SECUREHSM.vault.USGOVCLOUDAPI.net",
        "https://contoso.managedhsm.USGOVCLOUDAPI.NET",
        "HTTPS://fabrikam42.vault.azure.net",
        "hTtPs://corp-hsm.managedhsm.azure.net",
        "https://CONTOSO.VAULT.AZURE.NET",
        "HtTpS://devkeys99.vault.azure.cn",
        "https://GovVault1.Vault.Azure.Net"
    ])
    def test_correctly_handles_upper_lowercase(self, uri):
        assert URIValidator.in_azure_keyvault_domain(uri) is True

    @pytest.mark.parametrize("uri,expected", [        
        ("http://accountname.vault.azure.net", True),
        ("https://accountname.vault.azure.net", True),
        ("ws://accountname.vault.azure.net", False),
        ("wss://accountname.vault.azure.net", False),
        ("ftp://accountname.vault.azure.net", False),
        ("file://accountname.vault.azure.net", False),
        ("gopher://accountname.vault.azure.net", False),
        ("mailto:accountname.vault.azure.net", False),
        ("data://accountname.vault.azure.net", False),
        ("javascript:alert('XSS')", False),
        ("evil.com://accountname.vault.azure.net", False),
        ("evil.com:/accountname.vault.azure.net", False),
        ("evil.com:\\accountname.vault.azure.net", False),
        ("evil.com:\\/accountname.vault.azure.net", False),
        ("evil.com://\\accountname.vault.azure.net", False),
        ("evil.com://///accountname.vault.azure.net", False),
        ("evil.com:\\\\accountname.vault.azure.net", False),
        ("evil.com:accountname.vault.azure.net", False),
    ])
    def test_correctly_enforces_allowed_protocols(self, uri, expected):
        assert URIValidator.in_azure_keyvault_domain(uri) is expected
    