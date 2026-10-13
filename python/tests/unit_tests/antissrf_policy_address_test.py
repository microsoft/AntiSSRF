# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import socket

import pytest

from AntiSSRF import AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError
from AntiSSRF.ipaddress_ranges import IPAddressRanges

TEST_DOMAIN = "ambitious-flower-0611c910f.2.azurestaticapps.net"


class TestBadInputs:    
    def test_deny_all_then_specific_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.deny_all_unspecified_ips = True
        with pytest.raises(AntiSSRFError, match="Can't add denied networks when deny_all_unspecified_ips is true"):
            policy.add_denied_addresses(["1.2.3.4"])

    def test_add_allowed_none_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        with pytest.raises(ValueError, match="Null argument"):
            policy.add_allowed_addresses(None)

    def test_add_allowed_with_none_element_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        with pytest.raises(AntiSSRFError, match="Invalid network string"):
            policy.add_allowed_addresses([None])

    def test_add_denied_none_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        with pytest.raises(ValueError, match="Null argument"):
            policy.add_denied_addresses(None)

    def test_add_denied_with_none_element_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        with pytest.raises(AntiSSRFError, match="Invalid network string"):
            policy.add_denied_addresses([None])

    def test_add_denied_empty_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        with pytest.raises(ValueError, match="Null argument"):
            policy.add_denied_addresses([])

    def test_add_denied_invalid_ip_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        with pytest.raises(AntiSSRFError, match="Invalid network string"):
            policy.add_denied_addresses(["invalid.ip.address"])

    def test_add_denied_out_of_range_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        with pytest.raises(AntiSSRFError, match="Invalid network string"):
            policy.add_denied_addresses(["256.256.256.256/24"])

    def test_add_denied_invalid_prefix_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        with pytest.raises(AntiSSRFError, match="Invalid network string"):
            policy.add_denied_addresses(["192.168.1.1/33"])

    def test_add_allowed_invalid_ip_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        with pytest.raises(AntiSSRFError, match="Invalid network string"):
            policy.add_allowed_addresses(["not-an-ip"])

    def test_add_denied_array_with_none_element_raises(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        with pytest.raises(AntiSSRFError, match="Invalid network string"):
            policy.add_denied_addresses(["192.168.1.0/24", None, "10.0.0.0/8"])

    def test_no_edits_after_session(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        policy.get_antissrf_session()
        with pytest.raises(AntiSSRFError, match="Policy can't be modified after it has been used to create a session"):
            policy.add_allowed_addresses(["1.2.3.4"])
        with pytest.raises(AntiSSRFError, match="Policy can't be modified after it has been used to create a session"):
            policy.add_denied_addresses(["1.2.3.4"])


# ======= Check defaults across all config options =======

# IPs that should be denied by all restricting policies
imds_addrs = [
    "https://169.254.169.254/latest/meta-data/",
    "https://0xA9.0xFE.0xA9.0xFE/latest/meta-data/",
    "https://[::ffff:169.254.169.254]/latest/meta-data/",
    "https://[::ffff:A9FE:A9FE]/latest/meta-data/",
    f"https://{TEST_DOMAIN}/api/imds-ip?code=301",
    f"https://{TEST_DOMAIN}/api/imds-ip?code=302",
    f"https://{TEST_DOMAIN}/api/imds?redirectNum=3"
]

wireserver_addrs = [
    "http://168.63.129.16/",
    "http://0xA8.0x3F.0x81.0x10/",
    "http://[::ffff:168.63.129.16]/",
    "http://[::ffff:A83F:8110]/",
    f"https://{TEST_DOMAIN}/api/wireserver"
]

localhost_addrs = [
    "http://127.0.0.1/",
    "http://0x7F.0x0.0x0.0x1/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7F00:1]/",
    f"https://{TEST_DOMAIN}/api/localhost",
    "http://localhost/"
]

# Policies that should deny IMDS/wireserver/localhost
denying_configs = [
    PolicyConfigOptions.INTERNAL_ONLY,
    PolicyConfigOptions.EXTERNAL_ONLY_V1,
    PolicyConfigOptions.EXTERNAL_ONLY_LATEST,
]


@pytest.mark.parametrize("config", denying_configs)
@pytest.mark.parametrize("addr", imds_addrs)
def test_check_defaults_imds_denied(config, addr):
    policy = AntiSSRFPolicy(config)
    policy.allow_plain_text_http = True
    session = policy.get_antissrf_session()
    with pytest.raises((AntiSSRFError, socket.gaierror), match="denied by policy|Name or service not known|getaddrinfo failed|not known"):
        session.get(addr)


@pytest.mark.parametrize("config", denying_configs)
@pytest.mark.parametrize("addr", wireserver_addrs)
def test_check_defaults_wireserver_denied(config, addr):
    policy = AntiSSRFPolicy(config)
    policy.allow_plain_text_http = True
    session = policy.get_antissrf_session()
    with pytest.raises((AntiSSRFError, socket.gaierror), match="denied by policy|Name or service not known|getaddrinfo failed|not known"):
        session.get(addr)


@pytest.mark.parametrize("config", denying_configs)
@pytest.mark.parametrize("addr", localhost_addrs)
def test_check_defaults_localhost_denied(config, addr):
    policy = AntiSSRFPolicy(config)
    policy.allow_plain_text_http = True
    session = policy.get_antissrf_session()
    with pytest.raises((AntiSSRFError, socket.gaierror), match="denied by policy|Name or service not known|getaddrinfo failed|not known"):
        session.get(addr)


@pytest.mark.parametrize("addr", imds_addrs + wireserver_addrs + localhost_addrs)
def test_check_defaults_not_denied(addr):
    policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
    policy.allow_plain_text_http = True
    session = policy.get_antissrf_session()
    # NONE denies nothing; the request may fail to connect, but must not be denied by policy.
    try:
        session.get(addr)
    except AntiSSRFError as e:
        assert "denied by policy" not in str(e), f"{addr} should not be denied by policy"
    except Exception:
        pass


# ======= Default with IPAddressRanges =======


class TestDefaultWithIPAddressRanges:

    def setup_method(self):
        """ExternalOnlyV1 + allow IMDS/wireserver/loopback should permit those IPs"""
        policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
        policy.allow_plain_text_http = True
        policy.add_allowed_addresses(
            IPAddressRanges.imds
            + IPAddressRanges.wireserver
            + IPAddressRanges.loopback
        )
        self.session = policy.get_antissrf_session()

    @pytest.mark.parametrize("addr", [
        "http://127.0.0.1/",
        f"http://{TEST_DOMAIN}/api/localhost"
    ])
    def test_allow_loopback(self, addr):
        try:
            self.session.get(addr)
        except AntiSSRFError:
            raise
        except Exception:
            pass
    
    @pytest.mark.parametrize("addr", [
        "http://168.63.129.16/",
        f"http://{TEST_DOMAIN}/api/wireserver"
    ])
    def test_allow_wireserver(self, addr):
        try:
            self.session.get(addr)
        except AntiSSRFError:
            raise
        except Exception:
            pass

    @pytest.mark.parametrize("addr", [
        "http://169.254.169.254/",
        f"http://{TEST_DOMAIN}/api/imds"
    ])
    def test_allow_imds(self, addr):
        try:
            self.session.get(addr)
        except AntiSSRFError:
            raise
        except Exception:
            pass


# ======= Allow/Deny IPv4/IPv6 tests =======


class TestAllowIPv4Addresses:

    def setup_method(self):
        infos = socket.getaddrinfo(TEST_DOMAIN, None, socket.AF_INET, socket.SOCK_STREAM)
        self.test_ips = [info[4][0] for info in infos]

        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.allow_plain_text_http = True
        policy.deny_all_unspecified_ips = True
        policy.add_allowed_addresses(self.test_ips)
        self.session = policy.get_antissrf_session()

    def test_allowed_ipv4(self):
        # Allowed by policy; may still fail for non-policy (network) reasons.
        try:
            self.session.get(f"http://{self.test_ips[0]}")
        except AntiSSRFError:
            raise
        except Exception:
            pass

    def test_allowed_ipv4_mapped_ipv6(self):
        try:
            self.session.get(f"http://[::ffff:{self.test_ips[0]}]:80")
        except AntiSSRFError:
            raise
        except Exception:
            pass

    def test_disallowed_ipv4(self):
        with pytest.raises(AntiSSRFError, match="denied by policy"):
            self.session.get("http://1.2.3.4")

    def test_disallowed_ipv6(self):
        with pytest.raises(AntiSSRFError, match="denied by policy"):
            self.session.get("http://[1:2:3:4:5:6:7:8]")


class TestAllowIPv4MappedIPv6Addresses:

    def setup_method(self):
        infos = socket.getaddrinfo(TEST_DOMAIN, None, socket.AF_INET, socket.SOCK_STREAM)
        self.test_ips = [info[4][0] for info in infos]

        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.allow_plain_text_http = True
        policy.deny_all_unspecified_ips = True
        policy.add_allowed_addresses([f"::ffff:{ip}" for ip in self.test_ips])
        self.session = policy.get_antissrf_session()

    def test_allowed_ipv4(self):
        try:
            self.session.get(f"http://{self.test_ips[0]}")
        except AntiSSRFError:
            raise
        except Exception:
            pass

    def test_allowed_ipv4_mapped_ipv6(self):
        try:
            self.session.get(f"http://[::ffff:{self.test_ips[0]}]:80")
        except AntiSSRFError:
            raise
        except Exception:
            pass

    def test_disallowed_ipv4(self):
        with pytest.raises(AntiSSRFError, match="denied by policy"):
            self.session.get("http://1.2.3.4")

    def test_disallowed_ipv6(self):
        with pytest.raises(AntiSSRFError, match="denied by policy"):
            self.session.get("http://[1:2:3:4:5:6:7:8]")


class TestAllowIPv6Addresses:

    def setup_method(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.allow_plain_text_http = True
        policy.deny_all_unspecified_ips = True
        policy.add_allowed_addresses(["::1"])
        self.session = policy.get_antissrf_session()

    def test_allowed_ipv6(self):
        try:
            self.session.get("http://[::1]")
        except AntiSSRFError:
            raise
        except Exception:
            pass

    def test_disallowed_ipv4(self):
        with pytest.raises(AntiSSRFError, match="denied by policy"):
            self.session.get("https://1.2.3.4")

    def test_disallowed_different_ipv6(self):
        with pytest.raises(AntiSSRFError, match="denied by policy"):
            self.session.get("https://[2606:4700:4700::1111]")


class TestDenyIPv4Address:

    def setup_method(self):
        infos = socket.getaddrinfo(TEST_DOMAIN, None, socket.AF_INET, socket.SOCK_STREAM)
        self.test_ips = [info[4][0] for info in infos]

        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.add_denied_addresses(self.test_ips)
        self.session = policy.get_antissrf_session()

    def test_denied_ipv4(self):
        with pytest.raises(AntiSSRFError, match="denied by policy"):
            self.session.get(f"https://{self.test_ips[0]}")

    def test_denied_ipv4_mapped_ipv6(self):
        with pytest.raises(AntiSSRFError, match="denied by policy"):
            self.session.get(f"https://[::ffff:{self.test_ips[0]}]")

    def test_allowed_different_ipv4(self):
        try:
            self.session.get("https://github.com")
        except AntiSSRFError:
            raise
        except Exception:
            pass
    
    def test_allowed_ipv6(self):
        try:
            self.session.get("https://ipv6.google.com")
        except AntiSSRFError as e:
            assert "denied by policy" not in str(e)
        except Exception:
            pass


class TestDenyIPv4MappedIPv6Address:

    def setup_method(self):
        infos = socket.getaddrinfo(TEST_DOMAIN, None, socket.AF_INET, socket.SOCK_STREAM)
        self.test_ips = [info[4][0] for info in infos]

        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.allow_plain_text_http = True
        policy.add_denied_addresses(self.test_ips)
        self.session = policy.get_antissrf_session()

    def test_denied_ipv4(self):
        with pytest.raises(AntiSSRFError, match="denied by policy"):
            self.session.get(f"http://{self.test_ips[0]}")

    def test_denied_ipv4_mapped_ipv6(self):
        with pytest.raises(AntiSSRFError, match="denied by policy"):
            self.session.get(f"http://[::ffff:{self.test_ips[0]}]")

    def test_allowed_different_ipv4(self):
        try:
            self.session.get("https://github.com")
        except AntiSSRFError:
            raise
        except Exception:
            pass


class TestDenyIPv6Address:

    def setup_method(self):
        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.allow_plain_text_http = True
        policy.add_denied_addresses(["2001:4860:4860::8888"])
        self.session = policy.get_antissrf_session()

    def test_denied_ipv6(self):
        with pytest.raises(AntiSSRFError, match="denied by policy"):
            self.session.get("http://[2001:4860:4860::8888]")

    def test_allowed_ipv4(self):
        try:
            self.session.get("https://github.com")
        except AntiSSRFError:
            raise
        except Exception:
            pass


class TestBothAllowAndDeny:

    def setup_method(self):
        infos = socket.getaddrinfo(TEST_DOMAIN, None, socket.AF_INET, socket.SOCK_STREAM)
        self.test_ips = [info[4][0] for info in infos]

        policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
        policy.add_denied_addresses(self.test_ips)
        policy.add_allowed_addresses(self.test_ips)
        self.session = policy.get_antissrf_session()

    def test_allow_takes_priority(self):
        """When the same IP is both allowed and denied, allow takes priority."""
        try:
            self.session.get(f"https://{TEST_DOMAIN}")
        except AntiSSRFError:
            raise
        except Exception:
            pass


# ======= Direct IPs - WireServer =======
    
wire_server_ips = [
    # Standard decimal IPv4
    "168.63.129.16",

    # IPv4-mapped-IPv6
    "::FFFF:168.63.129.16",
    "[0:0:0:0:0:FFFF:A83F:8110]"
]

bad_wire_server_ips = [
    # dddd
    "0xA83f8110", # hex
    "2822734096", # dec
    "025017700420", # oct

    # d.ddd
    "0xA8.0x3F8110", # hex
    "168.4161808", # dec
    "0250.017700420", # oct
    "168.017700420", # mixed
    "0250.4161808",

    # d.d.dd
    "0xA8.0x3F.0x8110", # hex
    "168.63.33040", # dec
    "0250.077.0100420", # oct
    "168.077.33040", # mixed
    "0250.0x3f.0100420",

    # d.d.d.d
    "0xA8.0x3F.0x81.0x10", # hex
    "0250.077.0201.020", # oct
    "168.077.0x81.16", # mixed
    "0250.0x3f.0201.020"
]

@pytest.mark.parametrize("ip", wire_server_ips)
def test_wire_server_defaults(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
    assert policy._is_network_connection_allowed([ip]) is False
    
@pytest.mark.parametrize("ip", bad_wire_server_ips)
def test_bad_wire_server_defaults(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
    assert policy._is_network_connection_allowed([ip]) is False


@pytest.mark.parametrize("ip", wire_server_ips)
def test_wire_server_explicit_deny(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
    policy.add_denied_addresses(["168.63.129.16"])
    assert policy._is_network_connection_allowed([ip]) is False

@pytest.mark.parametrize("ip", bad_wire_server_ips)
def test_bad_wire_server_explicit_deny(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
    policy.add_denied_addresses(["168.63.129.16"])
    assert policy._is_network_connection_allowed([ip]) is False

@pytest.mark.parametrize("ip", wire_server_ips)
def test_wire_server_explicit_allow(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
    policy.add_allowed_addresses(["168.63.129.16"])
    assert policy._is_network_connection_allowed([ip]) is True
    
@pytest.mark.parametrize("ip", bad_wire_server_ips)
def test_bad_wire_server_explicit_allow(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
    policy.add_allowed_addresses(["168.63.129.16"])
    assert policy._is_network_connection_allowed([ip]) is False
    
# ======= Direct IPs - IMDS =======

    
imds_ips = [
    # Standard decimal IPv4
    "169.254.169.254",

    # IPv4-mapped-IPv6
    "::FFFF:169.254.169.254",
    "[0:0:0:0:0:FFFF:A9FE:A9FE]"
]

bad_imds_ips = [
    # dddd
    "0xA9FEA9FE", # hex
    "2852039166", # dec
    "025177524776", # oct

    # d.ddd
    "0xA9.0xFEA9FE", # hex
    "169.16689662", # dec
    "0251.077524776", # oct
    "169.077524776", # mixed
    "0251.16689662",

    # d.d.dd
    "0xA9.0xFE.0xA9FE", # hex
    "169.254.43518", # dec
    "0251.0376.0124776", # oct
    "169.0376.43518", # mixed
    "0251.0xfe.0124776",

    # d.d.d.d
    "0xA9.0xFE.0xA9.0xFE", # hex
    "0251.0376.0251.0376", # oct
    "169.0376.0xA9.254", # mixed
    "0251.0xfe.0251.0376"
]

@pytest.mark.parametrize("ip", imds_ips)
def test_imds_defaults(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
    assert policy._is_network_connection_allowed([ip]) is False
    
@pytest.mark.parametrize("ip", bad_imds_ips)
def test_bad_imds_defaults(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
    assert policy._is_network_connection_allowed([ip]) is False

@pytest.mark.parametrize("ip", imds_ips + bad_imds_ips)
def test_imds_explicit_deny(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)
    policy.add_denied_addresses(["169.254.169.254"])
    assert policy._is_network_connection_allowed([ip]) is False

@pytest.mark.parametrize("ip", bad_imds_ips)
def test_bad_imds_explicit_allow(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
    policy.add_allowed_addresses(["169.254.169.254"])
    assert policy._is_network_connection_allowed(ip) is False

@pytest.mark.parametrize("ip", imds_ips)
def test_imds_explicit_allow(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
    policy.add_allowed_addresses(["169.254.169.254"])
    assert policy._is_network_connection_allowed([ip]) is True
    
@pytest.mark.parametrize("ip", bad_imds_ips)
def test_bad_imds_explicit_allow(ip):
    policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_V1)
    policy.add_allowed_addresses(["169.254.169.254"])
    assert policy._is_network_connection_allowed(ip) is False
