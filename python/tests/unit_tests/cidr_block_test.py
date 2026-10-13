# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

from AntiSSRF._ipaddr import IPAddress
from AntiSSRF._cidr_block import CIDRBlock
from ipaddress import AddressValueError, NetmaskValueError


# ===== IPAddress (_ipaddr) tests =====


# IPv4 tests
@pytest.mark.parametrize('addr, expected', [
    ('1.1.1.10', '1.1.1.10'),
])
def test_valid_dotted_quad_ipv4(addr, expected):
	ipaddress = IPAddress(addr)
	assert str(ipaddress) == expected
	assert ipaddress.is_ipv4()


@pytest.mark.parametrize('addr, expected', [
    ('127.0.0.1', '127.0.0.1'),
    ('200.24.5.1', '200.24.5.1'),
    ('255.255.255.255', '255.255.255.255'),
])
def test_ipv4_d_d_d_d_decimal(addr, expected):
    ipaddress = IPAddress(addr)
    assert str(ipaddress) == expected
    assert ipaddress.is_ipv4()


# IPv6 tests
@pytest.mark.parametrize('addr, expected', [
    ('2001:0db8:85a3:0000:0000:8a2e:0370:7334', '2001:db8:85a3::8a2e:370:7334'),
    ('34:5f:7ee:2a:67:8355:0:1', '34:5f:7ee:2a:67:8355:0:1'),
    ('4d:26:2E:0A5:3eE:58:05:41', '4d:26:2e:a5:3ee:58:5:41'),
    
])
def test_ipv6_standard_format(addr, expected):
    ipaddress = IPAddress(addr)
    assert str(ipaddress) == expected
    

@pytest.mark.parametrize('addr', [
    '2001:::85a3',
    '1:1:1:1:1:1:1',
    '1:1:1:1:1:1:1:1:1',
    '4d.ef.2E.rg.3E.58.05.41',
    '1:1:1:1:1:1:1:0x2',
    '1:1:1:1:1:1:1:22222',
])
def test_invalid_ipv6(addr):
    with pytest.raises(AddressValueError):
        IPAddress(addr)
        

@pytest.mark.parametrize('addr, expected', [
    ('34::2a:67:83:0:1', '34::2a:67:83:0:1'),
    ('4d:26:2eeE:0A5:3E:58::', '4d:26:2eee:a5:3e:58::')
])
def test_ipv6_compressed_format(addr, expected):
	# Valid inputs
	ipaddress = IPAddress(addr)
	assert str(ipaddress) == expected
 
 
@pytest.mark.parametrize('addr', [
    '1:1:1:1:1:1:1:1::',
    '1::1:1:1::1',
    '::1::'
])
def test_ipv6_invalid_compressed_format(addr):
    with pytest.raises(AddressValueError):
        IPAddress(addr)


@pytest.mark.parametrize('addr, expected', [
    ('34:5f:7e:28aa:67:83:127.0.0.1', '34:5f:7e:28aa:67:83:7f00:1'),
    ('4d:26:2E::3E:5888:56.76.78.34', '4d:26:2e:0:3e:5888:384c:4e22'),
])
def test_ipv6_mixed(addr, expected):
	# Valid inputs
	ipaddress = IPAddress(addr)
	assert str(ipaddress) == expected


@pytest.mark.parametrize('addr', [
    '1:1:1:1:1:1:1:127.0.0.1',
    '1:1:1:1:1:1:1:0xff.0xff.0xff.0xff',
    '1:1:1:1:1:1:1:0x7f.0.0.1',
    '1:1:1:1:1:127.0.0',
    '1:1:1:1:1:1:00000127.0.0.0',
])
def test_invalid_ipv6_mixed(addr):
	with pytest.raises(AddressValueError):
		IPAddress(addr)


@pytest.mark.parametrize('addr, expected', [
    ('[34:5f:7e:28aa:67:83:127.0.0.1]', '34:5f:7e:28aa:67:83:7f00:1'),
    ('[::127.0.0.1]', '::7f00:1')
])
def test_ipv6_bracket_notation(addr, expected):
	# Valid inputs
	ipaddress = IPAddress(addr)
	assert str(ipaddress) == expected
	
 
@pytest.mark.parametrize('addr', [
    '[127.0.0.1]',
    '[1:1:1:1:1:1:1]',
])
def test_invalid_ipv6_bracket_notation(addr):
    with pytest.raises(AddressValueError):
        IPAddress(addr)



@pytest.mark.parametrize('addr, expected', [
    ('127.0.0.1', '::ffff:127.0.0.1'),
    ('192.168.1.1', '::ffff:192.168.1.1'),
    ('169.254.169.254', "::ffff:169.254.169.254"),
    ('168.63.129.16', "::ffff:168.63.129.16")
])
def test_ipv6_mapped(addr, expected): 
	# IPv6-mapped IPv4 address - compare bytes instead of string format
	ipaddr = IPAddress(addr)
	expected_addr = IPAddress(expected)
	assert int(ipaddr.ipv6_mapped()) == int(expected_addr.get_address())


@pytest.mark.parametrize('addr, expected', [
    ('168.63.129.16', '168.63.129.16'),
])
def test_wireserver_ips(addr, expected):
    ipaddress = IPAddress(addr)
    assert str(ipaddress) == expected
    assert ipaddress.get_type() == "ipv4"


@pytest.mark.parametrize('addr, expected', [
    ('169.254.169.254', '169.254.169.254'),
])
def test_IMDS_ips(addr, expected):
    ipaddress = IPAddress(addr)
    assert str(ipaddress) == expected


# Tests for ipv6-mapped IPv4 addresses matching with their IPv4 counterparts
@pytest.mark.parametrize('expected, addr', [
    ('::ffff:127.0.0.1', '127.0.0.1'),
    ('::ffff:192.168.1.1', '192.168.1.1'),
    ('::ffff:169.254.169.254', '169.254.169.254'),
    ('::ffff:168.63.129.16', '168.63.129.16')
])
def test_ipv6_mapped_matching(expected, addr):
    # Compare bytes instead of string format
    ipaddr = IPAddress(addr)
    expected_addr = IPAddress(expected)
    assert int(ipaddr.ipv6_mapped()) == int(expected_addr.get_address())


# Tests for different IPv4-mapped IPv6 format equivalence
@pytest.mark.parametrize('formats', [
    # 127.0.0.1 in various IPv4-mapped IPv6 formats
    [
        '::ffff:127.0.0.1',           # compressed with dotted-quad
        '::ffff:7f00:1',              # compressed with hex
        '0:0:0:0:0:ffff:127.0.0.1',   # expanded with dotted-quad
        '0:0:0:0:0:ffff:7f00:1',      # expanded with hex
        '[::ffff:127.0.0.1]',         # bracket notation
        '[::ffff:7f00:1]',            # bracket notation hex
    ],
    # 192.168.1.1 in various IPv4-mapped IPv6 formats
    [
        '::ffff:192.168.1.1',
        '::ffff:c0a8:101',
        '0:0:0:0:0:ffff:192.168.1.1',
        '0:0:0:0:0:ffff:c0a8:101',
        '[::ffff:192.168.1.1]',
        '[::ffff:c0a8:101]',
    ],
    # 10.0.0.1 in various IPv4-mapped IPv6 formats
    [
        '::ffff:10.0.0.1',
        '::ffff:a00:1',
        '0:0:0:0:0:ffff:10.0.0.1',
        '0:0:0:0:0:ffff:a00:1',
        '[::ffff:10.0.0.1]',
    ],
    # 169.254.169.254 (IMDS) in various IPv4-mapped IPv6 formats
    [
        '::ffff:169.254.169.254',
        '::ffff:a9fe:a9fe',
        '0:0:0:0:0:ffff:169.254.169.254',
        '0:0:0:0:0:ffff:a9fe:a9fe',
        '[::ffff:169.254.169.254]',
    ],
])
def test_ipv4_mapped_ipv6_format_equivalence(formats):
    """Test that different notations for IPv4-mapped IPv6 addresses are equivalent."""
    addresses = [IPAddress(fmt) for fmt in formats]
    
    # All formats should produce the same integer value
    int_values = [int(addr) for addr in addresses]
    assert all(v == int_values[0] for v in int_values), \
        f"Integer values differ: {int_values}"
    
    # All formats should normalize to the same string representation
    str_values = [str(addr) for addr in addresses]
    assert all(s == str_values[0] for s in str_values), \
        f"String representations differ: {str_values}"


@pytest.mark.parametrize('ipv4, ipv6_formats', [
    ('127.0.0.1', ['::ffff:127.0.0.1', '::ffff:7f00:1', '0:0:0:0:0:ffff:7f00:1']),
    ('192.168.1.1', ['::ffff:192.168.1.1', '::ffff:c0a8:101', '0:0:0:0:0:ffff:c0a8:101']),
    ('10.0.0.1', ['::ffff:10.0.0.1', '::ffff:a00:1']),
    ('168.63.129.16', ['::ffff:168.63.129.16', '::ffff:a83f:8110']),
])
def test_ipv4_mapped_equivalence_with_ipv4(ipv4, ipv6_formats):
    """Test that IPv4-mapped IPv6 formats match the ipv6_mapped() output of their IPv4 counterpart."""
    ipv4_addr = IPAddress(ipv4)
    mapped = ipv4_addr.ipv6_mapped()
    
    for fmt in ipv6_formats:
        ipv6_addr = IPAddress(fmt)
        assert int(ipv6_addr) == int(mapped), \
            f"IPv6 format {fmt} does not match IPv4 {ipv4}'s mapped address"


@pytest.mark.parametrize('addr1, addr2', [
    # Same address in different notations should be equivalent
    ('::ffff:127.0.0.1', '::FFFF:127.0.0.1'),           # case insensitivity
    ('::ffff:c0a8:101', '::FFFF:C0A8:101'),             # case insensitivity hex
    ('0:0:0:0:0:ffff:7f00:1', '0000:0000:0000:0000:0000:ffff:7f00:0001'),  # leading zeros
])
def test_ipv4_mapped_ipv6_case_and_padding_equivalence(addr1, addr2):
    """Test that case differences and zero-padding produce equivalent addresses."""
    ip1 = IPAddress(addr1)
    ip2 = IPAddress(addr2)
    
    assert int(ip1) == int(ip2)
    assert str(ip1) == str(ip2)

# ===== CIDRBlock (_cidr_block) tests =====


@pytest.mark.parametrize("network", [
    None,                   # Null input
    "/8",                   # Missing IP address
    "127.0.0.1/",           # Missing prefix length
    "127.0.0.1/bad",        # Non-numeric prefix length
    "127.0.0.1/8/8",        # Extra slash
    "",                     # Empty string
    'invalid/24',           # Invalid IP address
    
    '300.168.0.0/24',       # Invalid IPv4 address
    '127.0.0.1/33',         # Invalid IPv4 prefix length
    '127.0.0.1/0x1',        # Non-numeric IPv4 prefix length
    
    '[2001:0db8::]/129',    # Invalid IPv6 prefix length
    '1::/234',              # Invalid IPv6 prefix length
    '1::/0x3',              # Non-numeric IPv6 prefix length

    '192.168.1.0/24/16',    # Too many slashes
    '10.0.0.0/8/',          # Trailing slash
    '2001:db8::/32/64',     # Too many slashes (IPv6)
    '256.256.256.256/24',   # Out-of-range IPv4
    '192.168.1.300/24',     # Out-of-range IPv4 octet
    '999.999.999.999',      # Invalid IP, no prefix
    'gggg::1/64',           # Invalid IPv6
    '192.168.1.0/24.5',     # Non-integer prefix
    '192.168.1.0/+24',      # Signed prefix
    '192.168.1.0/-1',       # Negative prefix
    '192.168.1.0/255',      # Out-of-range IPv4 prefix
    '2001:db8::/-5',        # Negative IPv6 prefix
])
def test_bad_inputs(network):
    with pytest.raises(NetmaskValueError):
        CIDRBlock(network)
    

@pytest.mark.parametrize("network, expected_net, expected_prefix", [
    # IPv4 no prefix
    ('127.0.0.1', '::ffff:127.0.0.1', '128'),
    # IPv4 with prefix
    ('192.168.0.0/24', '::ffff:192.168.0.0', '120'),
    ('127.0.0.1/31', '::ffff:127.0.0.0', '127'),
])
def test_ipv4_network(network, expected_net, expected_prefix):
    # Compare network address bytes instead of string format
    net = CIDRBlock(network)
    expected_addr = IPAddress(expected_net)
    assert int(net.get_network().network_address) == int(expected_addr.get_address())
    assert str(net.get_prefix()) == expected_prefix


@pytest.mark.parametrize("network, expected_net, expected_prefix", [
    # IPv6 no prefix
    ('[2001:0db8::]', '2001:db8::/128', '128'),
    ('45:56f:3e:ad:7e:23:1:05', '45:56f:3e:ad:7e:23:1:5/128', '128'),
    ('45:56:3e:aaad::1:05', '45:56:3e:aaad::1:5/128', '128'),
    ('[::1]', '::1/128', '128'),
    # IPv6 with prefix
    ('[2001:0db8::]/32', '2001:db8::/32', '32'),
    ('45:56f:3e:ad:7e:23:1:05/45', '45:56f:38::/45', '45'),
    ('45:56:3e:aaad::1:05/1', '::/1', '1'),
    ('[::1]/128', '::1/128', '128'),
    ('[::]/0', '::/0', '0')
])
def test_ipv6_network_prefix(network, expected_net, expected_prefix):
    net = CIDRBlock(network)
    assert str(net) == expected_net
    assert str(net.get_prefix()) == expected_prefix
    

@pytest.mark.parametrize("network, addr_in, addr_not", [
    # plain IPv4 cases
    ('127.0.0.1', '127.0.0.1', '127.0.0.2'),
    ('192.168.1.0/24', '192.168.1.5', '192.168.2.5'),
    # plain IPv6 case
    ('[2001:db8::]/32', '2001:db8::1', '2002::1'),

    # Mixed: IPv6 network contains IPv4-mapped address
    ('::ffff:168.63.129.0/120', '168.63.129.16', '2001::1'),
    ('::ffff:169.254.169.0/120', '169.254.169.254', '169.254.170.1'),

    # Mixed: IPv4-style network (will be represented as IPv6-mapped by CIDRBlock)
    # should contain IPv6-mapped variants and exclude others
    ('192.168.1.0/24', '::ffff:192.168.1.5', '::1'),
    ('169.254.169.0/24', '::ffff:169.254.169.254', '::1'),
])
def test_containment_ipv4_and_ipv6(network, addr_in, addr_not):
    net = CIDRBlock(network)
    assert IPAddress(addr_in).ipv6_mapped() in net.get_network()
    assert IPAddress(addr_not).ipv6_mapped() not in net.get_network()
    

@pytest.mark.parametrize("network", [
    # WireServer standard decimal format
    "168.63.129.16",
])
def test_wireserver_variants(network):
    # Compare network address bytes instead of string format
    net = CIDRBlock(network)
    expected_addr = IPAddress("::ffff:168.63.129.16")
    assert int(net.get_network().network_address) == int(expected_addr.get_address())
    assert net.get_prefix() == 128


@pytest.mark.parametrize("network", [
    # IMDS standard decimal format
    "169.254.169.254",
])
def test_imds_variants(network):
    # Compare network address bytes instead of string format
    net = CIDRBlock(network)
    expected_addr = IPAddress("::ffff:169.254.169.254")
    assert int(net.get_network().network_address) == int(expected_addr.get_address())
    assert net.get_prefix() == 128
