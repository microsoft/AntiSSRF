// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "assert";

import { CIDRBlock } from "../../src/Helpers/CIDRBlock";
import { AntiSSRFError } from "../../src";

describe("CIRRBlock Testss", () => {
    it("bad inputs", () => {
        // Parse - null input
            assert.throws(() => CIDRBlock._parseCIDR(null!), (err: AntiSSRFError) => err.message === "Null argument");

            // Parse - too many /
            assert.throws(() => CIDRBlock._parseCIDR("192.168.1.0/24/16"), (err: AntiSSRFError) => err.message === "Invalid CIDR format");
            assert.throws(() => CIDRBlock._parseCIDR("10.0.0.0/8/"), (err: AntiSSRFError) => err.message === "Invalid CIDR format");
            assert.throws(() => CIDRBlock._parseCIDR("2001:db8::/32/64"), (err: AntiSSRFError) => err.message === "Invalid CIDR format");

            // Parse - invalid IP address
            assert.throws(() => CIDRBlock._parseCIDR("256.256.256.256/24"), (err: AntiSSRFError) => err.message === "Invalid IP address");
            assert.throws(() => CIDRBlock._parseCIDR("192.168.1.300/24"), (err: AntiSSRFError) => err.message === "Invalid IP address");
            assert.throws(() => CIDRBlock._parseCIDR("not-an-ip/24"), (err: AntiSSRFError) => err.message === "Invalid IP address");
            assert.throws(() => CIDRBlock._parseCIDR("999.999.999.999"), (err: AntiSSRFError) => err.message === "Invalid IP address");
            assert.throws(() => CIDRBlock._parseCIDR("gggg::1/64"), (err: AntiSSRFError) => err.message === "Invalid IP address");

            // Parse - invalid prefix format
            assert.throws(() => CIDRBlock._parseCIDR("192.168.1.0/abc"), (err: AntiSSRFError) => err.message === "Invalid prefix format");
            assert.throws(() => CIDRBlock._parseCIDR("192.168.1.0/24.5"), (err: AntiSSRFError) => err.message === "Invalid prefix format");
            assert.throws(() => CIDRBlock._parseCIDR("192.168.1.0/"), (err: AntiSSRFError) => err.message === "Invalid prefix format");
            assert.throws(() => CIDRBlock._parseCIDR("/24"), (err: AntiSSRFError) => err.message === "Invalid prefix format");
            assert.throws(() => CIDRBlock._parseCIDR("192.168.1.0/+24"), (err: AntiSSRFError) => err.message === "Invalid prefix format");
            assert.throws(() => CIDRBlock._parseCIDR("127.0.0.0/024"), (err: AntiSSRFError) => err.message === "Invalid prefix format");

            // Parse - invalid prefix length
            assert.throws(() => CIDRBlock._parseCIDR("192.168.1.0/33"), (err: AntiSSRFError) => err.message === "Invalid prefix length");
            assert.throws(() => CIDRBlock._parseCIDR("192.168.1.0/-1"), (err: AntiSSRFError) => err.message === "Invalid prefix length");
            assert.throws(() => CIDRBlock._parseCIDR("192.168.1.0/255"), (err: AntiSSRFError) => err.message === "Invalid prefix length");
            assert.throws(() => CIDRBlock._parseCIDR("2001:db8::/129"), (err: AntiSSRFError) => err.message === "Invalid prefix length");
            assert.throws(() => CIDRBlock._parseCIDR("2001:db8::/-5"), (err: AntiSSRFError) => err.message === "Invalid prefix length");
    });
});
//     public class CIDRBlockTests
//     {


//         [Fact]
//         public void Contains_IPv4Address_ReturnsExpectedResult()
//         {
//             // Standard decimal format
//             var block1 = CIDRBlock.Parse("192.168.1.0/24");
//             Assert.True(block1.Contains(IPAddress.Parse("192.168.1.1")));
//             Assert.True(block1.Contains(IPAddress.Parse("192.168.1.255")));
//             Assert.False(block1.Contains(IPAddress.Parse("192.168.2.1")));

//             // Octal format
//             var block2 = CIDRBlock.Parse("0300.0250.001.000/24");
//             Assert.True(block2.Contains(IPAddress.Parse("192.168.1.1")));
//             Assert.False(block2.Contains(IPAddress.Parse("192.168.2.1")));

//             // Hexadecimal format
//             var block3 = CIDRBlock.Parse("0xC0.0xA8.0x1.0x0/24");
//             Assert.True(block3.Contains(IPAddress.Parse("192.168.1.1")));
//             Assert.False(block3.Contains(IPAddress.Parse("192.168.2.1")));

//             // Mixed formats
//             var block4 = CIDRBlock.Parse("192.0250.1.0x0/24");
//             Assert.True(block4.Contains(IPAddress.Parse("192.168.1.1")));
//             Assert.False(block4.Contains(IPAddress.Parse("192.168.2.1")));

//             // 3 octets format
//             var block5 = CIDRBlock.Parse("192.168.256/24");
//             Assert.True(block5.Contains(IPAddress.Parse("192.168.1.1")));
//             Assert.False(block5.Contains(IPAddress.Parse("192.168.2.1")));

//             // 2 octets format
//             var block6 = CIDRBlock.Parse("192.11010304/24");
//             Assert.True(block6.Contains(IPAddress.Parse("192.168.1.1")));
//             Assert.False(block6.Contains(IPAddress.Parse("192.168.2.1")));

//             // Single number format
//             var block7 = CIDRBlock.Parse("3232235776/24");
//             Assert.True(block7.Contains(IPAddress.Parse("192.168.1.1")));
//             Assert.False(block7.Contains(IPAddress.Parse("192.168.2.1")));

//             // Test without prefix length
//             var block9 = CIDRBlock.Parse("0xC0A80101");
//             Assert.True(block9.Contains(IPAddress.Parse("192.168.1.1")));
//             Assert.False(block9.Contains(IPAddress.Parse("192.168.1.2")));

//             var block10 = CIDRBlock.Parse("192.168.257");
//             Assert.True(block10.Contains(IPAddress.Parse("192.168.1.1")));
//             Assert.False(block10.Contains(IPAddress.Parse("192.168.1.2")));
//         }

//         [Fact]
//         public void Contains_IPv6Address_ReturnsExpectedResult()
//         {
//             // Standard full format
//             var block1 = CIDRBlock.Parse("2001:0db8:0000:0000:0000:0000:0000:0000/32");
//             Assert.True(block1.Contains(IPAddress.Parse("2001:db8::1")));
//             Assert.True(block1.Contains(IPAddress.Parse("2001:db8:ffff::1")));
//             Assert.False(block1.Contains(IPAddress.Parse("2001:db9::1")));

//             // Leading compression
//             var block3 = CIDRBlock.Parse("::1/128");
//             Assert.True(block3.Contains(IPAddress.Parse("::1")));
//             Assert.False(block3.Contains(IPAddress.Parse("::2")));

//             // Trailing compression
//             var block4 = CIDRBlock.Parse("2001:db8:1::/48");
//             Assert.True(block4.Contains(IPAddress.Parse("2001:db8:1::1")));
//             Assert.True(block4.Contains(IPAddress.Parse("2001:db8:1:ffff::1")));
//             Assert.False(block4.Contains(IPAddress.Parse("2001:db8:2::1")));

//             // Middle compression
//             var block5 = CIDRBlock.Parse("2001:db8::1:0:0:1/64");
//             Assert.True(block5.Contains(IPAddress.Parse("2001:db8::1")));
//             Assert.True(block5.Contains(IPAddress.Parse("2001:db8:0:0:ffff::")));
//             Assert.False(block5.Contains(IPAddress.Parse("2001:db9::1")));

//             // ::<ipv4> format
//             var block6 = CIDRBlock.Parse("::ffff:192.168.1.0/120");
//             Assert.True(block6.Contains(IPAddress.Parse("::ffff:192.168.1.1")));
//             Assert.True(block6.Contains(IPAddress.Parse("::ffff:192.168.1.255")));
//             Assert.False(block6.Contains(IPAddress.Parse("::ffff:192.168.2.1")));

//             // Mixed case hex digits
//             var block8 = CIDRBlock.Parse("2001:DB8:aBCD:Ef01::/64");
//             Assert.True(block8.Contains(IPAddress.Parse("2001:db8:abcd:ef01::1")));
//             Assert.False(block8.Contains(IPAddress.Parse("2001:db8:abcd:ef02::1")));

//             // Test without prefix length (should default to /128)
//             var block9 = CIDRBlock.Parse("2001:db8::1");
//             Assert.True(block9.Contains(IPAddress.Parse("2001:db8::1")));
//             Assert.False(block9.Contains(IPAddress.Parse("2001:db8::2")));

//             var block10 = CIDRBlock.Parse("::1");
//             Assert.True(block10.Contains(IPAddress.Parse("::1")));
//             Assert.False(block10.Contains(IPAddress.Parse("::2")));

//             var block11 = CIDRBlock.Parse("::ffff:192.168.1.1");
//             Assert.True(block11.Contains(IPAddress.Parse("::ffff:192.168.1.1")));
//             Assert.False(block11.Contains(IPAddress.Parse("::ffff:192.168.1.2")));
//         }

//         [Fact]
//         public void Contains_IPv6AddressWithScope_ScopeIsStripped()
//         {
//             // Scoped addresses (e.g. fe80::1%eth0) contain a zone ID that must be
//             // stripped before prefix matching; the scope does not affect containment.
//             var block = CIDRBlock.Parse("fe80::/10");

// #if NET5_0_OR_GREATER
//             Assert.True(block.Contains(IPAddress.Parse("fe80::1%eth0")));
//             Assert.True(block.Contains(IPAddress.Parse("fe80::1%1")));
//             Assert.False(block.Contains(IPAddress.Parse("2001:db8::1%eth0")));
// #else
//             Assert.Throws<FormatException>(() => block.Contains(IPAddress.Parse("fe80::1%eth0")));
// #endif
//         }

//         [Fact]
//         public void Contains_IPAddress_NetworkBoundaryAddress_ReturnsTrue()
//         {
//             var block = CIDRBlock.Parse("192.168.1.0/24");

//             Assert.True(block.Contains(IPAddress.Parse("192.168.1.0")));
//             Assert.True(block.Contains(IPAddress.Parse("192.168.1.255")));
//         }

//         [Fact]
//         public void Contains_CIDRBlock_NoOverlap_ReturnsFalse()
//         {
//             var block1 = CIDRBlock.Parse("192.168.1.0/24");
//             var block2 = CIDRBlock.Parse("192.168.2.0/24");
//             var block3 = CIDRBlock.Parse("192.168.3.128/26");

//             Assert.False(block1.Contains(block2));
//             Assert.False(block2.Contains(block1));
//             Assert.False(block1.Contains(block3));
//             Assert.False(block3.Contains(block1));
//             Assert.False(block2.Contains(block3));
//             Assert.False(block3.Contains(block2));
//         }

//         [Fact]
//         public void Contains_CIDRBlock_PartialOverlap_ReturnsFalse()
//         {
//             var block1 = CIDRBlock.Parse("192.168.1.0/28");
//             var block2 = CIDRBlock.Parse("192.168.1.32/28");
//             var block3 = CIDRBlock.Parse("192.168.1.48/28");

//             Assert.False(block1.Contains(block2));
//             Assert.False(block2.Contains(block1));
//             Assert.False(block1.Contains(block3));
//             Assert.False(block3.Contains(block1));
//             Assert.False(block2.Contains(block3));
//             Assert.False(block3.Contains(block2));
//         }

//         [Fact]
//         public void Contains_CIDRBlock_NestedContainment_ReturnsExpectedResult()
//         {
//             var block1 = CIDRBlock.Parse("192.168.1.0/24");
//             var block2 = CIDRBlock.Parse("192.168.1.128/25");
//             var block3 = CIDRBlock.Parse("192.168.1.200");

//             // block1 contains block2 and block3
//             Assert.True(block1.Contains(block2));
//             Assert.True(block1.Contains(block3));

//             // block2 contains block3
//             Assert.True(block2.Contains(block3));

//             // Each block contains itself
//             Assert.True(block1.Contains(block1));
//             Assert.True(block2.Contains(block2));
//             Assert.True(block3.Contains(block3));

//             // Narrower blocks cannot contain broader blocks
//             Assert.False(block2.Contains(block1));
//             Assert.False(block3.Contains(block1));
//             Assert.False(block3.Contains(block2));
//         }

//         [Fact]
//         public void ToCIDR_ReturnsExpectedString()
//         {
//             // Standard IPv4 with prefix
//             Assert.Equal("192.168.1.0/24", CIDRBlock.Parse("192.168.1.0/24").ToCIDR());

//             // IPv4 host address (no prefix given defaults to /32)
//             Assert.Equal("10.0.0.1/32", CIDRBlock.Parse("10.0.0.1").ToCIDR());

//             // IPv4 with /0
//             Assert.Equal("0.0.0.0/0", CIDRBlock.Parse("0.0.0.0/0").ToCIDR());

//             // IPv6 with prefix
//             Assert.Equal("2001:db8::/32", CIDRBlock.Parse("2001:db8::/32").ToCIDR());

//             // IPv6 host address (no prefix given defaults to /128)
//             Assert.Equal("::1/128", CIDRBlock.Parse("::1").ToCIDR());

//             // IPv4-mapped IPv6 input round-trips back to IPv4 notation
//             Assert.Equal("192.168.1.0/24", CIDRBlock.Parse("::ffff:192.168.1.0/120").ToCIDR());

//             // Scoped IPv6 address - scope is stripped in output
// #if NET5_0_OR_GREATER
//             Assert.Equal("fe80::1/128", CIDRBlock.Parse("fe80::1%eth0").ToCIDR());
// #else
//             Assert.Throws<FormatException>(() => CIDRBlock.Parse("fe80::1%eth0").ToCIDR());
// #endif
//         }
//     }
// }