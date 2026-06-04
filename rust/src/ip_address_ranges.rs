// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Static IP address ranges for AntiSSRF protection.
//!
//! Each constant in this module represents a category of special-purpose IP
//! addresses defined by IANA / IETF RFCs.  They are used by
//! [`AntiSSRFPolicy`](crate::AntiSSRFPolicy)
//! to build deny/allow lists.
//!
//! # Usage
//!
//! ```rust
//! use antissrf::ip_address_ranges;
//!
//! // Block the Azure Instance Metadata Service endpoint
//! let imds = ip_address_ranges::IMDS;
//! assert!(imds.contains(&"169.254.169.254/32"));
//! ```
//!
//! # Source
//!
//! This file is auto-generated from `config/IPAddressRanges.json`.
//! Do not edit manually; run `scripts/build-ip-ranges-rust.sh` to regenerate.
//!
//! # References
//!
//! - [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
//! - [IANA IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)
//! - [RFC 6890](https://tools.ietf.org/html/rfc6890) — Special-Purpose IP Address Registries

/// Address Management Transitions (AMT) relay addresses.
///
/// Defined in [RFC 7450](https://tools.ietf.org/html/rfc7450).
/// Not typically relevant for SSRF unless your application explicitly uses AMT.
pub const AMT: &[&str] = &["192.52.193.0/24", "2001:3::/32"];

/// AS112 DNS server addresses for reverse DNS of private-use space.
///
/// Defined in [RFC 7535](https://tools.ietf.org/html/rfc7535).
pub const AS112: &[&str] = &[
    "192.31.196.0/24",
    "192.175.48.0/24",
    "2001:4:112::/48",
    "2620:4f:8000::/48",
];

/// Benchmarking addresses for network interconnection devices.
///
/// Defined in [RFC 2544](https://tools.ietf.org/html/rfc2544) and
/// [RFC 5180](https://tools.ietf.org/html/rfc5180).
pub const BENCHMARKING: &[&str] = &["198.18.0.0/15", "2001:2::/48"];

/// Deprecated 6to4 anycast relay addresses.
///
/// Formerly used for 6to4 transition; now deprecated per
/// [RFC 7526](https://tools.ietf.org/html/rfc7526).
pub const DEPRECATED: &[&str] = &["192.88.99.0/24", "2001:10::/28"];

/// DetNet Service Prefixes for Deterministic Networking.
///
/// Defined in [RFC 9023](https://tools.ietf.org/html/rfc9023).
pub const DETSPREFIX: &[&str] = &["2001:30::/28"];

/// Discard-only prefix for IPv6 documentation.
///
/// Defined in [RFC 6666](https://tools.ietf.org/html/rfc6666).
pub const DISCARDONLY: &[&str] = &["100::/64"];

/// Documentation and example addresses.
///
/// These ranges are reserved for use in documentation and examples
/// ([RFC 5737](https://tools.ietf.org/html/rfc5737), [RFC 3849](https://tools.ietf.org/html/rfc3849)).
/// They should never appear in legitimate traffic.
pub const DOCUMENTATION: &[&str] = &[
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "2001:db8::/32",
    "3fff::/20",
];

/// Dummy / test addresses for protocol experiments.
///
/// Defined in [RFC 4727](https://tools.ietf.org/html/rfc4727).
pub const DUMMY: &[&str] = &["192.0.0.8/32", "100:0:0:1::/64"];

/// IETF protocol assignment addresses.
///
/// Used for protocol number assignments and other IETF purposes
/// ([RFC 6890](https://tools.ietf.org/html/rfc6890)).
pub const IETFPROTOCOL: &[&str] = &["192.0.0.0/24", "2001::/23"];

/// Azure Instance Metadata Service (IMDS) endpoint.
///
/// `169.254.169.254` is the link-local address used by Azure VMs to retrieve
/// instance metadata, tokens, and secrets.  **Blocking this is critical**
/// for SSRF prevention in Azure environments.
pub const IMDS: &[&str] = &["169.254.169.254/32"];

/// IPv4/IPv6 translation well-known prefixes.
///
/// Defined in [RFC 6052](https://tools.ietf.org/html/rfc6052) and
/// [RFC 8215](https://tools.ietf.org/html/rfc8215).
pub const IPV4IPV6TRANSLAT: &[&str] = &["64:ff9b::/96", "64:ff9b:1::/48"];

/// IPv4 Service Continuity Prefix for DS-Lite.
///
/// Defined in [RFC 6333](https://tools.ietf.org/html/rfc6333).
pub const IPV4SERVICECONTINUITY: &[&str] = &["192.0.0.0/29"];

/// Limited broadcast address.
///
/// `255.255.255.255` is the IPv4 limited broadcast destination
/// ([RFC 919](https://tools.ietf.org/html/rfc919)).
pub const BROADCAST: &[&str] = &["255.255.255.255/32"];

/// Link-local addresses (auto-configured, non-routable).
///
/// `169.254.0.0/16` (IPv4) and `fe80::/10` (IPv6) are used for local network
/// communication without a DHCP server.  Commonly exploited in SSRF attacks.
pub const LINKLOCAL: &[&str] = &["169.254.0.0/16", "fe80::/10"];

/// Loopback addresses.
///
/// `127.0.0.0/8` (IPv4) and `::1/128` (IPv6) refer to the local host.
/// **Always block in ExternalOnly policies** to prevent connections to
/// local services.
pub const LOOPBACK: &[&str] = &["127.0.0.0/8", "::1/128"];

/// Multicast addresses.
///
/// `224.0.0.0/4` (IPv4) and `ff00::/8` (IPv6) are reserved for multicast
/// traffic ([RFC 1112](https://tools.ietf.org/html/rfc1112), [RFC 4291](https://tools.ietf.org/html/rfc4291)).
pub const MULTICAST: &[&str] = &["224.0.0.0/4", "ff00::/8"];

/// ORCHIDv2 overlay routable cryptographic hash identifiers.
///
/// Defined in [RFC 7343](https://tools.ietf.org/html/rfc7343).
pub const ORCHIDV2: &[&str] = &["2001:20::/28"];

/// Private-use (RFC 1918) addresses.
///
/// `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` are the standard
/// private IPv4 ranges.  These are the **most common targets** for SSRF
/// attacks against internal infrastructure.
pub const PRIVATEUSE: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/// Reserved IPv4 addresses (future use).
///
/// `240.0.0.0/4` is reserved by [RFC 1112](https://tools.ietf.org/html/rfc1112)
/// for future use.
pub const RESERVED: &[&str] = &["240.0.0.0/4"];

/// Carrier-grade NAT (CGNAT) shared address space.
///
/// `100.64.0.0/10` is reserved for ISP-level NAT per
/// [RFC 6598](https://tools.ietf.org/html/rfc6598).  Should be treated as
/// internal for SSRF purposes.
pub const SHAREDADDRESSSPACE: &[&str] = &["100.64.0.0/10"];

/// Deprecated site-local IPv6 addresses.
///
/// `fec0::/10` was deprecated by [RFC 3879](https://tools.ietf.org/html/rfc3879).
pub const SITELOCAL: &[&str] = &["fec0::/10"];

/// 6to4 transition anycast addresses.
///
/// Defined in [RFC 3056](https://tools.ietf.org/html/rfc3056).
pub const SIXTO4: &[&str] = &["2002::/16"];

/// SRv6 Segment Identifier (SID) prefix.
///
/// Defined in [RFC 9602](https://tools.ietf.org/html/rfc9602).
pub const SRV6SID: &[&str] = &["5f00::/16"];

/// Teredo transition tunneling addresses.
///
/// Defined in [RFC 4380](https://tools.ietf.org/html/rfc4380).
pub const TEREDO: &[&str] = &["2001::/32"];

/// Unique local IPv6 unicast addresses (ULA).
///
/// `fc00::/7` is the IPv6 equivalent of RFC 1918 private addresses
/// ([RFC 4193](https://tools.ietf.org/html/rfc4193)).
pub const UNIQUELOCAL: &[&str] = &["fc00::/7"];

/// Unspecified addresses.
///
/// `0.0.0.0/8` (IPv4) and `::/128` (IPv6) represent "this host on this network"
/// ([RFC 1122](https://tools.ietf.org/html/rfc1122)).
pub const UNSPECIFIED: &[&str] = &["0.0.0.0/8", "::/128"];

/// Azure Wire Server endpoint.
///
/// `168.63.129.16` is used by Azure for VM Agent communication and
/// DHCP-like functionality.  **Block in ExternalOnly policies** to prevent
/// SSRF-based metadata exfiltration.
pub const WIRESERVER: &[&str] = &["168.63.129.16/32"];

/// Recommended deny list (version 1) — comprehensive combination of all
/// dangerous special-purpose ranges.
///
/// This list includes:
///
/// - Loopback, link-local, multicast, broadcast
/// - Private-use (RFC 1918) and CGNAT (RFC 6598)
/// - Documentation / example ranges
/// - Transition / deprecated ranges
/// - Azure-specific endpoints ([`IMDS`], [`WIRESERVER`])
///
/// Used by [`PolicyConfigOptions::ExternalOnlyLatest`](crate::PolicyConfigOptions::ExternalOnlyLatest).
/// This is the default comprehensive blocklist for production use.
pub const RECOMMENDEDV1: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "168.63.129.16/32",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "192.175.48.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::1/128",
    "::/128",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "100:0:0:1::/64",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "2620:4f:8000::/48",
    "3fff::/20",
    "5f00::/16",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
];

/// Alias for the current recommended deny list.
///
/// Always points to [`RECOMMENDEDV1`].  When a new version is introduced,
/// this alias will be updated to reference it.
pub const RECOMMENDED_LATEST: &[&str] = RECOMMENDEDV1;
