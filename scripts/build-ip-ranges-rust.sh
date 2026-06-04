#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Script to build src/ip_address_ranges.rs from config/IPAddressRanges.json
# Generates a Rust module with static constants

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JSON_FILE="$SCRIPT_DIR/../config/IPAddressRanges.json"
RS_FILE="$SCRIPT_DIR/../rust/src/ip_address_ranges.rs"

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed."
    exit 1
fi

if [[ ! -f "$JSON_FILE" ]]; then
    echo "Error: IPAddressRanges.json not found in $SCRIPT_DIR/../config/"
    exit 1
fi

# Generate module header
cat > "$RS_FILE" << 'EOF'
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

EOF

# Helper: output doc comment lines for a constant
doc_comment() {
    local key=$1
    case $key in
        amt)
            echo "/// Address Management Transitions (AMT) relay addresses."
            echo "///"
            echo "/// Defined in [RFC 7450](https://tools.ietf.org/html/rfc7450)."
            echo "/// Not typically relevant for SSRF unless your application explicitly uses AMT."
            ;;
        as112)
            echo "/// AS112 DNS server addresses for reverse DNS of private-use space."
            echo "///"
            echo "/// Defined in [RFC 7535](https://tools.ietf.org/html/rfc7535)."
            ;;
        benchmarking)
            echo "/// Benchmarking addresses for network interconnection devices."
            echo "///"
            echo "/// Defined in [RFC 2544](https://tools.ietf.org/html/rfc2544) and"
            echo "/// [RFC 5180](https://tools.ietf.org/html/rfc5180)."
            ;;
        deprecated)
            echo "/// Deprecated 6to4 anycast relay addresses."
            echo "///"
            echo "/// Formerly used for 6to4 transition; now deprecated per"
            echo "/// [RFC 7526](https://tools.ietf.org/html/rfc7526)."
            ;;
        detsPrefix)
            echo "/// DetNet Service Prefixes for Deterministic Networking."
            echo "///"
            echo "/// Defined in [RFC 9023](https://tools.ietf.org/html/rfc9023)."
            ;;
        discardOnly)
            echo "/// Discard-only prefix for IPv6 documentation."
            echo "///"
            echo "/// Defined in [RFC 6666](https://tools.ietf.org/html/rfc6666)."
            ;;
        documentation)
            echo "/// Documentation and example addresses."
            echo "///"
            echo "/// These ranges are reserved for use in documentation and examples"
            echo "/// ([RFC 5737](https://tools.ietf.org/html/rfc5737), [RFC 3849](https://tools.ietf.org/html/rfc3849))."
            echo "/// They should never appear in legitimate traffic."
            ;;
        dummy)
            echo "/// Dummy / test addresses for protocol experiments."
            echo "///"
            echo "/// Defined in [RFC 4727](https://tools.ietf.org/html/rfc4727)."
            ;;
        ietfProtocol)
            echo "/// IETF protocol assignment addresses."
            echo "///"
            echo "/// Used for protocol number assignments and other IETF purposes"
            echo "/// ([RFC 6890](https://tools.ietf.org/html/rfc6890))."
            ;;
        imds)
            echo "/// Azure Instance Metadata Service (IMDS) endpoint."
            echo "///"
            echo "/// \`169.254.169.254\` is the link-local address used by Azure VMs to retrieve"
            echo "/// instance metadata, tokens, and secrets.  **Blocking this is critical**"
            echo "/// for SSRF prevention in Azure environments."
            ;;
        ipv4Ipv6Translat)
            echo "/// IPv4/IPv6 translation well-known prefixes."
            echo "///"
            echo "/// Defined in [RFC 6052](https://tools.ietf.org/html/rfc6052) and"
            echo "/// [RFC 8215](https://tools.ietf.org/html/rfc8215)."
            ;;
        ipv4ServiceContinuity)
            echo "/// IPv4 Service Continuity Prefix for DS-Lite."
            echo "///"
            echo "/// Defined in [RFC 6333](https://tools.ietf.org/html/rfc6333)."
            ;;
        broadcast)
            echo "/// Limited broadcast address."
            echo "///"
            echo "/// \`255.255.255.255\` is the IPv4 limited broadcast destination"
            echo "/// ([RFC 919](https://tools.ietf.org/html/rfc919))."
            ;;
        linkLocal)
            echo "/// Link-local addresses (auto-configured, non-routable)."
            echo "///"
            echo "/// \`169.254.0.0/16\` (IPv4) and \`fe80::/10\` (IPv6) are used for local network"
            echo "/// communication without a DHCP server.  Commonly exploited in SSRF attacks."
            ;;
        loopback)
            echo "/// Loopback addresses."
            echo "///"
            echo "/// \`127.0.0.0/8\` (IPv4) and \`::1/128\` (IPv6) refer to the local host."
            echo "/// **Always block in ExternalOnly policies** to prevent connections to"
            echo "/// local services."
            ;;
        multicast)
            echo "/// Multicast addresses."
            echo "///"
            echo "/// \`224.0.0.0/4\` (IPv4) and \`ff00::/8\` (IPv6) are reserved for multicast"
            echo "/// traffic ([RFC 1112](https://tools.ietf.org/html/rfc1112), [RFC 4291](https://tools.ietf.org/html/rfc4291))."
            ;;
        orchidv2)
            echo "/// ORCHIDv2 overlay routable cryptographic hash identifiers."
            echo "///"
            echo "/// Defined in [RFC 7343](https://tools.ietf.org/html/rfc7343)."
            ;;
        privateUse)
            echo "/// Private-use (RFC 1918) addresses."
            echo "///"
            echo "/// \`10.0.0.0/8\`, \`172.16.0.0/12\`, and \`192.168.0.0/16\` are the standard"
            echo "/// private IPv4 ranges.  These are the **most common targets** for SSRF"
            echo "/// attacks against internal infrastructure."
            ;;
        reserved)
            echo "/// Reserved IPv4 addresses (future use)."
            echo "///"
            echo "/// \`240.0.0.0/4\` is reserved by [RFC 1112](https://tools.ietf.org/html/rfc1112)"
            echo "/// for future use."
            ;;
        sharedAddressSpace)
            echo "/// Carrier-grade NAT (CGNAT) shared address space."
            echo "///"
            echo "/// \`100.64.0.0/10\` is reserved for ISP-level NAT per"
            echo "/// [RFC 6598](https://tools.ietf.org/html/rfc6598).  Should be treated as"
            echo "/// internal for SSRF purposes."
            ;;
        siteLocal)
            echo "/// Deprecated site-local IPv6 addresses."
            echo "///"
            echo "/// \`fec0::/10\` was deprecated by [RFC 3879](https://tools.ietf.org/html/rfc3879)."
            ;;
        sixto4)
            echo "/// 6to4 transition anycast addresses."
            echo "///"
            echo "/// Defined in [RFC 3056](https://tools.ietf.org/html/rfc3056)."
            ;;
        srv6Sid)
            echo "/// SRv6 Segment Identifier (SID) prefix."
            echo "///"
            echo "/// Defined in [RFC 9602](https://tools.ietf.org/html/rfc9602)."
            ;;
        teredo)
            echo "/// Teredo transition tunneling addresses."
            echo "///"
            echo "/// Defined in [RFC 4380](https://tools.ietf.org/html/rfc4380)."
            ;;
        uniqueLocal)
            echo "/// Unique local IPv6 unicast addresses (ULA)."
            echo "///"
            echo "/// \`fc00::/7\` is the IPv6 equivalent of RFC 1918 private addresses"
            echo "/// ([RFC 4193](https://tools.ietf.org/html/rfc4193))."
            ;;
        unspecified)
            echo "/// Unspecified addresses."
            echo "///"
            echo "/// \`0.0.0.0/8\` (IPv4) and \`::/128\` (IPv6) represent \"this host on this network\""
            echo "/// ([RFC 1122](https://tools.ietf.org/html/rfc1122))."
            ;;
        wireserver)
            echo "/// Azure Wire Server endpoint."
            echo "///"
            echo "/// \`168.63.129.16\` is used by Azure for VM Agent communication and"
            echo "/// DHCP-like functionality.  **Block in ExternalOnly policies** to prevent"
            echo "/// SSRF-based metadata exfiltration."
            ;;
        recommendedV1)
            echo "/// Recommended deny list (version 1) — comprehensive combination of all"
            echo "/// dangerous special-purpose ranges."
            echo "///"
            echo "/// This list includes:"
            echo "///"
            echo "/// - Loopback, link-local, multicast, broadcast"
            echo "/// - Private-use (RFC 1918) and CGNAT (RFC 6598)"
            echo "/// - Documentation / example ranges"
            echo "/// - Transition / deprecated ranges"
            echo "/// - Azure-specific endpoints ([\`IMDS\`], [\`WIRESERVER\`])"
            echo "///"
            echo "/// Used by [\`PolicyConfigOptions::ExternalOnlyLatest\`](crate::PolicyConfigOptions::ExternalOnlyLatest)."
            echo "/// This is the default comprehensive blocklist for production use."
            ;;
    esac
}

# Helper: format a CIDR array as a Rust const
# Arguments: constant_name, UPPER_CASE_NAME
format_const() {
    local key=$1
    local uc_key=$2
    local count

    count=$(jq -r ".\"$key\".cidr | length" "$JSON_FILE")

    # Output doc comment
    doc_comment "$key"

    if [[ "$count" -le 3 ]]; then
        # Single line — join with ", "
        local values
        values=$(jq -r ".\"$key\".cidr | join(\"\\\", \\\"\")" "$JSON_FILE")
        echo "pub const $uc_key: &[&str] = &[\"$values\"];"
    else
        # Multi-line — one CIDR per line with trailing comma
        echo "pub const $uc_key: &[&str] = &["
        jq -r ".\"$key\".cidr[] | \"    \\\"\" + . + \"\\\",\"" "$JSON_FILE"
        echo "];"
    fi
    echo ""
}

# Process each standalone variable in JSON order
for key in $(jq -r 'to_entries | map(select(.key != "_sources" and .value.standaloneVariable == true)) | .[].key' "$JSON_FILE"); do
    uc_key=$(echo "$key" | tr '[:lower:]' '[:upper:]')
    format_const "$key" "$uc_key" >> "$RS_FILE"
done

# Add recommendedV1 (also standaloneVariable=true but handled above)
# Then RECOMMENDED_LATEST alias
{
    echo "/// Alias for the current recommended deny list."
    echo "///"
    echo "/// Always points to [\`RECOMMENDEDV1\`].  When a new version is introduced,"
    echo "/// this alias will be updated to reference it."
    echo "pub const RECOMMENDED_LATEST: &[&str] = RECOMMENDEDV1;"
} >> "$RS_FILE"

echo "Successfully generated $RS_FILE"
