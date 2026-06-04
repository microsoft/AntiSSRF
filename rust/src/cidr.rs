//! CIDR block parsing and IP range containment for AntiSSRF protection.
//!
//! [`CIDRBlock`] is the foundational primitive for all IP-based policy checks.
//! It normalizes every IPv4 address and network to IPv6-mapped form
//! (`::ffff:<ipv4>`), so a single comparison path handles both families.
//!
//! # IPv6 Normalization
//!
//! When you parse `"10.0.0.0/8"`, the internal representation becomes
//! `"::ffff:10.0.0.0/104"` (prefix + 96).  This means:
//!
//! - `contains("10.1.2.3")` → true
//! - `contains("::ffff:10.1.2.3")` → true (IPv4-mapped IPv6)
//! - `contains("2001:db8::1")` → false
//!
//! See [`CIDRBlock::parse`] and [`CIDRBlock::contains`] for details.

use crate::error::AntiSSRFError;
use ipnetwork::{IpNetwork, Ipv6Network};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// Represents a CIDR block for IP range checking.
///
/// Internally, all networks are normalized to IPv6-mapped form so that
/// a single comparison logic works regardless of address family.
///
/// # Example
///
/// ```rust
/// use antissrf::CIDRBlock;
/// use std::net::IpAddr;
///
/// let block = CIDRBlock::parse("10.0.0.0/8").unwrap();
/// assert!(block.contains("10.1.2.3".parse::<IpAddr>().unwrap()));
/// assert!(!block.contains("11.0.0.1".parse::<IpAddr>().unwrap()));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CIDRBlock {
    /// Normalized IPv6 network (IPv4 CIDRs are mapped to IPv6-mapped form).
    network: Ipv6Network,
    /// Original CIDR string, preserved for Display.
    original: String,
}

impl CIDRBlock {
    /// Parse a CIDR notation string into a `CIDRBlock`.
    ///
    /// Supports both IPv4 (`10.0.0.0/8`) and IPv6 (`fe80::/10`) notation.
    /// IPv4 CIDRs are internally normalized to IPv6-mapped form (`::ffff:10.0.0.0/104`).
    ///
    /// # Errors
    ///
    /// Returns `AntiSSRFError::InvalidCIDR` if the string is not valid CIDR notation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use antissrf::CIDRBlock;
    ///
    /// let block = CIDRBlock::parse("192.168.0.0/16").unwrap();
    /// let block_v6 = CIDRBlock::parse("fe80::/10").unwrap();
    /// ```
    pub fn parse(cidr: &str) -> Result<Self, AntiSSRFError> {
        let original = cidr.to_string();
        let network =
            IpNetwork::from_str(cidr).map_err(|e| AntiSSRFError::InvalidCIDR(e.to_string()))?;

        let ipv6_network = match network {
            IpNetwork::V4(v4) => {
                let mapped = v4.network().to_ipv6_mapped();
                let prefix = v4.prefix() + 96;
                Ipv6Network::new(mapped, prefix)
                    .map_err(|e| AntiSSRFError::InvalidCIDR(e.to_string()))?
            }
            IpNetwork::V6(v6) => v6,
        };

        Ok(Self {
            network: ipv6_network,
            original,
        })
    }

    /// Check whether an IP address is contained within this CIDR block.
    ///
    /// IPv4 addresses are automatically mapped to IPv6-mapped form before checking.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use antissrf::CIDRBlock;
    /// use std::net::IpAddr;
    ///
    /// let block = CIDRBlock::parse("10.0.0.0/8").unwrap();
    /// assert!(block.contains("10.1.2.3".parse::<IpAddr>().unwrap()));
    /// assert!(!block.contains("11.0.0.1".parse::<IpAddr>().unwrap()));
    ///
    /// // IPv4-mapped IPv6 address also matches IPv4 CIDR
    /// assert!(block.contains("::ffff:10.1.2.3".parse::<IpAddr>().unwrap()));
    /// ```
    pub fn contains(&self, addr: IpAddr) -> bool {
        let ipv6_addr = match addr {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        self.network.contains(ipv6_addr)
    }

    /// Check whether another CIDR block is fully contained within this block.
    ///
    /// Returns `true` if `other` represents a subnet of `self`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use antissrf::CIDRBlock;
    ///
    /// let parent = CIDRBlock::parse("10.0.0.0/8").unwrap();
    /// let child = CIDRBlock::parse("10.1.0.0/16").unwrap();
    /// assert!(parent.contains_cidr(&child));
    ///
    /// let non_child = CIDRBlock::parse("11.0.0.0/8").unwrap();
    /// assert!(!parent.contains_cidr(&non_child));
    /// ```
    pub fn contains_cidr(&self, other: &CIDRBlock) -> bool {
        if other.network.prefix() < self.network.prefix() {
            return false;
        }
        self.network.contains(other.network.network())
    }
}

impl fmt::Display for CIDRBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parse_valid_ipv4() {
        let block = CIDRBlock::parse("10.0.0.0/8").unwrap();
        assert_eq!(block.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn parse_valid_ipv6() {
        let block = CIDRBlock::parse("fe80::/10").unwrap();
        assert_eq!(block.to_string(), "fe80::/10");
    }

    #[test]
    fn parse_invalid_cidr() {
        assert!(matches!(
            CIDRBlock::parse("invalid"),
            Err(AntiSSRFError::InvalidCIDR(_))
        ));
    }

    #[test]
    fn parse_invalid_prefix() {
        assert!(matches!(
            CIDRBlock::parse("10.0.0.0/33"),
            Err(AntiSSRFError::InvalidCIDR(_))
        ));
    }

    #[test]
    fn contains_ipv4_in_ipv4_cidr() {
        let block = CIDRBlock::parse("10.0.0.0/8").unwrap();
        assert!(block.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!block.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn contains_ipv4_mapped_in_ipv4_cidr() {
        let block = CIDRBlock::parse("10.0.0.0/8").unwrap();
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x0a01, 0x0203));
        assert!(block.contains(mapped));
    }

    #[test]
    fn contains_ipv6_in_ipv6_cidr() {
        let block = CIDRBlock::parse("fe80::/10").unwrap();
        assert!(block.contains(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
        assert!(!block.contains(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn contains_ipv4_in_ipv6_mapped_cidr() {
        // ::ffff:10.0.0.0/104 is the IPv6-mapped form of 10.0.0.0/8
        let block = CIDRBlock::parse("::ffff:10.0.0.0/104").unwrap();
        assert!(block.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
    }

    #[test]
    fn contains_cidr_ipv4() {
        let parent = CIDRBlock::parse("10.0.0.0/8").unwrap();
        let child = CIDRBlock::parse("10.1.0.0/16").unwrap();
        assert!(parent.contains_cidr(&child));

        let non_child = CIDRBlock::parse("11.0.0.0/8").unwrap();
        assert!(!parent.contains_cidr(&non_child));

        let same_prefix = CIDRBlock::parse("10.0.0.0/8").unwrap();
        assert!(parent.contains_cidr(&same_prefix));
    }

    #[test]
    fn contains_cidr_larger_prefix_fails() {
        let small = CIDRBlock::parse("10.1.0.0/16").unwrap();
        let large = CIDRBlock::parse("10.0.0.0/8").unwrap();
        assert!(!small.contains_cidr(&large));
    }

    #[test]
    fn display_preserves_original() {
        let block = CIDRBlock::parse("192.168.0.0/16").unwrap();
        assert_eq!(format!("{}", block), "192.168.0.0/16");
    }

    #[test]
    fn clone_and_eq() {
        let a = CIDRBlock::parse("10.0.0.0/8").unwrap();
        let b = a.clone();
        assert_eq!(a, b);
    }
}
