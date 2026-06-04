// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! URL and domain validation utilities for AntiSSRF protection.
//!
//! [`URIValidator`] provides static methods for checking whether a URL belongs
//! to a trusted domain.  It is used independently of [`AntiSSRFPolicy`](crate::AntiSSRFPolicy)
//! for lightweight, non-network validation — for example, whitelisting a redirect
//! target or verifying that a user-supplied URL points to an approved service.
//!
//! # Supported Protocols
//!
//! | Method | Allowed protocols |
//! |--------|-------------------|
//! | [`in_domain`](URIValidator::in_domain) | `http:`, `https:`, `ws:`, `wss:` |
//! | [`in_azure_key_vault_domain`](URIValidator::in_azure_key_vault_domain) | `http:`, `https:` |
//! | [`in_azure_storage_domain`](URIValidator::in_azure_storage_domain) | `http:`, `https:` |
//!
//! # Subdomain Matching
//!
//! All three methods support subdomain matching.  For example,
//! `"https://api.trusted.com"` matches `"trusted.com"`.
//!
//! # Punycode Normalisation
//!
//! Internationalised domain names (IDN) are normalised to ASCII (punycode) form
//! before comparison.  Both the URL hostname and the trusted domain list are
//! converted, so `"münchen.example"` matches `"xn--mnchen-3ya.example"`.

use url::Url;

/// Static utility for validating URLs against trusted domains.
///
/// All methods are stateless; you do not need to instantiate this struct.
pub struct URIValidator;

impl URIValidator {
    const DOMAIN_PROTOCOLS: &[&str] = &["http:", "https:", "ws:", "wss:"];
    const AZURE_SDK_PROTOCOLS: &[&str] = &["http:", "https:"];

    /// Verifies whether a URL's hostname is within any of the provided domains.
    ///
    /// Supports subdomain matching and punycode normalisation.  Malformed URLs
    /// or unsupported protocols return `false`.
    ///
    /// # Arguments
    ///
    /// * `url` — The URL to verify.  Must include a scheme and hostname.
    /// * `trusted_domains` — One or more domains to check against.  Each domain
    ///   may be dotted (`.trusted.com`) or undotted (`trusted.com`).
    ///
    /// # Returns
    ///
    /// `true` if the URL's hostname is in any provided domain, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use antissrf::URIValidator;
    ///
    /// // Subdomain match
    /// assert!(URIValidator::in_domain("https://api.trusted.com", &["trusted.com"]));
    ///
    /// // Exact match
    /// assert!(URIValidator::in_domain("https://trusted.com", &["trusted.com"]));
    ///
    /// // No match
    /// assert!(!URIValidator::in_domain("https://evil.com", &["trusted.com"]));
    ///
    /// // Dotted domain syntax also works
    /// assert!(URIValidator::in_domain("https://api.trusted.com", &[".trusted.com"]));
    ///
    /// // Malformed URL returns false
    /// assert!(!URIValidator::in_domain("not-a-url", &["trusted.com"]));
    /// ```
    pub fn in_domain(url: &str, trusted_domains: &[&str]) -> bool {
        let hostname = match Self::get_valid_hostname(url, Self::DOMAIN_PROTOCOLS) {
            Some(h) => h,
            None => return false,
        };

        if trusted_domains.is_empty() {
            return false;
        }

        for domain in trusted_domains {
            let ascii_domain = match Self::domain_to_ascii(domain) {
                Some(d) => d,
                None => continue,
            };

            if Self::hostname_in_single_domain(&hostname, &ascii_domain) {
                return true;
            }
        }

        false
    }

    /// Verifies whether a URL is in an Azure Key Vault domain.
    ///
    /// Checks against the well-known Key Vault endpoints listed in
    /// [`AZURE_KEY_VAULT_DOMAINS`](crate::domains::AZURE_KEY_VAULT_DOMAINS).
    /// Rejects hostnames containing `--`, which violates Azure naming restrictions.
    ///
    /// # Arguments
    ///
    /// * `url` — The URL to verify.  Must use `http:` or `https:`.
    ///
    /// # Returns
    ///
    /// `true` if the URL is in any Azure Key Vault domain, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use antissrf::URIValidator;
    ///
    /// assert!(URIValidator::in_azure_key_vault_domain("https://myvault.vault.azure.net"));
    /// assert!(!URIValidator::in_azure_key_vault_domain("https://my--vault.vault.azure.net"));
    /// assert!(!URIValidator::in_azure_key_vault_domain("ws://myvault.vault.azure.net"));
    /// ```
    pub fn in_azure_key_vault_domain(url: &str) -> bool {
        let hostname = match Self::get_valid_hostname(url, Self::AZURE_SDK_PROTOCOLS) {
            Some(h) => h,
            None => return false,
        };

        if hostname.contains("--") {
            return false;
        }

        for domain in crate::domains::AZURE_KEY_VAULT_DOMAINS {
            if Self::hostname_in_single_domain(&hostname, domain) {
                return true;
            }
        }

        false
    }

    /// Verifies whether a URL is in an Azure Storage domain.
    ///
    /// Checks against the well-known Storage endpoints listed in
    /// [`AZURE_STORAGE_DOMAINS`](crate::domains::AZURE_STORAGE_DOMAINS).
    /// Rejects hostnames containing `--`, which violates Azure naming restrictions.
    ///
    /// # Arguments
    ///
    /// * `url` — The URL to verify.  Must use `http:` or `https:`.
    ///
    /// # Returns
    ///
    /// `true` if the URL is in any Azure Storage domain, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use antissrf::URIValidator;
    ///
    /// assert!(URIValidator::in_azure_storage_domain("https://mystorage.blob.core.windows.net"));
    /// assert!(!URIValidator::in_azure_storage_domain("https://my--storage.blob.core.windows.net"));
    /// ```
    pub fn in_azure_storage_domain(url: &str) -> bool {
        let hostname = match Self::get_valid_hostname(url, Self::AZURE_SDK_PROTOCOLS) {
            Some(h) => h,
            None => return false,
        };

        if hostname.contains("--") {
            return false;
        }

        for domain in crate::domains::AZURE_STORAGE_DOMAINS {
            if Self::hostname_in_single_domain(&hostname, domain) {
                return true;
            }
        }

        false
    }

    /// Extract and validate a hostname from a URL string.
    ///
    /// Returns `None` if the URL is malformed, has no hostname, or uses an
    /// unsupported protocol.
    fn get_valid_hostname(url_str: &str, allowed_protocols: &[&str]) -> Option<String> {
        let url = Url::parse(url_str).ok()?;
        let hostname = url.host_str()?.to_string();
        if hostname.is_empty() {
            return None;
        }

        let protocol = format!("{}:", url.scheme());
        if !allowed_protocols.contains(&protocol.as_str()) {
            return None;
        }

        Some(hostname)
    }

    /// Convert a domain string to ASCII (punycode) form using the `url` crate.
    ///
    /// Returns `None` if the domain cannot be parsed.
    fn domain_to_ascii(domain: &str) -> Option<String> {
        let temp_url = format!("https://{}/", domain);
        let url = Url::parse(&temp_url).ok()?;
        url.host_str().map(|s| s.to_string())
    }

    /// Check whether `hostname` is within a single `domain`.
    ///
    /// Supports exact match and subdomain match.  A dotted domain (`.trusted.com`)
    /// matches both `trusted.com` and any subdomain.
    fn hostname_in_single_domain(hostname: &str, domain: &str) -> bool {
        let dotted = format!(".{}", hostname);
        if dotted.ends_with(domain) {
            if hostname.len() == domain.len() {
                return true;
            }
            if domain.starts_with('.') {
                return true;
            }
            if hostname.len() > domain.len()
                && hostname.as_bytes()[hostname.len() - domain.len() - 1] == b'.'
            {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_domain_exact_match() {
        assert!(URIValidator::in_domain(
            "https://trusted.com",
            &["trusted.com"]
        ));
    }

    #[test]
    fn in_domain_subdomain_match() {
        assert!(URIValidator::in_domain(
            "https://api.trusted.com",
            &["trusted.com"]
        ));
        assert!(URIValidator::in_domain(
            "https://sub.api.trusted.com",
            &["trusted.com"]
        ));
    }

    #[test]
    fn in_domain_no_false_positive() {
        assert!(!URIValidator::in_domain(
            "https://nottrusted.com",
            &["trusted.com"]
        ));
        assert!(!URIValidator::in_domain(
            "https://trusted.com.evil.com",
            &["trusted.com"]
        ));
    }

    #[test]
    fn in_domain_dotted_domain() {
        assert!(URIValidator::in_domain(
            "https://api.trusted.com",
            &[".trusted.com"]
        ));
        assert!(URIValidator::in_domain(
            "https://trusted.com",
            &[".trusted.com"]
        ));
    }

    #[test]
    fn in_domain_multiple_domains() {
        assert!(URIValidator::in_domain(
            "https://api.first.com",
            &["first.com", "second.com"]
        ));
        assert!(URIValidator::in_domain(
            "https://api.second.com",
            &["first.com", "second.com"]
        ));
    }

    #[test]
    fn in_domain_unsupported_protocol() {
        assert!(!URIValidator::in_domain(
            "ftp://trusted.com",
            &["trusted.com"]
        ));
        assert!(!URIValidator::in_domain(
            "file:///trusted.com",
            &["trusted.com"]
        ));
    }

    #[test]
    fn in_domain_supported_protocols() {
        assert!(URIValidator::in_domain(
            "http://trusted.com",
            &["trusted.com"]
        ));
        assert!(URIValidator::in_domain(
            "https://trusted.com",
            &["trusted.com"]
        ));
        assert!(URIValidator::in_domain(
            "ws://trusted.com",
            &["trusted.com"]
        ));
        assert!(URIValidator::in_domain(
            "wss://trusted.com",
            &["trusted.com"]
        ));
    }

    #[test]
    fn in_domain_invalid_url() {
        assert!(!URIValidator::in_domain("not-a-url", &["trusted.com"]));
    }

    #[test]
    fn in_domain_empty_hostname() {
        assert!(!URIValidator::in_domain("https://", &["trusted.com"]));
    }

    #[test]
    fn in_domain_empty_trusted_domains() {
        assert!(!URIValidator::in_domain("https://trusted.com", &[]));
    }

    #[test]
    fn in_domain_skips_malformed_domains() {
        // Malformed domain in the list should be skipped, not abort the entire check.
        assert!(URIValidator::in_domain(
            "https://valid.com",
            &["valid.com", "not a domain!"]
        ));
        assert!(URIValidator::in_domain(
            "https://valid.com",
            &["not a domain!", "valid.com"]
        ));
        assert!(!URIValidator::in_domain(
            "https://valid.com",
            &["not a domain!", "also bad"]
        ));
    }

    #[test]
    fn in_domain_invalid_trusted_domain() {
        assert!(!URIValidator::in_domain(
            "https://trusted.com",
            &["not a domain"]
        ));
    }

    #[test]
    fn in_domain_punycode() {
        // URL hostname is automatically punycoded by Url::parse
        // Trusted domain must also be converted to match
        assert!(URIValidator::in_domain(
            "https://münchen.example",
            &["xn--mnchen-3ya.example"]
        ));
    }

    #[test]
    fn in_azure_key_vault_domain_match() {
        assert!(URIValidator::in_azure_key_vault_domain(
            "https://myvault.vault.azure.net"
        ));
    }

    #[test]
    fn in_azure_key_vault_domain_subdomain() {
        assert!(URIValidator::in_azure_key_vault_domain(
            "https://sub.myvault.vault.azure.net"
        ));
    }

    #[test]
    fn in_azure_key_vault_domain_rejects_double_dash() {
        assert!(!URIValidator::in_azure_key_vault_domain(
            "https://my--vault.vault.azure.net"
        ));
    }

    #[test]
    fn in_azure_key_vault_domain_rejects_unsupported_protocol() {
        assert!(!URIValidator::in_azure_key_vault_domain(
            "ws://myvault.vault.azure.net"
        ));
    }

    #[test]
    fn in_azure_key_vault_domain_no_match() {
        assert!(!URIValidator::in_azure_key_vault_domain("https://evil.com"));
    }

    #[test]
    fn in_azure_storage_domain_match() {
        assert!(URIValidator::in_azure_storage_domain(
            "https://mystorage.blob.core.windows.net"
        ));
    }

    #[test]
    fn in_azure_storage_domain_rejects_double_dash() {
        assert!(!URIValidator::in_azure_storage_domain(
            "https://my--storage.blob.core.windows.net"
        ));
    }

    #[test]
    fn in_azure_storage_domain_no_match() {
        assert!(!URIValidator::in_azure_storage_domain("https://evil.com"));
    }

    #[test]
    fn hostname_in_single_domain_exact() {
        assert!(URIValidator::hostname_in_single_domain(
            "trusted.com",
            "trusted.com"
        ));
    }

    #[test]
    fn hostname_in_single_domain_subdomain() {
        assert!(URIValidator::hostname_in_single_domain(
            "api.trusted.com",
            "trusted.com"
        ));
    }

    #[test]
    fn hostname_in_single_domain_no_false_match() {
        assert!(!URIValidator::hostname_in_single_domain(
            "nottrusted.com",
            "trusted.com"
        ));
        assert!(!URIValidator::hostname_in_single_domain(
            "trusted.com.evil",
            "trusted.com"
        ));
    }

    #[test]
    fn hostname_in_single_domain_dotted() {
        assert!(URIValidator::hostname_in_single_domain(
            "api.trusted.com",
            ".trusted.com"
        ));
        assert!(URIValidator::hostname_in_single_domain(
            "trusted.com",
            ".trusted.com"
        ));
    }
}
