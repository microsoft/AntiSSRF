//! Policy configuration and request validation.
//!
//! [`AntiSSRFPolicy`] is the central configuration object. It is created once,
//! optionally mutated through builder-style methods, and then locked on first use.
//! Once locked it becomes immutable, ensuring that validation rules cannot change
//! mid-request.
//!
//! # Evaluation order
//!
//! When [`is_network_connection_allowed`](AntiSSRFPolicy::is_network_connection_allowed)
//! checks a list of IP addresses, the following precedence is used for **each** IP:
//!
//! 1. **Allowlist** — if the IP is inside any [`CIDRBlock`] in
//!    [`allowed_addresses`](AntiSSRFPolicy::allowed_addresses), the IP is **allowed**.
//! 2. **`deny_all_unspecified_ips`** — if this flag is `true` and the IP was not
//!    in the allowlist, the IP is **denied**.
//! 3. **Denylist** — if the IP is inside any [`CIDRBlock`] in
//!    [`denied_addresses`](AntiSSRFPolicy::denied_addresses), the IP is **denied**.
//! 4. **Default** — if none of the above matched, the IP is **allowed**.
//!
//! This means the allowlist always wins, even over `deny_all_unspecified_ips`.
//!
//! # Edit locking
//!
//! A policy is automatically locked the first time a validation method
//! ([`is_network_connection_allowed`](AntiSSRFPolicy::is_network_connection_allowed)
//! or [`validate_request`](AntiSSRFPolicy::validate_request)) is called.
//! After that point all mutating methods return [`PolicyLocked`](crate::AntiSSRFError::PolicyLocked).
//! This prevents accidental or malicious runtime changes to security rules.
//!
//! # Example
//!
//! ```
//! use antissrf::{AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError};
//!
//! # fn main() -> Result<(), AntiSSRFError> {
//! let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
//!
//! // Allow a specific internal range (allowlist wins over denylist)
//! policy.add_allowed_addresses(&["10.0.0.0/8"])?;
//!
//! // Require a tracing header
//! policy.add_required_headers(&["x-request-id"])?;
//!
//! // Lock occurs here
//! assert!(policy.is_network_connection_allowed(&["8.8.8.8"])?);
//! assert!(policy.is_network_connection_allowed(&["10.0.0.1"])?);
//! assert!(!policy.is_network_connection_allowed(&["169.254.169.254"])?);
//! # Ok(())
//! # }
//! ```

use crate::cidr::CIDRBlock;
use crate::error::AntiSSRFError;
use crate::ip_address_ranges;
use std::net::IpAddr;

/// Preset blocking strategies used when constructing an [`AntiSSRFPolicy`].
///
/// These options configure sensible defaults. You can further customize the
/// policy after creation via [`AntiSSRFPolicy`] methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyConfigOptions {
    /// No restrictions. All IP addresses, protocols, and headers are allowed.
    ///
    /// Use this variant when you intend to configure every rule manually or
    /// when you only need the library for CIDR parsing and domain validation.
    None,

    /// Block all external IPs unless explicitly allowlisted.
    ///
    /// Sets [`deny_all_unspecified_ips`](AntiSSRFPolicy::deny_all_unspecified_ips)
    /// to `true`. Any IP address that is **not** in the allowlist is denied.
    /// This is suitable for services that should only talk to a known set of
    /// internal or partner endpoints.
    InternalOnly,

    /// Block known dangerous IP ranges (V1 list).
    ///
    /// Populates the denylist with [`crate::ip_address_ranges::RECOMMENDEDV1`],
    /// which includes:
    /// - Azure IMDS (`169.254.169.254/32`)
    /// - Azure WireServer (`168.63.129.16/32`)
    /// - Loopback, link-local, multicast, RFC 1918 private ranges, CGNAT, and more
    ///
    /// Also enables [`add_xff_header`](AntiSSRFPolicy::add_xff_header).
    /// External public IPs (e.g. `8.8.8.8`) remain allowed.
    ExternalOnlyV1,

    /// Alias for [`ExternalOnlyV1`](PolicyConfigOptions::ExternalOnlyV1).
    ///
    /// Reserved for forward compatibility. When a future version introduces a
    /// new recommended blocklist, this variant will automatically map to it.
    ExternalOnlyLatest,
}

/// Central configuration object for SSRF prevention.
///
/// `AntiSSRFPolicy` is created via [`new`](AntiSSRFPolicy::new) with a
/// [`PolicyConfigOptions`] preset and then customised through `add_*` / `set_*`
/// methods. Once a validation method is called the policy is **locked** and
/// can no longer be changed.
///
/// # Thread safety
///
/// The type is `Clone` but not `Sync`. If you need to share a policy across
/// threads, clone it before locking or wrap it in an `Arc`.
///
/// # Security behaviour summary
///
/// | Setting | Default | Purpose |
/// |---------|---------|---------|
/// | `allowed_addresses` | empty | IPs/CIDRs that are always permitted |
/// | `denied_addresses` | empty | IPs/CIDRs that are always blocked |
/// | `deny_all_unspecified_ips` | `false` | Reject any IP not in `allowed_addresses` |
/// | `required_headers` | empty | Headers that must be present (case-insensitive names) |
/// | `denied_headers` | empty | Headers that must not be present (case-insensitive names) |
/// | `add_xff_header` | `false` | Inject `X-Forwarded-For: true` if missing |
/// | `allow_plaintext_http` | `false` | Permit `http://` requests |
#[derive(Debug, Clone, PartialEq)]
pub struct AntiSSRFPolicy {
    allowed_addresses: Vec<CIDRBlock>,
    denied_addresses: Vec<CIDRBlock>,
    deny_all_unspecified_ips: bool,
    required_headers: Vec<String>,
    denied_headers: Vec<String>,
    add_xff_header: bool,
    allow_plaintext_http: bool,
    locked: bool,
}

impl AntiSSRFPolicy {
    /// Create a new policy using a preset configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions};
    ///
    /// let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
    /// ```
    pub fn new(config: PolicyConfigOptions) -> Self {
        let mut policy = Self {
            allowed_addresses: Vec::new(),
            denied_addresses: Vec::new(),
            deny_all_unspecified_ips: false,
            required_headers: Vec::new(),
            denied_headers: Vec::new(),
            add_xff_header: false,
            allow_plaintext_http: false,
            locked: false,
        };

        match config {
            PolicyConfigOptions::None => {}
            PolicyConfigOptions::InternalOnly => {
                policy.deny_all_unspecified_ips = true;
            }
            PolicyConfigOptions::ExternalOnlyV1 | PolicyConfigOptions::ExternalOnlyLatest => {
                policy.add_denied_addresses_from_slice(ip_address_ranges::RECOMMENDEDV1);
                policy.add_xff_header = true;
            }
        }

        policy
    }

    // =========================================================================
    // Getters
    // =========================================================================

    /// Return the list of allowed IP address CIDR blocks.
    ///
    /// The returned slice is ordered by insertion order.
    pub fn allowed_addresses(&self) -> &[CIDRBlock] {
        &self.allowed_addresses
    }

    /// Return the list of denied IP address CIDR blocks.
    ///
    /// The returned slice is ordered by insertion order.
    pub fn denied_addresses(&self) -> &[CIDRBlock] {
        &self.denied_addresses
    }

    /// Return whether every IP not explicitly allowlisted is denied.
    pub fn deny_all_unspecified_ips(&self) -> bool {
        self.deny_all_unspecified_ips
    }

    /// Return the list of required HTTP header names (all lowercased).
    pub fn required_headers(&self) -> &[String] {
        &self.required_headers
    }

    /// Return the list of denied HTTP header names (all lowercased).
    pub fn denied_headers(&self) -> &[String] {
        &self.denied_headers
    }

    /// Return whether the policy will automatically inject `X-Forwarded-For`.
    pub fn add_xff_header(&self) -> bool {
        self.add_xff_header
    }

    /// Return whether plaintext `http://` requests are permitted.
    pub fn allow_plaintext_http(&self) -> bool {
        self.allow_plaintext_http
    }

    /// Return whether the policy has been locked.
    ///
    /// A policy becomes locked on the first call to
    /// [`is_network_connection_allowed`](AntiSSRFPolicy::is_network_connection_allowed)
    /// or [`validate_request`](AntiSSRFPolicy::validate_request).
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    // =========================================================================
    // Locking mechanism
    // =========================================================================

    fn lock(&mut self) {
        self.locked = true;
    }

    fn assert_not_locked(&self) -> Result<(), AntiSSRFError> {
        if self.locked {
            Err(AntiSSRFError::PolicyLocked)
        } else {
            Ok(())
        }
    }

    // =========================================================================
    // IP address management
    // =========================================================================

    /// Add IP addresses or CIDR blocks to the allowlist.
    ///
    /// Strings are normalised before parsing: single IPs receive the correct
    /// host-prefix length (`/32` for IPv4, `/128` for IPv6).
    ///
    /// # Errors
    ///
    /// Returns [`PolicyLocked`](crate::AntiSSRFError::PolicyLocked) if the
    /// policy has already been used, or [`InvalidCIDR`](crate::AntiSSRFError::InvalidCIDR)
    /// if a string cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```
    /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError};
    ///
    /// # fn main() -> Result<(), AntiSSRFError> {
    /// let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    /// policy.add_allowed_addresses(&["10.0.0.0/8", "::1"])?;
    /// assert_eq!(policy.allowed_addresses().len(), 2);
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_allowed_addresses(&mut self, addresses: &[&str]) -> Result<(), AntiSSRFError> {
        self.assert_not_locked()?;
        for addr in addresses {
            let normalized = Self::normalize_address(addr);
            let block = CIDRBlock::parse(&normalized)?;
            self.allowed_addresses.push(block);
        }
        Ok(())
    }

    /// Add IP addresses or CIDR blocks to the denylist.
    ///
    /// Strings are normalised before parsing (see [`add_allowed_addresses`](AntiSSRFPolicy::add_allowed_addresses)).
    ///
    /// # Errors
    ///
    /// Returns [`PolicyLocked`](crate::AntiSSRFError::PolicyLocked) if the
    /// policy has already been used, [`ConflictingConfiguration`](crate::AntiSSRFError::ConflictingConfiguration)
    /// if [`deny_all_unspecified_ips`](AntiSSRFPolicy::deny_all_unspecified_ips) is already
    /// `true`, or [`InvalidCIDR`](crate::AntiSSRFError::InvalidCIDR) on parse failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError};
    ///
    /// # fn main() -> Result<(), AntiSSRFError> {
    /// let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    /// policy.add_denied_addresses(&["169.254.169.254/32"])?;
    /// assert_eq!(policy.denied_addresses().len(), 1);
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_denied_addresses(&mut self, addresses: &[&str]) -> Result<(), AntiSSRFError> {
        self.assert_not_locked()?;
        if self.deny_all_unspecified_ips {
            return Err(AntiSSRFError::ConflictingConfiguration);
        }
        for addr in addresses {
            let normalized = Self::normalize_address(addr);
            let block = CIDRBlock::parse(&normalized)?;
            self.denied_addresses.push(block);
        }
        Ok(())
    }

    /// Check whether every IP in the supplied list is allowed by this policy.
    ///
    /// This method **locks** the policy. After it returns (successfully or not)
    /// the policy can no longer be modified.
    ///
    /// # Arguments
    ///
    /// * `ipaddresses` — Slice of IP address strings (e.g. `["8.8.8.8", "::1"]`).
    ///   Each string is parsed with [`IpAddr`] before checking.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — **all** IPs are allowed.
    /// - `Ok(false)` — at least one IP is blocked.
    /// - `Err(AntiSSRFError::InvalidIP)` — one of the strings is not a valid IP address.
    ///
    /// # Examples
    ///
    /// ```
    /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError};
    ///
    /// # fn main() -> Result<(), AntiSSRFError> {
    /// let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
    ///
    // Allowlist wins over denylist
    /// policy.add_allowed_addresses(&["169.254.169.254/32"])?;
    /// assert!(policy.is_network_connection_allowed(&["169.254.169.254"])?);
    ///
    /// // But 127.0.0.1 is still blocked (loopback is in the V1 denylist)
    /// assert!(!policy.is_network_connection_allowed(&["127.0.0.1"])?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_network_connection_allowed(
        &mut self,
        ipaddresses: &[&str],
    ) -> Result<bool, AntiSSRFError> {
        self.lock();

        for ip_str in ipaddresses {
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|_| AntiSSRFError::InvalidIP(ip_str.to_string()))?;

            // If this IP is in the allowlist it is safe – move on to the next IP
            if self.allowed_addresses.iter().any(|a| a.contains(ip)) {
                continue;
            }

            // Reject when every unspecified IP is denied or this IP is in the denylist
            if self.deny_all_unspecified_ips || self.denied_addresses.iter().any(|d| d.contains(ip))
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Set the `deny_all_unspecified_ips` flag.
    ///
    /// When `true`, any IP that is **not** in the allowlist is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyLocked`](crate::AntiSSRFError::PolicyLocked) if the
    /// policy has already been used.
    pub fn set_deny_all_unspecified_ips(&mut self, value: bool) -> Result<(), AntiSSRFError> {
        self.assert_not_locked()?;
        self.deny_all_unspecified_ips = value;
        Ok(())
    }

    // =========================================================================
    // Header management
    // =========================================================================

    /// Add required HTTP header names.
    ///
    /// Names are automatically trimmed and lowercased. A request that does
    /// not contain **all** required headers (case-insensitive name match) is
    /// rejected with [`HeaderRequired`](crate::AntiSSRFError::HeaderRequired).
    ///
    /// # Errors
    ///
    /// Returns [`PolicyLocked`](crate::AntiSSRFError::PolicyLocked) or
    /// [`InvalidHeader`](crate::AntiSSRFError::InvalidHeader) if an empty
    /// string is supplied.
    ///
    /// # Examples
    ///
    /// ```
    /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError};
    ///
    /// # fn main() -> Result<(), AntiSSRFError> {
    /// let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    /// policy.add_required_headers(&["Authorization", "X-Request-ID"])?;
    /// assert_eq!(policy.required_headers(), &["authorization", "x-request-id"]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_required_headers(&mut self, headers: &[&str]) -> Result<(), AntiSSRFError> {
        self.assert_not_locked()?;
        for header in headers {
            let h = header.trim().to_ascii_lowercase();
            if h.is_empty() {
                return Err(AntiSSRFError::InvalidHeader);
            }
            self.required_headers.push(h);
        }
        Ok(())
    }

    /// Add denied HTTP header names.
    ///
    /// Names are automatically trimmed and lowercased. A request that contains
    /// **any** denied header (case-insensitive name match) is rejected with
    /// [`HeaderDenied`](crate::AntiSSRFError::HeaderDenied).
    ///
    /// # Errors
    ///
    /// Returns [`PolicyLocked`](crate::AntiSSRFError::PolicyLocked) or
    /// [`InvalidHeader`](crate::AntiSSRFError::InvalidHeader) if an empty
    /// string is supplied.
    ///
    /// # Examples
    ///
    /// ```
    /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError};
    ///
    /// # fn main() -> Result<(), AntiSSRFError> {
    /// let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    /// policy.add_denied_headers(&["X-Internal-Auth", "X-Debug"])?;
    /// assert_eq!(policy.denied_headers(), &["x-internal-auth", "x-debug"]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_denied_headers(&mut self, headers: &[&str]) -> Result<(), AntiSSRFError> {
        self.assert_not_locked()?;
        for header in headers {
            let h = header.trim().to_ascii_lowercase();
            if h.is_empty() {
                return Err(AntiSSRFError::InvalidHeader);
            }
            self.denied_headers.push(h);
        }
        Ok(())
    }

    /// Set whether to automatically inject an `X-Forwarded-For` header.
    ///
    /// When enabled, [`validate_request`](AntiSSRFPolicy::validate_request)
    /// appends `X-Forwarded-For: true` to the header list if the header is not
    /// already present. The comparison is case-insensitive.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyLocked`](crate::AntiSSRFError::PolicyLocked) if the
    /// policy has already been used.
    pub fn set_add_xff_header(&mut self, value: bool) -> Result<(), AntiSSRFError> {
        self.assert_not_locked()?;
        self.add_xff_header = value;
        Ok(())
    }

    /// Set whether plaintext `http://` requests are permitted.
    ///
    /// When `false` (the default), only `https:` is accepted by
    /// [`validate_request`](AntiSSRFPolicy::validate_request).
    ///
    /// # Errors
    ///
    /// Returns [`PolicyLocked`](crate::AntiSSRFError::PolicyLocked) if the
    /// policy has already been used.
    pub fn set_allow_plaintext_http(&mut self, value: bool) -> Result<(), AntiSSRFError> {
        self.assert_not_locked()?;
        self.allow_plaintext_http = value;
        Ok(())
    }

    // =========================================================================
    // HTTP request validation
    // =========================================================================

    /// Validate the protocol scheme and headers of an HTTP request.
    ///
    /// This method **locks** the policy. After it returns (successfully or not)
    /// the policy can no longer be modified.
    ///
    /// # Arguments
    ///
    /// * `protocol` — Scheme string such as `"http:"` or `"https:"`.
    /// * `headers` — Mutable list of header key-value pairs. If
    ///   [`add_xff_header`](AntiSSRFPolicy::add_xff_header) is enabled and
    ///   `X-Forwarded-For` is missing, the header is appended in-place.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — the request complies with the policy.
    /// - `Err(AntiSSRFError::SchemeDisallowed)` — the scheme is not `https:`
    ///   (or `http:` when [`allow_plaintext_http`](AntiSSRFPolicy::allow_plaintext_http) is `true`).
    /// - `Err(AntiSSRFError::HeaderDenied)` — a denied header was found.
    /// - `Err(AntiSSRFError::HeaderRequired)` — a required header is missing.
    ///
    /// # Examples
    ///
    /// ```
    /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError};
    ///
    /// # fn main() -> Result<(), AntiSSRFError> {
    /// let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    /// policy.set_allow_plaintext_http(true)?;
    /// policy.add_required_headers(&["x-request-id"])?;
    ///
    /// let mut headers = vec![
    ///     ("X-Request-ID".to_string(), "abc".to_string()),
    /// ];
    /// assert!(policy.validate_request("http:", &mut headers)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate_request(
        &mut self,
        protocol: &str,
        headers: &mut Vec<(String, String)>,
    ) -> Result<bool, AntiSSRFError> {
        self.lock();

        // Protocol check
        if protocol != "https:" {
            if protocol == "http:" && self.allow_plaintext_http {
                // OK
            } else {
                return Err(AntiSSRFError::SchemeDisallowed);
            }
        }

        // Only allow HTTP and HTTPS
        if protocol != "http:" && protocol != "https:" {
            return Err(AntiSSRFError::SchemeDisallowed);
        }

        // Denied header check
        for denied in &self.denied_headers {
            if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(denied)) {
                return Err(AntiSSRFError::HeaderDenied);
            }
        }

        // Required header check
        for required in &self.required_headers {
            if !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(required))
            {
                return Err(AntiSSRFError::HeaderRequired);
            }
        }

        // Inject `X-Forwarded-For` if enabled and not already present
        if self.add_xff_header
            && !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
        {
            headers.push(("X-Forwarded-For".to_string(), "true".to_string()));
        }

        Ok(true)
    }

    /// Determine whether this request needs an injected `X-Forwarded-For` header.
    ///
    /// Returns `true` when [`add_xff_header`](AntiSSRFPolicy::add_xff_header)
    /// is enabled **and** no `X-Forwarded-For` header (case-insensitive) is
    /// already present in `headers`.
    ///
    /// This is a pure query; it does **not** lock the policy.
    ///
    /// # Examples
    ///
    /// ```
    /// use antissrf::{AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError};
    ///
    /// # fn main() -> Result<(), AntiSSRFError> {
    /// let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::None);
    /// policy.set_add_xff_header(true)?;
    ///
    /// assert!(policy.needs_xff_header(&[]));
    ///
    /// let headers = vec![("x-forwarded-for".to_string(), "1.2.3.4".to_string())];
    /// assert!(!policy.needs_xff_header(&headers));
    /// # Ok(())
    /// # }
    /// ```
    pub fn needs_xff_header(&self, headers: &[(String, String)]) -> bool {
        self.add_xff_header
            && !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    fn add_denied_addresses_from_slice(&mut self, addresses: &[&str]) {
        for addr in addresses {
            let normalized = Self::normalize_address(addr);
            if let Ok(block) = CIDRBlock::parse(&normalized) {
                self.denied_addresses.push(block);
            }
        }
    }

    /// Normalise an IP address string by trimming whitespace and appending the
    /// host-prefix length if a CIDR mask is missing.
    fn normalize_address(addr: &str) -> String {
        let trimmed = addr.trim();
        if !trimmed.contains('/') {
            if trimmed.contains(':') {
                format!("{}/128", trimmed)
            } else {
                format!("{}/32", trimmed)
            }
        } else {
            trimmed.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Constructor tests
    // =========================================================================

    #[test]
    fn new_none_has_empty_lists() {
        let p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        assert!(!p.deny_all_unspecified_ips);
        assert!(!p.add_xff_header);
        assert!(!p.allow_plaintext_http);
    }

    #[test]
    fn new_internal_only_sets_deny_all() {
        let p = AntiSSRFPolicy::new(PolicyConfigOptions::InternalOnly);
        assert!(p.deny_all_unspecified_ips);
    }

    #[test]
    fn new_external_v1_populates_denylist() {
        let p = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyV1);
        assert!(!p.denied_addresses.is_empty());
        assert!(p.add_xff_header);
    }

    #[test]
    fn new_external_latest_populates_denylist() {
        let p = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
        assert!(!p.denied_addresses.is_empty());
        assert!(p.add_xff_header);
    }

    // =========================================================================
    // IP address tests
    // =========================================================================

    #[test]
    fn add_allowed_addresses_works() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::InternalOnly);
        p.add_allowed_addresses(&["10.0.0.0/8"]).unwrap();
        assert_eq!(p.allowed_addresses.len(), 1);
        assert!(p.is_network_connection_allowed(&["10.0.0.0"]).unwrap());
        assert!(p.is_network_connection_allowed(&["10.0.0.1"]).unwrap());
        assert!(p.is_network_connection_allowed(&["10.1.2.3"]).unwrap());
        assert!(
            p.is_network_connection_allowed(&["10.255.255.255"])
                .unwrap()
        );
        assert!(!p.is_network_connection_allowed(&["11.0.0.0"]).unwrap());
    }

    #[test]
    fn add_allowed_addresses_normalizes_single_ip() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::InternalOnly);
        p.add_allowed_addresses(&["10.0.0.1"]).unwrap();
        assert_eq!(p.allowed_addresses.len(), 1);
        assert!(p.is_network_connection_allowed(&["10.0.0.1"]).unwrap());
        assert!(!p.is_network_connection_allowed(&["10.0.0.2"]).unwrap());
    }

    #[test]
    fn add_allowed_addresses_rejects_invalid() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        let result = p.add_allowed_addresses(&["not-an-ip"]);
        assert!(matches!(result, Err(AntiSSRFError::InvalidCIDR(_))));
    }

    #[test]
    fn add_denied_addresses_works() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_denied_addresses(&["169.254.169.254/32"]).unwrap();
        assert!(
            p.is_network_connection_allowed(&["169.254.169.253"])
                .unwrap()
        );
        assert!(
            !p.is_network_connection_allowed(&["169.254.169.254"])
                .unwrap()
        );
        assert_eq!(p.denied_addresses.len(), 1);
    }

    #[test]
    fn add_denied_addresses_fails_when_deny_all_set() {
        // InternalOnly sets `deny_all_unspecified_ips = true`,
        // so adding specific denied addresses should fail.
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::InternalOnly);
        let result = p.add_denied_addresses(&["10.0.0.0/8"]);
        assert!(matches!(
            result,
            Err(AntiSSRFError::ConflictingConfiguration)
        ));
    }

    #[test]
    fn is_network_connection_allowed_basic() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        assert!(p.is_network_connection_allowed(&["8.8.8.8"]).unwrap());
    }

    #[test]
    fn is_network_connection_allowed_blocks_denylist() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_denied_addresses(&["169.254.169.254/32"]).unwrap();
        assert!(
            !p.is_network_connection_allowed(&["169.254.169.254"])
                .unwrap()
        );
    }

    #[test]
    fn is_network_connection_allowed_allows_allowlist() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_denied_addresses(&["10.0.0.0/8"]).unwrap();
        p.add_allowed_addresses(&["10.0.0.1/32"]).unwrap();
        assert!(p.is_network_connection_allowed(&["10.0.0.1"]).unwrap());
        assert!(!p.is_network_connection_allowed(&["10.0.0.2"]).unwrap());
    }

    #[test]
    fn is_network_connection_allowed_deny_all_unspecified() {
        // InternalOnly sets `deny_all_unspecified_ips = true`,
        // so any IP not explicitly allowed should be denied.
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::InternalOnly);
        assert!(!p.is_network_connection_allowed(&["8.8.8.8"]).unwrap());
    }

    #[test]
    fn is_network_connection_allowed_deny_all_with_allowlist() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::InternalOnly);
        p.add_allowed_addresses(&["8.8.8.8/32"]).unwrap();
        assert!(p.is_network_connection_allowed(&["8.8.8.8"]).unwrap());
        assert!(!p.is_network_connection_allowed(&["8.8.8.9"]).unwrap());
    }

    #[test]
    fn is_network_connection_allowed_mixed_allowlist_and_denylist() {
        // Verifies that a single blocked IP in a batch causes the entire check to fail,
        // even when another IP in the same batch is in the allowlist.
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_denied_addresses(&["10.0.0.0/8"]).unwrap();
        p.add_allowed_addresses(&["127.0.0.1/32"]).unwrap();
        assert!(
            !p.is_network_connection_allowed(&["127.0.0.1", "10.0.0.1"])
                .unwrap()
        );
    }

    #[test]
    fn is_network_connection_allowed_invalid_ip() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        let result = p.is_network_connection_allowed(&["not-an-ip"]);
        assert!(matches!(result, Err(AntiSSRFError::InvalidIP(_))));
    }

    #[test]
    fn is_network_connection_allowed_locks_policy() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.is_network_connection_allowed(&["8.8.8.8"]).unwrap();
        assert!(matches!(
            p.add_allowed_addresses(&["10.0.0.0/8"]),
            Err(AntiSSRFError::PolicyLocked)
        ));
    }

    #[test]
    fn ipv6_single_ip_normalized() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_allowed_addresses(&["::1"]).unwrap();
        assert_eq!(p.allowed_addresses.len(), 1);
        assert_eq!(p.allowed_addresses[0].to_string(), "::1/128");
    }

    #[test]
    fn external_v1_blocks_imds() {
        // ExternalOnlyV1 should block known dangerous IPs such as IMDS.
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyV1);
        assert!(
            !p.is_network_connection_allowed(&["169.254.169.254"])
                .unwrap()
        );

        assert!(!p.is_network_connection_allowed(&["168.63.129.16"]).unwrap());
    }

    #[test]
    fn external_latest_blocks_imds_and_wireserver() {
        // ExternalOnlyLatest should block known dangerous IPs such as IMDS and Wireserver.
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
        assert!(
            !p.is_network_connection_allowed(&["169.254.169.254"])
                .unwrap()
        );
        assert!(!p.is_network_connection_allowed(&["168.63.129.16"]).unwrap());
    }

    #[test]
    fn external_v1_allows_external_ips() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyV1);
        assert!(p.is_network_connection_allowed(&["8.8.8.8"]).unwrap());
        assert!(p.is_network_connection_allowed(&["1.1.1.1"]).unwrap());
    }

    #[test]
    fn external_latest_allows_external_ips() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
        assert!(p.is_network_connection_allowed(&["8.8.8.8"]).unwrap());
        assert!(p.is_network_connection_allowed(&["1.1.1.1"]).unwrap());
    }

    #[test]
    fn none_with_deny_all_blocks_unless_allowlisted() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.set_deny_all_unspecified_ips(true).unwrap();
        p.add_allowed_addresses(&["8.8.8.8/32"]).unwrap();
        assert!(p.is_network_connection_allowed(&["8.8.8.8"]).unwrap());
        assert!(!p.is_network_connection_allowed(&["1.1.1.1"]).unwrap());
    }

    // =========================================================================
    // HTTP header tests
    // =========================================================================

    #[test]
    fn add_required_headers_works() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_required_headers(&["Authorization", "X-Custom"])
            .unwrap();
        assert_eq!(p.required_headers, vec!["authorization", "x-custom"]);
    }

    #[test]
    fn add_required_headers_rejects_empty() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        let result = p.add_required_headers(&[""]);
        assert!(matches!(result, Err(AntiSSRFError::InvalidHeader)));
    }

    #[test]
    fn add_denied_headers_works() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_denied_headers(&["X-Secret"]).unwrap();
        assert_eq!(p.denied_headers, vec!["x-secret"]);
    }

    #[test]
    fn validate_request_https_always_allowed() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        assert!(p.validate_request("https:", &mut vec![]).unwrap());
    }

    #[test]
    fn validate_request_http_denied_by_default() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        let result = p.validate_request("http:", &mut vec![]);
        assert!(matches!(result, Err(AntiSSRFError::SchemeDisallowed)));
    }

    #[test]
    fn validate_request_http_allowed_when_configured() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.set_allow_plaintext_http(true).unwrap();
        assert!(p.validate_request("http:", &mut vec![]).unwrap());
    }

    #[test]
    fn validate_request_unknown_protocol_denied() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        let result = p.validate_request("ftp:", &mut vec![]);
        assert!(matches!(result, Err(AntiSSRFError::SchemeDisallowed)));
    }

    #[test]
    fn validate_request_denied_header_found() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_denied_headers(&["x-secret"]).unwrap();
        let mut headers = vec![("X-Secret".to_string(), "value".to_string())];
        let result = p.validate_request("https:", &mut headers);
        assert!(matches!(result, Err(AntiSSRFError::HeaderDenied)));
    }

    #[test]
    fn validate_request_required_header_missing() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_required_headers(&["authorization"]).unwrap();
        let result = p.validate_request("https:", &mut vec![]);
        assert!(matches!(result, Err(AntiSSRFError::HeaderRequired)));
    }

    #[test]
    fn validate_request_required_header_present() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_required_headers(&["authorization"]).unwrap();
        let mut headers = vec![("Authorization".to_string(), "Bearer token".to_string())];
        assert!(p.validate_request("https:", &mut headers).unwrap());
    }

    #[test]
    fn validate_request_locks_policy() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.validate_request("https:", &mut vec![]).unwrap();
        assert!(matches!(
            p.add_required_headers(&["X-Test"]),
            Err(AntiSSRFError::PolicyLocked)
        ));
    }

    #[test]
    fn is_locked_returns_true_after_validate_request() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        assert!(!p.is_locked());
        p.validate_request("https:", &mut vec![]).unwrap();
        assert!(p.is_locked());
    }

    // =========================================================================
    // Property tests
    // =========================================================================

    #[test]
    fn set_deny_all_unspecified_ips_works() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.set_deny_all_unspecified_ips(true).unwrap();
        assert!(p.deny_all_unspecified_ips());
    }

    #[test]
    fn set_add_xff_header_works() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.set_add_xff_header(true).unwrap();
        assert!(p.add_xff_header());
    }

    #[test]
    fn set_allow_plaintext_http_works() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.set_allow_plaintext_http(true).unwrap();
        assert!(p.allow_plaintext_http());
    }

    #[test]
    fn set_deny_all_unspecified_ips_locked() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::InternalOnly);
        p.is_network_connection_allowed(&["8.8.8.8"]).unwrap();
        assert!(matches!(
            p.set_deny_all_unspecified_ips(false),
            Err(AntiSSRFError::PolicyLocked)
        ));
    }

    // =========================================================================
    // XFF header tests
    // =========================================================================

    #[test]
    fn needs_xff_header_when_enabled_and_missing() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.set_add_xff_header(true).unwrap();
        assert!(p.needs_xff_header(&[]));
    }

    #[test]
    fn needs_xff_header_when_already_present() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.set_add_xff_header(true).unwrap();
        let headers = vec![("X-Forwarded-For".to_string(), "1.2.3.4".to_string())];
        assert!(!p.needs_xff_header(&headers));
    }

    #[test]
    fn needs_xff_header_when_disabled() {
        let p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        assert!(!p.needs_xff_header(&[]));
    }

    #[test]
    fn needs_xff_header_case_insensitive() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.set_add_xff_header(true).unwrap();
        let headers: Vec<(String, String)> =
            vec![("x-forwarded-for".to_string(), "1.2.3.4".to_string())];
        assert!(!p.needs_xff_header(&headers));
    }

    // =========================================================================
    // Getter tests
    // =========================================================================

    #[test]
    fn allowed_addresses_getter() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_allowed_addresses(&["10.0.0.0/8", "192.168.1.1"])
            .unwrap();
        let addrs = p.allowed_addresses();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].to_string(), "10.0.0.0/8");
        assert_eq!(addrs[1].to_string(), "192.168.1.1/32");
    }

    #[test]
    fn denied_addresses_getter() {
        let p = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyV1);
        let addrs = p.denied_addresses();
        assert!(!addrs.is_empty());
        // Verify that known dangerous IPs are in the denylist.
        assert!(addrs.iter().any(|a| a.to_string() == "169.254.0.0/16"));
    }

    #[test]
    fn required_headers_getter() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_required_headers(&["Authorization", "X-Custom"])
            .unwrap();
        let headers = p.required_headers();
        assert_eq!(headers, vec!["authorization", "x-custom"]);
    }

    #[test]
    fn denied_headers_getter() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.add_denied_headers(&["X-Secret"]).unwrap();
        let headers = p.denied_headers();
        assert_eq!(headers, vec!["x-secret"]);
    }

    // =========================================================================
    // XFF injection side-effect tests
    // =========================================================================

    #[test]
    fn validate_request_injects_xff_when_missing() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.set_add_xff_header(true).unwrap();
        let mut headers = vec![];
        let result = p.validate_request("https:", &mut headers).unwrap();
        assert!(result);
        assert!(
            headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
        );
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn validate_request_does_not_inject_xff_when_present() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.set_add_xff_header(true).unwrap();
        let mut headers = vec![("X-Forwarded-For".to_string(), "1.2.3.4".to_string())];
        let result = p.validate_request("https:", &mut headers).unwrap();
        assert!(result);
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn validate_request_does_not_inject_xff_when_disabled() {
        let mut p = AntiSSRFPolicy::new(PolicyConfigOptions::None);
        p.set_add_xff_header(false).unwrap();
        let mut headers = vec![];
        let result = p.validate_request("https:", &mut headers).unwrap();
        assert!(result);
        assert!(headers.is_empty());
    }
}
