//! Error types for AntiSSRF operations.
//!
//! Every fallible operation in this crate returns [`AntiSSRFError`], a single
//! enum that covers validation failures, configuration mistakes, and runtime
//! policy violations. The error type implements [`std::error::Error`] via
//! `thiserror`, and is [`Clone`] + [`PartialEq`] so it can be cheaply passed
//! around and compared in tests.
//!
//! # Error categories
//!
//! | Variant | Triggered by | Typical cause |
//! |---------|--------------|---------------|
//! | [`IPDisallowed`](AntiSSRFError::IPDisallowed) | [`AntiSSRFPolicy::validate_request`](crate::policy::AntiSSRFPolicy::validate_request), DNS resolution, redirects | Target IP is in a denylist or not in the allowlist |
//! | [`SchemeDisallowed`](AntiSSRFError::SchemeDisallowed) | [`AntiSSRFPolicy::validate_request`](crate::policy::AntiSSRFPolicy::validate_request) | `http://` used when [`set_allow_plaintext_http`](crate::policy::AntiSSRFPolicy::set_allow_plaintext_http) is `false` |
//! | [`HeaderDenied`](AntiSSRFError::HeaderDenied) | [`AntiSSRFPolicy::validate_request`](crate::policy::AntiSSRFPolicy::validate_request) | Request contains a header in the denylist |
//! | [`HeaderRequired`](AntiSSRFError::HeaderRequired) | [`AntiSSRFPolicy::validate_request`](crate::policy::AntiSSRFPolicy::validate_request) | Request is missing a header in the required list |
//! | [`InvalidHeader`](AntiSSRFError::InvalidHeader) | [`AntiSSRFPolicy`](crate::policy::AntiSSRFPolicy) configuration methods | Empty or malformed header name supplied at build time |
//! | [`PolicyLocked`](AntiSSRFError::PolicyLocked) | Mutating a locked [`AntiSSRFPolicy`](crate::policy::AntiSSRFPolicy) | Attempting to modify a policy after it has been used |
//! | [`ConflictingConfiguration`](AntiSSRFError::ConflictingConfiguration) | [`AntiSSRFPolicy`](crate::policy::AntiSSRFPolicy) configuration methods | Logically incompatible options (e.g. denylist + `deny_all_unspecified_ips`) |
//! | [`InvalidCIDR`](AntiSSRFError::InvalidCIDR) | [`CIDRBlock::parse`](crate::CIDRBlock::parse) | Malformed CIDR string such as `10.0.0.0/33` |
//! | [`InvalidIP`](AntiSSRFError::InvalidIP) | IP parsing helpers | String that does not represent a valid IPv4 or IPv6 address |
//! | [`InvalidURL`](AntiSSRFError::InvalidURL) | URL parsing helpers | String that is not a valid URL |
//! | [`RedirectValidationFailed`](AntiSSRFError::RedirectValidationFailed) | [`network`](crate::network) middleware | A redirect Location failed re-validation against the active policy |
//!
//! # Example
//!
//! ```
//! use antissrf::{AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError};
//!
//! # fn main() -> Result<(), AntiSSRFError> {
//! let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
//! policy.set_allow_plaintext_http(false)?;
//!
//! let mut headers = vec![];
//! match policy.validate_request("http:", &mut headers) {
//!     Err(AntiSSRFError::SchemeDisallowed) => {
//!         // plaintext HTTP rejected
//!     }
//!     Err(AntiSSRFError::IPDisallowed) => {
//!         // IMDS address blocked
//!     }
//!     Ok(_) => {}
//!     Err(e) => panic!("unexpected error: {}", e),
//! }
//! # Ok(())
//! # }
//! ```

use thiserror::Error;

/// Error types for AntiSSRF operations.
///
/// See the [module-level documentation](self) for a mapping of each variant to
/// the policy setting or API operation that triggers it.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum AntiSSRFError {
    /// The target IP address is blocked by the active policy.
    ///
    /// Returned by [`AntiSSRFPolicy::validate_request`](crate::policy::AntiSSRFPolicy::validate_request)
    /// and the network middleware when the resolved IP falls inside a denylist
    /// (or outside the allowlist when [`deny_all_unspecified_ips`](crate::policy::AntiSSRFPolicy::deny_all_unspecified_ips)
    /// is enabled).
    #[error("IP address disallowed by policy")]
    IPDisallowed,

    /// The request scheme is blocked by the active policy.
    ///
    /// Common causes:
    /// - Plaintext `http://` is used while [`set_allow_plaintext_http`](crate::policy::AntiSSRFPolicy::set_allow_plaintext_http)
    ///   is `false`.
    /// - A non-HTTP scheme such as `ftp:` or `file:` is requested.
    #[error("Request scheme disallowed by policy")]
    SchemeDisallowed,

    /// A denied HTTP header was present in the request.
    ///
    /// Set the denied header list via
    /// [`add_denied_headers`](crate::policy::AntiSSRFPolicy::add_denied_headers).
    /// Comparison is case-insensitive for header names.
    #[error("Request header disallowed by policy")]
    HeaderDenied,

    /// A required HTTP header was missing from the request.
    ///
    /// Set the required header list via
    /// [`add_required_headers`](crate::policy::AntiSSRFPolicy::add_required_headers).
    /// Comparison is case-insensitive for header names.
    #[error("Required request header missing")]
    HeaderRequired,

    /// An invalid or empty header name was provided during policy configuration.
    ///
    /// Header names must be non-empty and contain only printable ASCII characters
    /// excluding the colon (`:`).
    #[error("Invalid header name")]
    InvalidHeader,

    /// Custom DNS lookup functions are not permitted for security reasons.
    ///
    /// The network middleware must control name resolution to ensure IP validation
    /// happens after resolution and before the TCP handshake.
    #[error("Cannot use AntiSSRF with custom lookup function")]
    CustomLookupNotAllowed,

    /// The policy has been locked and can no longer be modified.
    ///
    /// Policies are automatically locked on first use (e.g. the first call to
    /// [`validate_request`](crate::policy::AntiSSRFPolicy::validate_request) or
    /// the first request made through the network middleware). Create a new
    /// [`AntiSSRFPolicy`](crate::policy::AntiSSRFPolicy) if you
    /// need different settings.
    #[error("Policy is locked and cannot be modified")]
    PolicyLocked,

    /// A logically incompatible combination of policy options was requested.
    ///
    /// For example, adding explicit denied addresses while
    /// [`deny_all_unspecified_ips`](crate::policy::AntiSSRFPolicy::deny_all_unspecified_ips)
    /// is already enabled is redundant and therefore rejected.
    #[error("Conflicting policy configuration")]
    ConflictingConfiguration,

    /// The supplied string is not a valid CIDR block.
    ///
    /// Valid examples: `192.168.0.0/24`, `::1/128`, `10.0.0.0/8`.
    /// Invalid examples: `10.0.0.0/33` (prefix too large), `not-an-ip/24`.
    #[error("Invalid CIDR block: {0}")]
    InvalidCIDR(String),

    /// The supplied string is not a valid IP address.
    ///
    /// Valid examples: `192.168.1.1`, `::1`, `::ffff:192.168.1.1`.
    #[error("Invalid IP address: {0}")]
    InvalidIP(String),

    /// The supplied string is not a valid URL.
    ///
    /// URLs must include a scheme and host. Valid examples:
    /// `https://example.com/path`, `http://10.0.0.1:8080/`.
    #[error("Invalid URL: {0}")]
    InvalidURL(String),

    /// A redirect in the HTTP response chain failed re-validation.
    ///
    /// The network middleware re-runs the active policy against every
    /// `Location` header in a 3xx redirect. If the new URL is blocked,
    /// this error is returned and the redirect is aborted.
    #[error("Redirect validation failed: {0}")]
    RedirectValidationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        assert_eq!(
            AntiSSRFError::IPDisallowed.to_string(),
            "IP address disallowed by policy"
        );
        assert_eq!(
            AntiSSRFError::SchemeDisallowed.to_string(),
            "Request scheme disallowed by policy"
        );
        assert_eq!(
            AntiSSRFError::HeaderDenied.to_string(),
            "Request header disallowed by policy"
        );
        assert_eq!(
            AntiSSRFError::HeaderRequired.to_string(),
            "Required request header missing"
        );
        assert_eq!(
            AntiSSRFError::InvalidHeader.to_string(),
            "Invalid header name"
        );
        assert_eq!(
            AntiSSRFError::CustomLookupNotAllowed.to_string(),
            "Cannot use AntiSSRF with custom lookup function"
        );
        assert_eq!(
            AntiSSRFError::PolicyLocked.to_string(),
            "Policy is locked and cannot be modified"
        );
        assert_eq!(
            AntiSSRFError::ConflictingConfiguration.to_string(),
            "Conflicting policy configuration"
        );
        assert_eq!(
            AntiSSRFError::InvalidCIDR("10.0.0.0/33".to_string()).to_string(),
            "Invalid CIDR block: 10.0.0.0/33"
        );
        assert_eq!(
            AntiSSRFError::InvalidIP("not-an-ip".to_string()).to_string(),
            "Invalid IP address: not-an-ip"
        );
        assert_eq!(
            AntiSSRFError::InvalidURL("not-a-url".to_string()).to_string(),
            "Invalid URL: not-a-url"
        );
        assert_eq!(
            AntiSSRFError::RedirectValidationFailed("http://127.0.0.1/secret".to_string())
                .to_string(),
            "Redirect validation failed: http://127.0.0.1/secret"
        );
    }

    #[test]
    fn error_clonable() {
        let err = AntiSSRFError::IPDisallowed;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn error_partial_eq() {
        assert_eq!(AntiSSRFError::PolicyLocked, AntiSSRFError::PolicyLocked);
        assert_ne!(AntiSSRFError::IPDisallowed, AntiSSRFError::SchemeDisallowed);
    }
}
