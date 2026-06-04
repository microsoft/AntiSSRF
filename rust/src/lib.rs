//! AntiSSRF — Microsoft's SSRF Prevention Library for Rust
//!
//! A Rust implementation of [Microsoft's AntiSSRF](https://github.com/microsoft/AntiSSRF)
//! library for preventing **Server-Side Request Forgery (SSRF)** attacks.
//!
//! SSRF occurs when an attacker tricks a server into making requests to
//! unintended destinations — typically internal services, cloud metadata
//! endpoints, or restricted networks. This crate provides layered defenses
//! against such attacks by validating URLs, IP addresses, headers, and
//! redirect chains **before** any network request is issued.
//!
//! # Architecture
//!
//! The library is organized into three layers:
//!
//! | Layer | Module | Purpose |
//! |-------|--------|---------|
//! | **Policy** | [`policy`] | Configure blocking rules, allowlists, and required headers |
//! | **Validation** | [`uri_validator`], [`cidr`] | Static checks for domains, CIDR ranges, and IP addresses |
//! | **Network** | [`network`] (reqwest feature) | `reqwest` middleware that enforces policy on every request and redirect |
//!
//! # Quick Start
//!
//! Build a policy that blocks all internal/sensitive IP ranges and then
//! wrap a `reqwest` client with enforcement middleware:
//!
//! ```no_run
//! # #[cfg(feature = "reqwest-integration")]
//! # {
//! use antissrf::{AntiSSRFPolicy, PolicyConfigOptions};
//! use antissrf::network::reqwest_integration::AntiSSRFClientBuilder;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
//!
//! let client = AntiSSRFClientBuilder::new(policy)
//!     .build_with_middleware()?;
//!
//! // Any request to a forbidden IP (e.g. 169.254.169.254) is rejected
//! // before a TCP connection is opened.
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! # Feature Flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `reqwest-integration` | **Yes** | Enables [`network`] module with `reqwest` / `reqwest-middleware` / `tower` support |
//!
//! Disable the default features if you only need static validation:
//!
//! ```toml
//! [dependencies]
//! antissrf = { version = "0.1.1", default-features = false }
//! ```
//!
//! # Usage Patterns
//!
//! ## Static IP / CIDR validation
//!
//! Use [`CIDRBlock`] and the constants in [`ip_address_ranges`]
//! directly when you don't need a full policy:
//!
//! ```
//! use antissrf::CIDRBlock;
//! use antissrf::ip_address_ranges::RECOMMENDEDV1;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let imds = CIDRBlock::parse("169.254.169.254/32")?;
//! assert!(imds.contains("169.254.169.254".parse()?));
//!
//! // Recommended set covers IMDS, WireServer, loopback, RFC 1918, etc.
//! let recommended: Vec<CIDRBlock> = RECOMMENDEDV1
//!     .iter()
//!     .map(|s| CIDRBlock::parse(s).unwrap())
//!     .collect();
//! # Ok(())
//! # }
//! ```
//!
//! ## Domain allowlisting
//!
//! [`URIValidator`] checks whether a URL belongs to a
//! trusted domain or an Azure service domain:
//!
//! ```
//! use antissrf::URIValidator;
//!
//! assert!(URIValidator::in_domain("https://api.trusted.com/v1", &["trusted.com"]));
//! assert!(!URIValidator::in_azure_key_vault_domain("https://evil.com"));
//! ```
//!
//! ## Fine-grained policy configuration
//!
//! [`AntiSSRFPolicy`] supports allowlists,
//! custom denylists, header enforcement, and protocol restrictions:
//!
//! ```
//! use antissrf::{AntiSSRFPolicy, PolicyConfigOptions, AntiSSRFError};
//!
//! # fn main() -> Result<(), AntiSSRFError> {
//! let mut policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);
//! policy.set_allow_plaintext_http(false)?;   // deny http://
//! policy.add_required_headers(&["X-Request-ID"])?;
//! policy.add_denied_headers(&["X-Internal-Auth"])?;
//!
//! let mut headers = vec![
//!     ("X-Request-ID".to_string(), "abc123".to_string()),
//! ];
//! assert!(policy.validate_request("https:", &mut headers)?);
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! 1. **Validate after DNS resolution** — IP checks must be performed on
//!    resolved addresses, not on the original hostname, to catch DNS rebinding
//!    attacks.
//! 2. **Re-validate every redirect** — A benign initial URL may redirect to a
//!    forbidden internal endpoint. The [`network`] middleware
//!    enforces this automatically.
//! 3. **IPv6 normalization** — All IPv4 addresses are mapped to the IPv6-mapped
//!    form (`::ffff:x.x.x.x`) before CIDR checks. Ensure your allow/deny
//!    lists account for this.
//! 4. **Header case-insensitivity** — Header names are compared
//!    case-insensitively per RFC 7230, but header values are compared
//!    exactly.
//! 5. **Policy immutability** — Once built, a policy cannot be modified
//!    (edit-lock). Create a new policy if requirements change.
//!
//! # References
//!
//! - [Microsoft AntiSSRF Documentation](https://microsoft.github.io/AntiSSRF/)
//! - [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
//! - [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
//!
//! # Crate Map
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`policy`] | [`AntiSSRFPolicy`] — central configuration object |
//! | [`error`] | [`AntiSSRFError`] — error variants with clear security semantics |
//! | [`cidr`] | [`CIDRBlock`] — parsing and IP containment with IPv6 normalization |
//! | [`ip_address_ranges`] | Static constants for RFC special-purpose IP ranges |
//! | [`domains`] | Azure cloud domain suffixes |
//! | [`uri_validator`] | [`URIValidator`] — domain and Azure service validation |
//! | [`network`] | `reqwest` middleware integration |

pub mod cidr;
pub mod domains;
pub mod error;
pub mod ip_address_ranges;
#[cfg(feature = "reqwest-integration")]
pub mod network;
pub mod policy;
pub mod uri_validator;

pub use cidr::CIDRBlock;
pub use error::AntiSSRFError;
pub use policy::{AntiSSRFPolicy, PolicyConfigOptions};
pub use uri_validator::URIValidator;

/// Result type alias for AntiSSRF operations.
pub type Result<T> = std::result::Result<T, AntiSSRFError>;
