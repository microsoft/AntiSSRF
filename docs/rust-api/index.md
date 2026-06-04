---
layout: default
title: Rust API Reference
nav_order: 5
description: "Complete API documentation for the AntiSSRF Rust Library"
has_children: true
has_toc: false
---

# API Documentation

## AntiSSRF Rust Library

The **AntiSSRF Rust Library** (`antissrf`) is a crate for Rust applications that provides robust URL validation and HTTP request protection to prevent SSRF vulnerabilities. It integrates with `reqwest` via `reqwest-middleware` for DNS-level IP blocking, header validation, protocol enforcement, and redirect-chain re-validation.

## Usage Instructions

The AntiSSRF library provides validation for different scenarios based on your trust requirements:

| Use Case | Description | Documentation |
| --- | --- | --- |
| **General Case** | Block internal/sensitive IP addresses, enforce headers, validate protocols. | [`AntiSSRFPolicy`](antissrfpolicy) |
| **Azure Key Vault Domain** | Validate URL belongs to an Azure Key Vault domain. | [`URIValidator::in_azure_key_vault_domain`](urivalidator/inazurekeyvaultdomain) |
| **Azure Storage Domain** | Validate URL belongs to an Azure Storage domain. | [`URIValidator::in_azure_storage_domain`](urivalidator/inazurestoragedomain) |
| **Trusted Domain Allowlist** | Validate URL belongs to a specific, trusted domain. | [`URIValidator::in_domain`](urivalidator/indomain) |

## Modules

| Module | Description |
| --- | --- |
| [`policy`](antissrfpolicy) | [`AntiSSRFPolicy`](antissrfpolicy) — central configuration object with allowlist, denylist, and header enforcement |
| [`error`](error) | [`AntiSSRFError`](error) — typed error variants with clear security semantics |
| [`cidr`](cidr) | [`CIDRBlock`](cidr) — CIDR block parsing and IP containment with IPv6 normalization |
| [`uri_validator`](urivalidator) | [`URIValidator`](urivalidator) — domain and Azure service URL validation |
| [`network`](network) | reqwest middleware integration with DNS-level IP blocking and redirect re-validation |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
antissrf = "0.1.1"
```

Or with explicit feature control:

```toml
# Core only (no HTTP client dependencies)
antissrf = { version = "0.1.1", default-features = false }

# Full reqwest integration (default)
antissrf = { version = "0.1.1", features = ["reqwest-integration"] }
```

## Quick Start

```rust
use antissrf::{AntiSSRFPolicy, PolicyConfigOptions};

// Block all known dangerous IPs
let policy = AntiSSRFPolicy::new(PolicyConfigOptions::ExternalOnlyLatest);

// Validate a request
let mut headers = vec![];
let allowed = policy.validate_request("https://api.example.com", &mut headers)?;
```

## Feature Flags

| Flag | Default | Description |
| --- | --- | --- |
| `reqwest-integration` | Yes | Enables `network` module with reqwest / reqwest-middleware support |

## References

- [crates.io](https://crates.io/crates/antissrf)
- [docs.rs](https://docs.rs/antissrf)
- [Standalone Repository](https://github.com/finn79426/AntiSSRF-rs)
- [Microsoft AntiSSRF Documentation](https://microsoft.github.io/AntiSSRF/)
