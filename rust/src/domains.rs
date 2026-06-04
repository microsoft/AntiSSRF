// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Well-known Azure service domains for URL validation.
//!
//! This module provides static domain lists used by [`crate::URIValidator`] to
//! recognise Azure Key Vault and Azure Storage endpoints.  The lists cover
//! all public Azure sovereign clouds (global Azure, China, US Government).
//!
//! # Usage
//!
//! These constants are typically consumed indirectly through
//! [`crate::URIValidator::in_azure_key_vault_domain`] and
//! [`crate::URIValidator::in_azure_storage_domain`], but they are also public
//! in case you need to build custom domain checks.
//!
//! This file is auto-generated from `config/Domains.json`.
//! Do not edit manually; run `scripts/build-domains-rust.sh` to regenerate.

/// Azure Key Vault service domains across all public Azure environments.
///
/// Covers vault and managed-HSM endpoints for:
///
/// | Suffix | Cloud |
/// |--------|-------|
/// | `vault.azure.net` | Global Azure |
/// | `vault.azure.cn` | Azure China |
/// | `vault.usgovcloudapi.net` | Azure US Government |
///
/// Hostnames containing `--` are rejected by [`crate::URIValidator::in_azure_key_vault_domain`]
/// per Azure naming restrictions.
pub const AZURE_KEY_VAULT_DOMAINS: &[&str] = &[
    "vault.azure.net",
    "managedhsm.azure.net",
    "vault.azure.cn",
    "managedhsm.azure.cn",
    "vault.usgovcloudapi.net",
    "managedhsm.usgovcloudapi.net",
];

/// Azure Storage service domains across all public Azure environments.
///
/// Covers Blob, Web, Data Lake Storage Gen2 (DFS), File, Queue, and Table
/// endpoints for:
///
/// | Suffix | Cloud |
/// |--------|-------|
/// | `*.core.windows.net` | Global Azure |
/// | `*.storage.azure.net` | Global Azure (alternative) |
/// | `*.core.usgovcloudapi.net` | Azure US Government |
/// | `*.core.chinacloudapi.cn` | Azure China |
///
/// Like [`AZURE_KEY_VAULT_DOMAINS`], hostnames containing `--` are rejected
/// by [`crate::URIValidator::in_azure_storage_domain`] per Azure naming restrictions.
pub const AZURE_STORAGE_DOMAINS: &[&str] = &[
    "blob.core.windows.net",
    "web.core.windows.net",
    "dfs.core.windows.net",
    "file.core.windows.net",
    "queue.core.windows.net",
    "table.core.windows.net",
    "blob.storage.azure.net",
    "web.storage.azure.net",
    "dfs.storage.azure.net",
    "file.storage.azure.net",
    "queue.storage.azure.net",
    "table.storage.azure.net",
    "blob.core.usgovcloudapi.net",
    "web.core.usgovcloudapi.net",
    "dfs.core.usgovcloudapi.net",
    "file.core.usgovcloudapi.net",
    "queue.core.usgovcloudapi.net",
    "table.core.usgovcloudapi.net",
    "blob.core.chinacloudapi.cn",
    "web.core.chinacloudapi.cn",
    "dfs.core.chinacloudapi.cn",
    "file.core.chinacloudapi.cn",
    "queue.core.chinacloudapi.cn",
    "table.core.chinacloudapi.cn",
];
