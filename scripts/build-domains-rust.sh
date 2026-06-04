#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Script to build src/domains.rs from config/Domains.json
# Generates a Rust module with static domain constants

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JSON_FILE="$SCRIPT_DIR/../config/Domains.json"
RS_FILE="$SCRIPT_DIR/../rust/src/domains.rs"

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed."
    exit 1
fi

if [[ ! -f "$JSON_FILE" ]]; then
    echo "Error: Domains.json not found in $SCRIPT_DIR/../config/"
    exit 1
fi

# Generate Rust file
cat > "$RS_FILE" << 'EOF'
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

EOF

# Generate Azure Key Vault domains
{
    echo "/// Azure Key Vault service domains across all public Azure environments."
    echo "///"
    echo "/// Covers vault and managed-HSM endpoints for:"
    echo "///"
    echo "/// | Suffix | Cloud |"
    echo "/// |--------|-------|"
    echo "/// | \`vault.azure.net\` | Global Azure |"
    echo "/// | \`vault.azure.cn\` | Azure China |"
    echo "/// | \`vault.usgovcloudapi.net\` | Azure US Government |"
    echo "///"
    echo "/// Hostnames containing \`--\` are rejected by [\`crate::URIValidator::in_azure_key_vault_domain\`]"
    echo "/// per Azure naming restrictions."
    echo "pub const AZURE_KEY_VAULT_DOMAINS: &[&str] = &["
    jq -r '.azureKeyVault.domains[] | "    \"" + . + "\","' "$JSON_FILE"
    echo "];"
    echo ""
} >> "$RS_FILE"

# Generate Azure Storage domains
{
    echo "/// Azure Storage service domains across all public Azure environments."
    echo "///"
    echo "/// Covers Blob, Web, Data Lake Storage Gen2 (DFS), File, Queue, and Table"
    echo "/// endpoints for:"
    echo "///"
    echo "/// | Suffix | Cloud |"
    echo "/// |--------|-------|"
    echo "/// | \`*.core.windows.net\` | Global Azure |"
    echo "/// | \`*.storage.azure.net\` | Global Azure (alternative) |"
    echo "/// | \`*.core.usgovcloudapi.net\` | Azure US Government |"
    echo "/// | \`*.core.chinacloudapi.cn\` | Azure China |"
    echo "///"
    echo "/// Like [\`AZURE_KEY_VAULT_DOMAINS\`], hostnames containing \`--\` are rejected"
    echo "/// by [\`crate::URIValidator::in_azure_storage_domain\`] per Azure naming restrictions."
    echo "pub const AZURE_STORAGE_DOMAINS: &[&str] = &["
    jq -r '.azureStorage.domains[] | "    \"" + . + "\","' "$JSON_FILE"
    echo "];"
} >> "$RS_FILE"

echo "Successfully generated $RS_FILE"
