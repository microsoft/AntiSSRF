---
layout: default
title: UriValidator
parent: Node.js API Reference
nav_order: 3
description: "Static utility methods for domain and service validation"
---

# UriValidator Class
{: .no_toc }

Static utility class for validating URIs against domains and Azure services.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

The `UriValidator` class provides static methods for validating URIs without requiring a policy instance. These utilities are perfect for quick domain checks and Azure service validation.

```javascript
import { UriValidator } from '@microsoft/antissrf';

// No instantiation needed - all methods are static
const isValid = UriValidator.inDomain(url, 'example.com');
```

---

## Domain Validation Methods

### inDomain()

```typescript
UriValidator.inDomain(uri: string | URL, domain: string | string[]): boolean
```

Check if a URI belongs to the specified domain(s).

**Parameters:**
- `uri` (string | URL): The URI to check
- `domain` (string | string[]): Domain or array of domains to validate against

**Returns:**
- `boolean`: True if URI belongs to any of the specified domains

**Examples:**

```javascript
// Single domain validation
const isValid = UriValidator.inDomain('https://api.example.com/data', 'example.com');
console.log(isValid); // true

// Multiple domains
const domains = ['example.com', 'api.example.com', 'cdn.example.com'];
const isValidMulti = UriValidator.inDomain('https://cdn.example.com/assets/logo.png', domains);
console.log(isValidMulti); // true

// Subdomain matching
const hasSubdomain = UriValidator.inDomain('https://blog.example.com', 'example.com');
console.log(hasSubdomain); // true

// Different domain
const isDifferent = UriValidator.inDomain('https://malicious.com', 'example.com');
console.log(isDifferent); // false
```

### Wildcard Domain Patterns

```javascript
// Wildcard subdomain matching
const patterns = ['*.example.com', 'api.*.example.com'];
const isWildcardMatch = UriValidator.inDomain('https://v1.api.dev.example.com', patterns);
```

---

## Azure Service Validation

### inAzureStorageDomain()

```typescript
UriValidator.inAzureStorageDomain(uri: string | URL): boolean
```

Check if a URI belongs to an Azure Storage domain across all Azure clouds.

**Parameters:**
- `uri` (string | URL): The URI to validate

**Returns:**
- `boolean`: True if URI is an Azure Storage endpoint

**Supported Azure Storage Services:**
- **Blob Storage**: `*.blob.core.windows.net`
- **File Storage**: `*.file.core.windows.net`
- **Queue Storage**: `*.queue.core.windows.net`
- **Table Storage**: `*.table.core.windows.net`
- **Data Lake**: `*.dfs.core.windows.net`

**Azure Cloud Support:**
- **Public Cloud**: `*.core.windows.net`
- **US Government**: `*.core.usgovcloudapi.net`
- **China**: `*.core.chinacloudapi.cn`
- **Private Endpoints**: `*.privatelink.blob.core.windows.net`

**Examples:**

```javascript
// Public Azure Storage
const blobUrl = 'https://mystorageaccount.blob.core.windows.net/container/file.txt';
console.log(UriValidator.inAzureStorageDomain(blobUrl)); // true

// Azure File Storage
const fileUrl = 'https://mystorageaccount.file.core.windows.net/share/directory/file.txt';
console.log(UriValidator.inAzureStorageDomain(fileUrl)); // true

// US Government Cloud
const govUrl = 'https://mystorageaccount.blob.core.usgovcloudapi.net/container/file.txt';
console.log(UriValidator.inAzureStorageDomain(govUrl)); // true

// China Cloud
const chinaUrl = 'https://mystorageaccount.blob.core.chinacloudapi.cn/container/file.txt';
console.log(UriValidator.inAzureStorageDomain(chinaUrl)); // true

// Private Endpoint
const privateUrl = 'https://mystorageaccount.privatelink.blob.core.windows.net/container/file.txt';
console.log(UriValidator.inAzureStorageDomain(privateUrl)); // true

// Non-Azure Storage
const nonAzure = 'https://example.com/storage/file.txt';
console.log(UriValidator.inAzureStorageDomain(nonAzure)); // false
```

### inAzureKeyVaultDomain()

```typescript
UriValidator.inAzureKeyVaultDomain(uri: string | URL): boolean
```

Check if a URI belongs to an Azure Key Vault domain.

**Parameters:**
- `uri` (string | URL): The URI to validate

**Returns:**
- `boolean`: True if URI is an Azure Key Vault endpoint

**Supported Key Vault Clouds:**
- **Public Cloud**: `*.vault.azure.net`
- **US Government**: `*.vault.usgovcloudapi.net`
- **China**: `*.vault.azure.cn`
- **Germany**: `*.vault.microsoftazure.de`

**Examples:**

```javascript
// Public Azure Key Vault
const vaultUrl = 'https://myvault.vault.azure.net/secrets/secret-name/version';
console.log(UriValidator.inAzureKeyVaultDomain(vaultUrl)); // true

// US Government Key Vault
const govVaultUrl = 'https://myvault.vault.usgovcloudapi.net/keys/key-name';
console.log(UriValidator.inAzureKeyVaultDomain(govVaultUrl)); // true

// China Key Vault
const chinaVaultUrl = 'https://myvault.vault.azure.cn/certificates/cert-name';
console.log(UriValidator.inAzureKeyVaultDomain(chinaVaultUrl)); // true

// Non-Key Vault
const nonVault = 'https://example.com/secrets/secret';
console.log(UriValidator.inAzureKeyVaultDomain(nonVault)); // false
```

---

## Advanced Usage Examples

### Combining Validations

```javascript
import { UriValidator } from '@microsoft/antissrf';

function validateTrustedUri(uri) {
  const trustedDomains = ['example.com', 'api.example.com', 'trusted-partner.com'];
  
  // Check if it's a trusted domain
  if (UriValidator.inDomain(uri, trustedDomains)) {
    return { valid: true, reason: 'Trusted domain' };
  }
  
  // Check if it's Azure Storage (always trusted)
  if (UriValidator.inAzureStorageDomain(uri)) {
    return { valid: true, reason: 'Azure Storage' };
  }
  
  // Check if it's Azure Key Vault (always trusted)
  if (UriValidator.inAzureKeyVaultDomain(uri)) {
    return { valid: true, reason: 'Azure Key Vault' };
  }
  
  return { valid: false, reason: 'Untrusted domain' };
}

// Usage
const result = validateTrustedUri('https://mystorageaccount.blob.core.windows.net/data');
console.log(result); // { valid: true, reason: 'Azure Storage' }
```

### Batch Validation

```javascript
function validateMultipleUris(uris) {
  return uris.map(uri => ({
    uri,
    isAzureStorage: UriValidator.inAzureStorageDomain(uri),
    isAzureKeyVault: UriValidator.inAzureKeyVaultDomain(uri),
    isTrustedDomain: UriValidator.inDomain(uri, ['example.com', 'api.example.com'])
  }));
}

const urls = [
  'https://mystorageaccount.blob.core.windows.net/container/file.txt',
  'https://myvault.vault.azure.net/secrets/secret',
  'https://api.example.com/data',
  'https://malicious.com/evil'
];

const results = validateMultipleUris(urls);
console.log(results);
```

### Custom Domain Lists

```javascript
class CustomUriValidator {
  static TRUSTED_DOMAINS = [
    'example.com',
    'api.example.com',
    '*.cdn.example.com',
    'partner-api.com'
  ];
  
  static isTrustedDomain(uri) {
    return UriValidator.inDomain(uri, this.TRUSTED_DOMAINS) ||
           UriValidator.inAzureStorageDomain(uri) ||
           UriValidator.inAzureKeyVaultDomain(uri);
  }
  
  static validateBusinessLogic(uri) {
    if (!this.isTrustedDomain(uri)) {
      throw new Error(`Untrusted domain: ${new URL(uri).hostname}`);
    }
    return true;
  }
}
```