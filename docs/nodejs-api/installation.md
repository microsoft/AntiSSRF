---
layout: default
title: Installation
parent: Node.js API Reference
nav_order: 1
description: "Setup and import instructions for the AntiSSRF Node.js library"
---

# Installation
{: .no_toc }

Setup and import instructions for the AntiSSRF Node.js library.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Package Installation

Install the AntiSSRF library via npm:

```bash
npm install @microsoft/antissrf
```

### Prerequisites

- Node.js 16+ or higher
- npm, yarn, or pnpm package manager

### Version Compatibility

The AntiSSRF library supports:
- **Node.js**: 16.x, 18.x, 20.x, 22.x
- **TypeScript**: 4.5+ (optional)
- **ES Modules**: Full support
- **CommonJS**: Full support

---

## Import Methods

### ES6 Modules (Recommended)

```javascript
// Import all main classes
import { AntiSSRFPolicy, UriValidator, PolicyConfigOptions } from '@microsoft/antissrf';

// Import specific classes only
import { AntiSSRFPolicy } from '@microsoft/antissrf';
import { UriValidator } from '@microsoft/antissrf';

// Import with custom names
import { AntiSSRFPolicy as Policy } from '@microsoft/antissrf';
```

### CommonJS

```javascript
// Import all main classes
const { AntiSSRFPolicy, UriValidator, PolicyConfigOptions } = require('@microsoft/antissrf');

// Import entire module
const AntiSSRF = require('@microsoft/antissrf');
const policy = new AntiSSRF.AntiSSRFPolicy(AntiSSRF.PolicyConfigOptions.ExternalOnlyV1);
```

### TypeScript

```typescript
import { 
  AntiSSRFPolicy, 
  UriValidator, 
  PolicyConfigOptions,
  AntiSSRFException 
} from '@microsoft/antissrf';

// Type imports (for type annotations only)
import type { PolicyConfig } from '@microsoft/antissrf';
```

---

## Quick Start

Once installed, you can immediately start using the library:

```javascript
import { AntiSSRFPolicy, PolicyConfigOptions } from '@microsoft/antissrf';

// Create a new policy with recommended settings
const policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1);

// Use the policy to validate requests
const url = 'https://api.example.com/data';
if (policy.isAllowed(url)) {
  // Safe to make the request
  const response = await fetch(url);
}
```

---

## Troubleshooting

### Common Installation Issues

**Error: Module not found**
```bash
# Clear npm cache and reinstall
npm cache clean --force
rm -rf node_modules package-lock.json
npm install
```

**TypeScript errors**
```bash
# Install TypeScript definitions if needed
npm install --save-dev @types/node
```

**ES Module issues**
```json
// Add to package.json
{
  "type": "module"
}
```

### Verification

Test your installation:

```javascript
import { UriValidator } from '@microsoft/antissrf';

console.log('AntiSSRF installed successfully!');
console.log('Azure Storage test:', UriValidator.inAzureStorageDomain('https://test.blob.core.windows.net'));
```