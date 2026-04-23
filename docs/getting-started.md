---
layout: default
title: Getting Started
nav_order: 2
description: "Learn how to install and configure AntiSSRF in your application"
---

# Getting Started with AntiSSRF

This guide will help you quickly get started with AntiSSRF in your application.

## Installation

### .NET (C#)

Install the NuGet package:

```bash
dotnet add package Microsoft.Security.AntiSSRF
```

Or via Package Manager Console:

```powershell
Install-Package Microsoft.Security.AntiSSRF
```

### Node.js (TypeScript/JavaScript)

Install via npm:

```bash
npm install @microsoft/antissrf
```

## Basic Usage

### .NET Example

```csharp
using Microsoft.Security.AntiSSRF;

// Create a policy with recommended settings
var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1);

// Get the HTTP handler
using var handler = policy.GetHandler();
using var client = new HttpClient(handler);

// Make requests - internal/dangerous IPs will be blocked
var response = await client.GetAsync("https://api.example.com/data");
```

### Node.js Example

```typescript
import { AntiSSRFPolicy, PolicyConfigOptions } from '@microsoft/antissrf';

// Create a policy with recommended settings
const policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1);

// Use with your HTTP client
const response = await fetch('https://api.example.com/data', {
    // Policy configuration applied here
});
```

## Configuration Options

### Policy Types

- **`ExternalOnlyV1`**: Recommended for most applications - blocks internal networks
- **`ExternalOnlyLatest`**: Latest recommended settings - more restrictive
- **`InternalOnly`**: Blocks all IPs by default - you must allowlist specific ranges
- **`None`**: No restrictions by default - configure manually

### Custom Configuration

```csharp
var policy = new AntiSSRFPolicy(PolicyConfigOptions.None);

// Add custom allowed/denied IP ranges
policy.AddAllowedAddresses(["192.168.1.0/24"]);
policy.AddDeniedAddresses(["10.0.0.0/8"]);

// Configure headers
policy.AddRequiredHeaders(["X-API-Key"]);
policy.AddDeniedHeaders(["X-Dangerous-Header"]);
```

## Next Steps

- Check out the [FAQ](faq.html) for common questions
- Review the [Changelog](changelog.html) for version history
- Read the full API documentation in your IDE