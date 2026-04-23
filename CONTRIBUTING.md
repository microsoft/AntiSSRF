# Contributing to AntiSSRF

Thank you for your interest in contributing to the AntiSSRF project! This guide will help you get started.

## Development Setup

### C# AntiSSRF Library
From the `./csharp` directory:

**Prerequisites:**
- .NET 8.0 SDK or later

**Commands:**
- **Build:** `dotnet build Microsoft.Security.AntiSSRF.sln`
- **Unit tests:** `dotnet test`

### Node.js (TypeScript)
From the `./nodejs` directory:

**Prerequisites:**
- Node.js 20+

**Commands:**
- **Install dependencies:** `npm install`
- **Build TypeScript:** `npm run build`
- **Unit tests:** `npm test`
- **Lint code:** `npm run lint`
- **Format code:** `npm run format`

## Updating IP Address Ranges or Domains

The IP address ranges are maintained in [`config/IPAddressRanges.json`](config/IPAddressRanges.json) and automatically generated into language-specific files.

The Azure SDK domains are maintained in [`config/Domains.json`](config/Domains.json) and automatically generated into language-specific files.

**Prerequisites:**
- `jq`: `brew install jq` (macOS) or `sudo apt-get install jq` (Linux)

**Commands:**
- **Regenerate IP Address Ranges:**
```bash
./scripts/build-ip-ranges-cs.sh
./scripts/build-ip-ranges-nodejs.sh
```
- **Regenerate Domains:**
```bash
./scripts/build-domains-cs.sh
./scripts/build-domains-nodejs.sh
```

**Important**: The GitHub Actions workflow will fail if generated files don't match the source JSON.
