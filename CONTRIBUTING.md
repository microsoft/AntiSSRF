# Contributing to AntiSSRF

Thank you for your interest in contributing to the AntiSSRF project! This guide will help you get started.

## Development Setup

1. Clone the repository
2. Install dependencies for your target language (C# or Node.js)
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Updating IP Address Ranges

The IP address ranges are maintained in [`config/IPAddressRanges.json`](config/IPAddressRanges.json) and automatically generated into language-specific files.

### Prerequisites
Install `jq`: `brew install jq` (macOS) or `sudo apt-get install jq` (Linux)

### Process
1. **Edit** [`config/IPAddressRanges.json`](config/IPAddressRanges.json)
2. **Regenerate** the code files:
   ```bash
   ./scripts/build-ip-ranges-nodejs.sh
   ./scripts/build-ip-ranges-cs.sh
   ```
3. **Commit** all changes (JSON + generated files):
   ```bash
   git add config/IPAddressRanges.json nodejs/config/IPAddressRanges.ts csharp/config/IPAddressRanges.cs
   git commit -m "Update IP address ranges"
   ```

**Important**: The GitHub Actions workflow will fail if generated files don't match the source JSON.
