## Microsoft AntiSSRF for Node.js

The Microsoft AntiSSRF library for Node.js is a security-developed, exhaustively-tested library that provides robust URL validation to protect Node.js applications from Server-Side Request Forgery (SSRF) vulnerabilities. It integrates seamlessly with Node.js HTTP/HTTPS agents, allowing developers to secure outbound HTTP requests with minimal code changes.

## How to Use

The AntiSSRF library provides validation for different scenarios based on your trust requirements:

| Use Case | Description | Documentation Link |
|----------|-------------|-------------------|
| **Any Domain** | Validate untrusted URLs belonging to any domain | [AntiSSRFPolicy](https://microsoft.github.io/AntiSSRF/nodejs-api/antissrfpolicy/) |
| **Azure Storage Domain** | Validate that URLs are Azure Storage endpoints | [inAzureStorageDomain](https://microsoft.github.io/AntiSSRF/nodejs-api/urivalidator/inazurestoragedomain/) |
| **Azure Key Vault Domain** | Validate URLs are Azure Key Vault endpoints | [inAzureKeyVaultDomain](https://microsoft.github.io/AntiSSRF/nodejs-api/urivalidator/inazurekeyvaultdomain/) |
| **Allowlist of Trusted Domains** | Validate that URLs belong to your custom allowlist of trusted domains | [inDomain](https://microsoft.github.io/AntiSSRF/nodejs-api/urivalidator/indomain/) |

## Key Features

🛡️ **SSRF Attack Prevention** - Blocks malicious server-side request forgery attempts

🚫 **Private Network Protection** - - Separate built-in configuration options for internal vs. external address HTTP clients

🔒 **DNS Rebinding Protection** - Guards against DNS-based attacks

🔄 **Redirect Protection** - Re-validates on all redirects to prevent bypass attempts

🌐 **Protocol Validation** - Ensures only safe protocols are used

⚙️ **Fully Customizable** - Configure domain allowlists, IP ranges, headers, and validation policies

## Additional Documentation

Explore our comprehensive documentation to get the most out of Microsoft AntiSSRF:

### Getting Started
- 📖 **Documentation Home**: [Microsoft AntiSSRF Documentation](https://microsoft.github.io/AntiSSRF/)
- 🚀 **Quick Start Guide**: [Getting Started with Node.js](https://microsoft.github.io/AntiSSRF/getting-started/)
- 💡 **Best Practices**: [Security Best Practices](https://microsoft.github.io/AntiSSRF/getting-started/#best-practices)
- ❓ **FAQ**: [Frequently Asked Questions](https://microsoft.github.io/AntiSSRF/faq/)
- 🔄 **Changelog**: [Version History and Updates](https://microsoft.github.io/AntiSSRF/nodejs-api/changelog/)

### API Documentation
- 🔧 **JavaScript API Reference**: [Complete Node.js API Documentation](https://microsoft.github.io/AntiSSRF/nodejs-api/)
- 🛡️ **AntiSSRFHandler**: [HTTP Handler Documentation](https://microsoft.github.io/AntiSSRF/nodejs-api/antissrfhandler/)
- ⚙️ **AntiSSRFPolicy**: [Policy Configuration Guide](https://microsoft.github.io/AntiSSRF/nodejs-api/antissrfpolicy/)
- 🔍 **URIValidator**: [URL Validation Methods](https://microsoft.github.io/AntiSSRF/nodejs-api/urivalidator/)

## Feedback & Contributing

We welcome feedback and contributions from the community! Here's how you can get involved:

- 🐛 **Report Issues**: [GitHub Issues](https://github.com/Microsoft/AntiSSRF/issues) - Report bugs or request new features
- 🤝 **Contribute**: [Contributing Guide](https://github.com/Microsoft/AntiSSRF/blob/main/CONTRIBUTING.md) - Learn how to contribute to the project
- 📧 **Contact**: antissrf-oss@microsoft.com - Direct email for questions and feedback

## Support Policy

For support inquiries, contact antissrf-oss@microsoft.com.