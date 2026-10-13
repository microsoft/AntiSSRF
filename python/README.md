## Microsoft AntiSSRF Library for Python

The Microsoft AntiSSRF Library for Python is a security-developed, exhaustively-tested library that provides robust URL validation to protect Python applications from Server-Side Request Forgery (SSRF) vulnerabilities. It integrates seamlessly with Python requests library, allowing developers to secure outbound HTTP requests with minimal code changes.

## How to Use

The AntiSSRF Library provides validation for different scenarios based on your trust requirements:

| Use Case | Description | Documentation Link |
| --- | --- | --- |
| **General Case** | The untrusted URL can belong to **any domain** or an **untrusted domain**. | [AntiSSRFPolicy](https://microsoft.github.io/AntiSSRF/python-api/antissrfpolicy) |
| **Azure Key Vault Domain** | The untrusted URL must be an **Azure Key Vault endpoint**. | [URIValidator.in_azure_keyvault_domain](https://microsoft.github.io/AntiSSRF/python-api/urivalidator/inazurekeyvaultdomain) |
| **Azure Storage Domain** | The untrusted URL must be an **Azure Storage endpoint**. | [URIValidator.in_azure_storage_domain](https://microsoft.github.io/AntiSSRF/python-api/urivalidator/inazurestoragedomain) |
| **Allowlist of Trusted Domains** | The untrusted URL must belong to a **specific, trusted domain**. | [URIValidator.in_domain](https://microsoft.github.io/AntiSSRF/python-api/urivalidator/indomain) |

## Key Features

* **SSRF Attack Prevention** - Blocks malicious server-side request forgery attempts

* **Private Network Protection** - Separate built-in configuration options for internal vs. external address HTTP clients

* **DNS Rebinding Protection** - Guards against DNS-based attacks

* **Redirect Protection** - Re-validates on all redirects to prevent bypass attempts

* **Protocol Validation** - Ensures only safe protocols are used

* **Fully Customizable** - Configure domain allowlists, IP ranges, headers, and validation policies

## Additional Documentation

Explore our comprehensive documentation to get the most out of Microsoft AntiSSRF:

### Getting Started
- [Microsoft AntiSSRF Documentation](https://microsoft.github.io/AntiSSRF/)
- [Quick Start Guide](https://microsoft.github.io/AntiSSRF/getting-started)
- [Security Best Practices](https://microsoft.github.io/AntiSSRF/getting-started#best-practices)
- [Frequently Asked Questions](https://microsoft.github.io/AntiSSRF/faq)
- [Changelog](https://microsoft.github.io/AntiSSRF/python-api/changelog)

### API Documentation
- [Complete Python API Documentation](https://microsoft.github.io/AntiSSRF/python-api)
- [AntiSSRF Python session](https://microsoft.github.io/AntiSSRF/python-api/antissrfpolicy/methods/getantissrfsession)
- [AntiSSRFPolicy](https://microsoft.github.io/AntiSSRF/python-api/antissrfpolicy)
- [URIValidator](https://microsoft.github.io/AntiSSRF/python-api/urivalidator)

## Feedback & Contributing

We welcome feedback and contributions from the community! Here's how you can get involved:

- **Report Issues**: [GitHub Issues](https://github.com/Microsoft/AntiSSRF/issues) - Report bugs or request new features
- **Contribute**: [Contributing Guide](https://github.com/Microsoft/AntiSSRF/blob/main/CONTRIBUTING.md) - Learn how to contribute to the project
- **Contact**: [antissrf-oss@microsoft.com](mailto:antissrf-oss@microsoft.com) - Direct email for questions and feedback

## Support Policy

For support inquiries, contact [antissrf-oss@microsoft.com](mailto:antissrf-oss@microsoft.com).