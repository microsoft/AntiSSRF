# Changelog

All notable changes to the AntiSSRF .NET Library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.1](https://github.com/microsoft/AntiSSRF/releases/tag/dotnet-1.0.1) (2026-10-08)

### Fixed

* Fixed single-threaded sychronization context bug.
* Set `UseProxy` to `false` on handlers to help prevent customers from unintentionally bypassing AntiSSRF protections by setting an underlying proxy on the system.
* Enforced better consistency in `InDomain` to return `false` on IP address hosts.
* Maintain context when throwing `InnerException`.

### Security

* Mitigates a vulnerability where an improperly parsed IPv6 address scope could be considered `InDomain` of a DNS host name.

### New Contributors

Thank you to all our new contributors!

List coming soon.

## [v1.0.0](https://github.com/microsoft/AntiSSRF/releases/tag/dotnet-1.0.0) (2026-05-06)

Initial version of the open-source Microsoft AntiSSRF Library for .NET.
* `AntiSSRFPolicy` - Used to customize protection policies applied on all requests by `AntiSSRFHandler`.
* `AntiSSRFHandler` - Implementation of .NET `HttpMessageHandler` that applies security policies on all requests.
* `URIValidator` - Provides three methods for validating the domain of a URL: `InAzureKeyVaultDomain`, `InAzureStorageDomain`, and `InDomain`.

## Thank you to all our original developers!

We are deeply grateful to our original contributors. We truly couldn't have gotten where we are today without you. Your years of dedicated hard work made this entire project possible. Thank you so much!

* [Arjun Gopalakrishna](https://github.com/247arjun)
* [Emmie Teng](https://github.com/EmmieBunnie)
* Kyndell Geddis
* [Leah Restad](https://github.com/leah-restad)
* [Likhitesh S](https://github.com/user007png)
* [Michael Hendrickx](https://github.com/ndrix)
* [Stephen Toub](https://github.com/stephentoub)
* [Susan Krkasharian](https://github.com/susan-krkasharian)
