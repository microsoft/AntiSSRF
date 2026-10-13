# Changelog

All notable changes to the AntiSSRF Python Library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.0](https://github.com/microsoft/AntiSSRF/releases/tag/python-1.0.0) (2026-10-13)

Initial version of the open-source Microsoft AntiSSRF Library for Node.js.
* `AntiSSRFPolicy` - Used to customize protection policies applied on all requests by Python `requests` library.
* `get_antissrf_session` - Returns an implementation of Python `requests session` that applies security policies on all requests.
* `URIValidator` - Provides three methods for validating the domain of a URL: `in_azure_keyvault_domain`, `in_azure_storage_domain`, and `in_domain`.
