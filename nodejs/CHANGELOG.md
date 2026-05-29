# Changelog

All notable changes to the AntiSSRF Node.js Library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.0](https://github.com/microsoft/AntiSSRF/releases/tag/nodejs-1.0.0) (2026-05-29)

Initial version of the open-source Microsoft AntiSSRF Library for Node.js.
* `AntiSSRFPolicy` - Used to customize protection policies applied on all requests by `node:http` Agents from `getHttpsAgent`.
* `getHttpsAgent` - Returns an implementation of Node.js `Agent` that applies security policies on all requests.
* `URIValidator` - Provides three methods for validating the domain of a URL: `inAzureKeyVaultDomain`, `inAzureStorageDomain`, and `inDomain`.
