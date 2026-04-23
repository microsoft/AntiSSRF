---
layout: default
title: Home
nav_order: 1
description: "AntiSSRF Documentation - Protect your applications from SSRF attacks"
permalink: /
---

# AntiSSRF Documentation

Welcome to the AntiSSRF library documentation. AntiSSRF is a security library that helps developers protect their applications from Server-Side Request Forgery (SSRF) attacks.

## Overview

AntiSSRF provides configurable policies to validate and filter outbound HTTP requests, preventing attackers from exploiting server-side functionality to access internal resources or perform unauthorized network requests.

## Features

- **IP Address Validation**: Block requests to internal/private IP ranges
- **Domain Filtering**: Validate requests against trusted domains
- **Azure Service Integration**: Built-in support for Azure Storage and Key Vault domains
- **Custom Policy Configuration**: Flexible configuration options
- **Multi-language Support**: Available for both .NET and Node.js

## Quick Links

- [Getting Started](getting-started.html) - Learn how to install and configure AntiSSRF
- [FAQ](faq.html) - Frequently asked questions
- [Changelog](changelog.html) - Release notes and version history

## Language Support

### .NET (C#)
- .NET Standard 2.0+
- .NET Framework 4.8+
- .NET 8.0+

### Node.js (TypeScript)
- Node.js 20+
- TypeScript support included
