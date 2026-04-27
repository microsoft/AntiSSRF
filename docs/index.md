---
layout: default
title: Home
nav_order: 1
description: "AntiSSRF Documentation - Protect your applications from SSRF attacks"
permalink: /
---

## What is Server-Side Request Forgery (SSRF)?

Server-Side Request Forgery (also known as SSRF) is a critical web security vulnerability in which an attacker can manipulate the server-side application to make network requests to an arbitrary endpoint. Through this vulnerability, the attacker manipulates the target web server to connect to internal, sensitive networks or exfiltrate sensitive data to an untrusted endpoint on the Internet.

SSRF can lead (but not limited) to:
- Exposure of internal services
- Leakage of sensitive data
- Service disruption
- Remote code execution

### What is "Untrusted" Input?

**All incoming HTTP requests are untrusted.** Any data originating from outside your service's immediate trust boundary must be treated as potentially malicious. This includes:

- User-provided URLs, filenames, or identifiers
- Data from external APIs, webhooks, or partner services
- Configuration values, metadata, or file contents that users can influence
- Requests from your own service's backend apps or other components within the same environment (Query parameters, headers, or form fields, etc)

Even data that doesn't initially appear to be a URL can become one. For example, a workspace name or resource identifier that gets concatenated into a URL. All untrusted input used in URL construction MUST be validated.

## What is the AntiSSRF Library?

AntiSSRF is a security library available for multiple languages that provides robust URI validation to prevent Server-Side Request Forgery (SSRF) vulnerabilities in code. It is aimed at being an easy-to-drop-in library with a minimal impact on the developers.

A common scenario in many online services is handling requests from customers containing customer-supplied strings that are, or are used to construct a URI. These strings are often not validated properly, leading to vulnerabilities such as Server-Side Request Forgery which can result in token theft.

### How the AntiSSRF Library Helps

- Automatically validates URLs and network connections
- Reduces developer effort and risk of insufficient validation
- Provides an agent that ensures HTTP requests cannot reach internal or sensitive IP addresses

## Supported Languages and Frameworks

| Language / Framework | Documentation | Notes |
| --- | --- | --- |
| .NET Framework and Core | [AntiSSRF C# Library](csharp-api/) | For web clients using `HttpClient` objects |
| JavaScript/TypeScript | [AntiSSRF JavaScript Library](nodejs-api/) | For requests using NodeJS HTTP(S) Agents |
| Golang | N/A | coming soon |
| Python | N/A | coming soon |

{: .note }
> For any questions regarding the usage of this library or for more information, please contact [antissrf-oss@microsoft.com](mailto:antissrf-oss@microsoft.com).