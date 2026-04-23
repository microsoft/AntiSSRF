---
layout: default
title: AntiSSRFPolicy
parent: Node.js API Reference
description: "Main policy configuration class for SSRF protection"
has_children: true
---

# AntiSSRFPolicy Class

## Use Case

You would use this class whenever you are accessesing a URL that can belong to any **any domain** or **some untrusted domain**.

When you are accessing a URL that was constructed with external input (user input or input from other services), you need to make sure the final construted URL cannot be abused to access unexpected internal endpoints. This class allows you to use built-in configurations or customize your own policy, then provides an `http.Agent` and `https.Agent` that will enforce that policy across all requests and redirects.

{: .note }
> * If you instead expect the domain to be a **specific, trusted domain**, see inDomain.
> * If you instead expect the URL to be an **Azure Storage endpoint**, see inAzureStorageDomain.
> * If you instead expect the URL to be an **Azure Key Vault endpoint**, see inAzureKeyVaultDomain.

## Definition

Represents a customizable security policy and provides HTTP(S) agents to ensure all outgoing requests match the security policy.

## Constructors

| Constructor | Description |
| --- | --- |
| `AntiSSRFPolicy(config: PolicyConfigOptions)` | Initializes a new instance of the `AntiSSRFPolicy` class with the specified initial configuration. |

## Properties

| Property | Description |
| --- | --- |
| allowPlainTextHttp | Determines whether HTTPS is required or HTTP is allowed. |
| denyAllUnspecifiedIPs | Determines whether all IP addresses should be blocked by default or only `deniedAddresses` IP addresses should be blocked. |
| addXFFHeader | Determines whether to add the `X-Forwarded-For` header to requests that are missing the header. |
| allowedAddresses | List of IPv4/IPv6 addresses or subnets that are explicitly allowed by the policy. |
| deniedAddresses | List of IPv4/IPv6 addresses or subnets that are explicitly blocked by the policy. |
| requiredHeaders | List of headers that are required to be present in all outgoing requests. |
| deniedHeaders | List of headers that are forbidden from being included in outgoing requests. |

## Policy Customization Methods

| Method | Description |
| --- | --- |
| addAllowedAddresses(networks: string[]) | Adds to a list of IPv4/IPv6 addresses or subnets to be explicitly allowed by the policy. |
| addDeniedAddresses(networks: string[]) | Adds to a list of IPv4/IPv6 addresses or subnets to be explicitly blocked by the policy. |
| addRequiredHeaders(headers: string[]) | Adds to the list of headers explicitly required by the policy. Outgoing requests that are missing a required header will be blocked. |
| addDeniedHeaders(headers: string[]) | Adds to the list of headers explicitly blocked by the policy. Outgoing requests that include a denied header will be blocked. |

## Policy Use Methods

| Method | Description |
| --- | --- |
| getHttpsAgent(agentOptions?: any): https.Agent | Builds an `http.Agent` that will enforce the policy on all outgoing requests. |
| getHttpAgent(agentOptions?: any): http.Agent | Builds an `https.Agent` that will enforce the policy on all outgoing requests. |
