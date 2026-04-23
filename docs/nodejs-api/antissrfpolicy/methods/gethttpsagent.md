---
layout: default
title: getHttpsAgent
parent: Methods
grand_parent: AntiSSRFPolicy
great_grand_parent: Node.js API Reference
nav_order: 1
description: "getHttpsAgent method documentation"
---

# AntiSSRFPolicy.getHttpsAgent Method

## Definition

Builds an `https.Agent` that will enforce the policy on all outgoing requests.

```js
getHttpsAgent(options?: http.AgentOptions): void
```

### Parameters

`options`: `https.AgentOptions`

* The optional `https.AgentOptions` to pass to the new agent.

### Errors

`AntiSSRFError`
* The function `lookup` is included in `options`.

### Security Notes
* The agents utilizes `lookup` function to apply the policy. Attempts to overwrite the `lookup` function will result in errors.
* While not explicitly blocked, any use of proxies, like with `proxyEnv` in `options` or in clients that use the agents, will bypass the protections provided with the AntiSSRF library.
