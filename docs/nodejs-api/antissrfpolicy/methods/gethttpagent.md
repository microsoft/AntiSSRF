---
layout: default
title: getHttpAgent
parent: Methods
grand_parent: AntiSSRFPolicy
great_grand_parent: Node.js API Reference
nav_order: 1
description: "getHttpAgent method documentation"
---

# AntiSSRFPolicy.getHttpAgent Method

## Definition

Builds an `http.Agent` that will enforce the policy on all outgoing requests.

```js
getHttpAgent(options?: http.AgentOptions): void
```

### Parameters

`options`: `http.AgentOptions`

* The optional `http.AgentOptions` to pass to the new agent.

### Errors

`AntiSSRFError`
* The function `lookup` is included in `options`.

### Security Notes
* The agents utilizes `lookup` function to apply the policy. Attempts to overwrite the `lookup` function will result in errors.
* While not explicitly blocked, any use of proxies, like with `proxyEnv` in `options` or in clients that use the agents, will bypass the protections provided with the AntiSSRF library.
