---
layout: default
title: follow-redirects
parent: Samples
grand_parent: Node.js API Reference
description: "AntiSSRF agent with follow-redirects"
---

# AntiSSRFPolicy with the follow-redirects Library

## Introduction

The [follow-redirects library](https://github.com/follow-redirects/follow-redirects/blob/694d6b47a42bc8377e5ef1480394de451e16bd5b/README.md) is a commonly used request library to extend Node.js http(s) functionality with the ability to automatically follow redirects. The example below shows how you can use the follow-redirects library with the AntiSSRF Node.js library.

> [!NOTE]
> Be careful if you use the `wrap` method, since this could lead to requests without a NodeJS agent, and therefore without the `AntiSSRFPolicy` applied.

{: .important }
> Be careful of options that can bypass AntiSSRF protections:
> * Changing the `adapter` option could lead to requests without a Node.js agent, and therefore without the `AntiSSRFPolicy` applied.
> * Like the AntiSSRF agents themselves, using a custom `lookup` function will bypass the IP address validations from `AntiSSRFPolicy`.
> * Using `proxy` with AntiSSRF will largely not work, since the `AntiSSRFPolicy` will not be used once control is passed to the proxy.

## Example

follow-redirects allows you to [make requests](https://github.com/follow-redirects/follow-redirects/blob/694d6b47a42bc8377e5ef1480394de451e16bd5b/README.md#per-request-options) either with the option `agent`, like in normal NodeJS requests, or the option `agents`, with both `http` and `https` agents for use in redirects.

### Setup

Set up the AntiSSRF policy for your specific use case, then get the AntiSSRF agents from the policy.

```TypeScript
import { AntiSSRFPolicy, PolicyConfigOptions } from '@azuresecurity/antissrf';
import { http, https } from "follow-redirects";

const policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);

const agents = {
    httpAgent: policy.getHttpAgent(),
    httpsAgent: policy.getHttpsAgent({ keepAlive: true })
}
```

### Use the AntiSSRF Agents for Requests

Every request to an endpoint with untrusted input should include the AntiSSRF agents.

```TypeScript
const httpsReq = https.get(
    "<some_https_url_constructed_with_untrusted_input>",
    {
        agents: agents,
        auth: {
            username: 'janedoe',
            password: 's00pers3cret'
        }
    },
    (res) => {
        /**
         *  Will get here if the untrusted URL does NOT direct the request to an internal,
         *  sensitive IP address
         */
    });

httpsReq.on("error", (err) => {
    /**
     * Will get here if the untrusted URL directs the request to an internal,
     * sensitive IP address
     */
});

httpsReq.end();
```

> [!NOTE]
> If you want different examples or if you find any bug while using `AntiSSRFPolicy` with follow-redirects, please let us know at [antissrf@microsoft.com](mailto:antissrf@microsoft.com).
