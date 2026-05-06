const express = require('express');
const http = require('http');
const { AntiSSRFPolicy, PolicyConfigOptions } = require('@microsoft/antissrf');

const app = express();
const policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);
const agent = policy.getHttpAgent();

app.get('/fetch', (req, res) => {
    try {
        const userUrl = new URL(req.query.url);
        http.get(userUrl, { agent }, (proxyRes) => {
            let data = '';
            proxyRes.on('data', (chunk) => data += chunk);
            proxyRes.on('end', () => res.send(`Successfully fetched: ${data}`));
        }).on('error', (err) => {
            res.status(500).send(`AntiSSRF Blocked: ${err.message}`);
        });
    } catch (e) {
        res.status(400).send("Invalid URL format");
    }
});

app.listen(3000, () => console.log('Victim server running on port 3000'));