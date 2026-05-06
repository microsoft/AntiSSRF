const { AntiSSRFPolicy, PolicyConfigOptions } = require('@microsoft/antissrf');
const http = require('http');

async function runTest() {
    const policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);
    const agent = policy.getHttpAgent();
    const target = 'http://7f000001.01010101.rbndr.us/';

    console.log(`[AUDIT] Testing DNS Rebinding protection: ${target}`);

    const req = http.get(target, { agent }, (res) => {
        console.error("FAIL: Request allowed to private IP range.");
        process.exit(1);
    });

    req.on('error', (err) => {
        if (err.message.includes('disallowed by policy')) {
            console.log("PASS: Library successfully blocked the attempt.");
            process.exit(0);
        } else {
            console.error("ERROR: Unexpected error type:", err.message);
            process.exit(1);
        }
    });
}
runTest();