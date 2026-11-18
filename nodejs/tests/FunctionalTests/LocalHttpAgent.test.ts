// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "assert";
import { Agent, createServer, Server } from "http";
import { AddressInfo } from "net";
import { http } from "follow-redirects";

import { AntiSSRFError, AntiSSRFPolicy, PolicyConfigOptions } from "../../src";

describe("HTTP agent - counted local requests", () => {
    let entry: Server;
    let internal: Server;
    let protectedAgent: Agent;
    let unsafeAgent: Agent;
    let entryOrigin: string;
    let internalOrigin: string;
    let internalPort: number;
    let entryHits = 0;
    let internalHits = 0;

    const listen = (server: Server, host: string) =>
        new Promise<number>((resolve, reject) => {
            server.once("error", reject);
            server.listen(0, host, () => {
                server.removeListener("error", reject);
                resolve((server.address() as AddressInfo).port);
            });
        });

    const close = (server?: Server) =>
        new Promise<void>((resolve, reject) => {
            if (!server?.listening) return resolve();
            server.closeAllConnections();
            server.close((error) => (error ? reject(error) : resolve()));
        });

    // Every URL in this file names a loopback literal. There is no external
    // DNS, public website, metadata endpoint, or fixed listening port.
    const get = (url: string, agent: Agent) =>
        new Promise<{ status: number; body: string }>((resolve, reject) => {
            const request = http.get(url, { agents: { http: agent }, maxRedirects: 3 }, (response) => {
                let body = "";
                response.setEncoding("utf8");
                response.on("data", (chunk: string) => (body += chunk));
                response.on("error", fail);
                response.on("end", () => {
                    clearTimeout(deadline);
                    resolve({ status: response.statusCode!, body });
                });
            });
            const deadline = setTimeout(() => {
                request.destroy(new Error("Local fixture request exceeded its deadline"));
            }, 3000);
            function fail(error: Error) {
                clearTimeout(deadline);
                request.destroy();
                reject(error);
            }
            request.on("error", fail);
        });

    const assertBlocked = async (request: () => Promise<unknown>) => {
        const before = internalHits;
        let error: unknown;
        try {
            await request();
        } catch (caught) {
            error = caught;
        }
        // A matching error cannot erase a request the target already received.
        assert.equal(internalHits - before, 0, "The internal fixture recorded a request");
        assert.ok(error instanceof AntiSSRFError, "Expected the library's policy refusal");
        assert.equal(error.message, "IP address disallowed by policy");
    };

    before(async () => {
        internal = createServer((_request, response) => {
            internalHits++;
            response.end("internal fixture");
        });
        internalPort = await listen(internal, "127.0.0.1");
        internalOrigin = `http://127.0.0.1:${internalPort}`;

        entry = createServer((request, response) => {
            entryHits++;
            switch (request.url) {
                case "/redirect-internal":
                    response.writeHead(302, { Location: internalOrigin });
                    break;
                case "/redirect-decimal":
                    response.writeHead(307, { Location: `http://2130706433:${internalPort}` });
                    break;
                case "/redirect-allowed":
                    response.writeHead(302, { Location: "/allowed" });
                    break;
                default:
                    response.end("allowed fixture");
                    return;
            }
            response.end();
        });
        entryOrigin = `http://127.0.0.2:${await listen(entry, "127.0.0.2")}`;

        const policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);
        policy.allowPlainTextHttp = true;
        // Permit only the local entry fixture. The internal listener remains
        // denied by the normal policy. This exception is confined to the test.
        policy.addAllowedAddresses(["127.0.0.2"]);
        protectedAgent = policy.getHttpAgent({ keepAlive: false });
        unsafeAgent = new Agent({ keepAlive: false });
    });

    it("completes an allowed request with the protected agent", async () => {
        const before = entryHits;
        const beforeInternal = internalHits;
        assert.deepStrictEqual(await get(entryOrigin, protectedAgent), { status: 200, body: "allowed fixture" });
        assert.equal(entryHits - before, 1);
        assert.equal(internalHits, beforeInternal);
    });

    it("follows an allowed redirect with the protected agent", async () => {
        const before = entryHits;
        const beforeInternal = internalHits;
        assert.deepStrictEqual(await get(`${entryOrigin}/redirect-allowed`, protectedAgent), {
            status: 200,
            body: "allowed fixture"
        });
        assert.equal(entryHits - before, 2);
        assert.equal(internalHits, beforeInternal);
    });

    const cases = [
        { name: "dotted loopback", url: () => internalOrigin, entryHits: 0 },
        { name: "decimal loopback", url: () => `http://2130706433:${internalPort}`, entryHits: 0 },
        { name: "octal loopback", url: () => `http://0177.0.0.1:${internalPort}`, entryHits: 0 },
        { name: "hexadecimal loopback", url: () => `http://0x7f.0.0.1:${internalPort}`, entryHits: 0 },
        { name: "mapped IPv6 loopback", url: () => `http://[::ffff:127.0.0.1]:${internalPort}`, entryHits: 0 },
        { name: "302 redirect to loopback", url: () => `${entryOrigin}/redirect-internal`, entryHits: 1 },
        { name: "307 redirect to decimal loopback", url: () => `${entryOrigin}/redirect-decimal`, entryHits: 1 }
    ];

    for (const testCase of cases) {
        it(`unsafe control reaches ${testCase.name}`, async () => {
            const before = internalHits;
            const beforeEntry = entryHits;
            assert.deepStrictEqual(await get(testCase.url(), unsafeAgent), { status: 200, body: "internal fixture" });
            assert.equal(internalHits - before, 1);
            assert.equal(entryHits - beforeEntry, testCase.entryHits);
        });

        it(`blocks ${testCase.name} without an internal request`, async () => {
            const before = entryHits;
            await assertBlocked(() => get(testCase.url(), protectedAgent));
            assert.equal(entryHits - before, testCase.entryHits);
        });
    }

    it("detects reach even when the caller later reports a policy error", async () => {
        const before = internalHits;
        await assert.rejects(
            () =>
                assertBlocked(async () => {
                    await get(internalOrigin, unsafeAgent);
                    throw new AntiSSRFError("IP address disallowed by policy");
                }),
            /The internal fixture recorded a request/
        );
        assert.equal(internalHits - before, 1);
    });

    after(async () => {
        protectedAgent?.destroy();
        unsafeAgent?.destroy();
        await Promise.all([close(entry), close(internal)]);
    });
});
