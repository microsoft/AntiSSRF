// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "assert";
import { ADDRCONFIG, ALL, lookup, LookupAddress, LookupOptions, V4MAPPED } from "dns";
import { LookupFunction } from "net";

import { antiSSRFDnsLookup } from "../../src/Helpers/AntiSSRFDnsLookup";
import { AntiSSRFPolicy, AntiSSRFError, PolicyConfigOptions } from "../../src";

/**
 * Converts a callback-based lookup function to a promise-based lookup function
 * for easier testing.
 */
const customPromisify = (lookup: LookupFunction) => (hostname: string, options: LookupOptions) =>
    new Promise((resolve, reject) => {
        lookup(hostname, options, (err, address, family) => {
            if (err) {
                return reject(err);
            }
            if (family != null) {
                return resolve({ address: address as string, family });
            } else {
                return resolve(address as LookupAddress[]);
            }
        });
    });

const optionsToString = (options: LookupOptions | null | undefined) => {
    if (!options) {
        return options;
    }

    return (
        "{" +
        Object.entries(options)
            .map(([key, value]) => {
                return `${key}: ${value}`;
            })
            .join(", ") +
        "}"
    );
};

/**
 * Asserts that the result of AntiSSRFDnsLookup matches the result of dns.lookup
 * for the given hostname and options.
 */
const AssertMatchResult = async (policy: AntiSSRFPolicy, hostname: string, options: LookupOptions) => {
    let expected;
    try {
        expected = await customPromisify(lookup)(hostname, options);
    } catch (err) {
        assert.fail(
            `Expected dns.lookup to not error: hostname - ${hostname}, options - ${optionsToString(options)}, error - ${err}`
        );
    }

    let actual;
    try {
        actual = await customPromisify(antiSSRFDnsLookup(policy))(hostname, options);
    } catch (err) {
        assert.fail(
            `Expected AntiSSRFDnsLookup to not error: hostname - ${hostname}, options - ${optionsToString(options)}, error - ${err}`
        );
    }

    assert.deepStrictEqual(
        actual,
        expected,
        `Expected results to match: hostname - ${hostname}, options - ${optionsToString(options)}`
    );
};

/**
 * Asserts that the error from AntiSSRFDnsLookup matches the error from
 * dns.lookup for the given hostname and options.
 */
const AssertMatchError = async (policy: AntiSSRFPolicy, hostname: string, options: LookupOptions) => {
    let expectedError: Error | null = null;
    try {
        await customPromisify(lookup)(hostname, options);
    } catch (err) {
        expectedError = err as Error;
    }
    if (!expectedError) {
        assert.fail(`Expected dns.lookup to error: hostname - ${hostname}, options - ${optionsToString(options)}`);
    }

    let actualError: Error | null = null;
    try {
        await customPromisify(antiSSRFDnsLookup(policy))(hostname, options);
    } catch (err) {
        actualError = err as Error;
    }
    if (!actualError) {
        assert.fail(
            `Expected AntiSSRFDnsLookup to error: hostname - ${hostname}, options - ${optionsToString(options)}`
        );
    }

    assert.deepStrictEqual(
        actualError,
        expectedError,
        `Expected errors to match: hostname - ${hostname}, options - ${optionsToString(options)}`
    );
};

/**
 * Asserts that the error from AntiSSRFDnsLookup matches the error from
 * dns.lookup for the given hostname and options OR asserts that the result of
 * AntiSSRFDnsLookup matches the result of dns.lookup for the given hostname and
 * options.
 *
 * Only used for hostnames/options that behave difference between local and
 * Azure pipeline tests.
 */
const AssertMatchResultOrError = async (policy: AntiSSRFPolicy, hostname: string, options: LookupOptions) => {
    let expectedResult;
    let expectedError: Error | null = null;
    try {
        expectedResult = await customPromisify(lookup)(hostname, options);
    } catch (err) {
        expectedError = err as Error;
    }

    let actualResult;
    let actualError: Error | null = null;
    try {
        actualResult = await customPromisify(antiSSRFDnsLookup(policy))(hostname, options);
    } catch (err) {
        actualError = err as Error;
    }

    if (expectedError) {
        assert.deepStrictEqual(
            actualError,
            expectedError,
            `Expected errors to match: hostname - ${hostname}, options - ${optionsToString(options)}`
        );
    } else {
        assert.deepStrictEqual(
            actualResult,
            expectedResult,
            `Expected results to match: hostname - ${hostname}, options - ${optionsToString(options)}`
        );
    }
};

describe("AntiSSRFDnsLookup", () => {
    describe("Bad inputs", () => {
        it("Null hostname", async () => {
            const policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            await AssertMatchResult(policy, null as unknown as string, {});
            await AssertMatchResult(policy, null as unknown as string, { all: false });
            await AssertMatchResult(policy, null as unknown as string, { all: true });
            await AssertMatchResult(policy, null as unknown as string, { family: 0 });
            await AssertMatchResult(policy, null as unknown as string, { family: 6 });
        });

        it("Undefined hostname", async () => {
            const policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            await AssertMatchResult(policy, undefined as unknown as string, {});
            await AssertMatchResult(policy, undefined as unknown as string, { all: false });
            await AssertMatchResult(policy, undefined as unknown as string, { all: true });
            await AssertMatchResult(policy, undefined as unknown as string, { family: 4 });
            await AssertMatchResult(policy, undefined as unknown as string, { family: 6 });
            await AssertMatchResult(policy, undefined as unknown as string, { family: 0, all: true });
        });

        it("Generally bad hostname", async () => {
            const policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            await AssertMatchError(policy, "hello", {});
            await AssertMatchError(policy, "https://google.com", { all: false });
            await AssertMatchError(policy, "https://www.google.com", null as any);
            await AssertMatchError(policy, "google.com:60", { all: true });
            await AssertMatchError(policy, "google.com/path", { family: 4 });
            await AssertMatchError(policy, "google.com/search?q=hi", { family: 6 });
            await AssertMatchError(policy, "username@sup.com", { family: 0, all: true });
            await AssertMatchError(policy, "#fragment", null as any);
        });

        it("Bad options", async () => {
            const policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            const hostname = "bing.com";

            // options.all must be true or false
            await AssertMatchError(policy, hostname, { all: 1 as unknown as boolean });

            // options.family must by 0, 4, 6, "IPv4", or "IPv6"
            await AssertMatchError(policy, hostname, { family: 3 as unknown as 0 });
            await AssertMatchError(policy, hostname, { family: "IPv0" as unknown as "IPv4" });

            // options.hints can only be specific flags
            await AssertMatchError(policy, hostname, { hints: -1 });

            // options.order can only be "verbatim", "ipv4first", or "ipv6first"
            // Behavior different across environments
            await AssertMatchResultOrError(policy, hostname, { order: "NotAnOrder" as unknown as "verbatim" });

            // options.verbatim can only be true or false
            await AssertMatchError(policy, hostname, { verbatim: 1 as unknown as boolean });
        });
    });

    /**
     * All addresses are allowed, so dns.lookup and AntiSSRFDnsLookup should
     * always return the same result or throw the same error.
     */
    describe("Lookup with accepting policy", () => {
        // If all addresses are allowed, dns.lookup and AntiSSRFDnsLookup should be the same
        const policy = new AntiSSRFPolicy(PolicyConfigOptions.None);

        const OPT_FAMILY: (0 | 4 | 6 | "IPv4" | "IPv6")[] = [4, 6, 0, "IPv4", "IPv6", undefined as unknown as 0];
        const OPT_ALL: boolean[] = [true, false, undefined as unknown as boolean];
        const OPT_ORDER: ("verbatim" | "ipv4first" | "ipv6first")[] = [
            "verbatim",
            "ipv4first",
            "ipv6first",
            undefined as unknown as "verbatim"
        ];
        const OPT_HINTS: number[] = [
            V4MAPPED, // 2048
            ALL, // 256
            ADDRCONFIG, // 1024
            V4MAPPED | ALL,
            V4MAPPED | ADDRCONFIG,
            ALL | ADDRCONFIG,
            V4MAPPED | ALL | ADDRCONFIG,
            undefined as unknown as number
        ];
        const OPT_VERBATIM: boolean[] = [true, false, undefined as unknown as boolean];

        const hostnames = ["google.com", "bing.com", "learn.microsoft.com"];
        for (const hostname of hostnames) {
            it(`Common domain tests - ${hostname}`, async () => {
                for (const all of OPT_ALL) {
                    for (const family of OPT_FAMILY) {
                        for (const order of OPT_ORDER) {
                            for (const hints of OPT_HINTS) {
                                for (const verbatim of OPT_VERBATIM) {
                                    if (family == 6 || family == "IPv6") {
                                        // Behavior different for IPv6 across environments
                                        if (process.platform === "win32") {
                                            await AssertMatchError(policy, hostname, {
                                                all,
                                                family,
                                                order,
                                                hints,
                                                verbatim
                                            });
                                        } else if (hints == null || (hints & V4MAPPED)) {
                                            await AssertMatchResult(policy, hostname, {
                                                all,
                                                family,
                                                order,
                                                hints,
                                                verbatim
                                            });
                                        } else if (hints & ALL && !(hints & ADDRCONFIG)) {
                                            await AssertMatchResult(policy, hostname, {
                                                all,
                                                family,
                                                order,
                                                hints,
                                                verbatim
                                            });
                                        } else {
                                            await AssertMatchError(policy, hostname, {
                                                all,
                                                family,
                                                order,
                                                hints,
                                                verbatim
                                            });
                                        }
                                    } else {
                                        await AssertMatchResult(policy, hostname, {
                                            all,
                                            family,
                                            order,
                                            hints,
                                            verbatim
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        const hostnames2 = ["azure.com", "github.com"];
        for (const hostname of hostnames2) {
            it(`Common domain tests, no IPv6 - ${hostname}`, async () => {
                for (const all of OPT_ALL) {
                    for (const family of OPT_FAMILY) {
                        for (const order of OPT_ORDER) {
                            for (const hints of OPT_HINTS) {
                                for (const verbatim of OPT_VERBATIM) {
                                    if ((family == 6 || family == "IPv6") && ((hints & V4MAPPED) == 0)) {
                                        if (process.platform === 'win32' || hints != null) {
                                            await AssertMatchError(policy, hostname, {
                                                all,
                                                family,
                                                order,
                                                hints,
                                                verbatim
                                            });
                                        } else {
                                            await AssertMatchResult(policy, hostname, {
                                                all,
                                                family,
                                                order,
                                                hints,
                                                verbatim
                                            });
                                        }
                                    } else {
                                        await AssertMatchResult(policy, hostname, {
                                            all,
                                            family,
                                            order,
                                            hints,
                                            verbatim
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    });

    describe("Lookup with policy functionality", () => {
        it("Default policy", async () => {
            const policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);
            const promisifiedAntiSSRFLookup = customPromisify(antiSSRFDnsLookup(policy));

            // Allowed by policy
            await AssertMatchResult(policy, "google.com", { family: 4 });
            await AssertMatchResult(policy, "yAhOo.com", { family: 4, all: false });

            // Disallowed by policy - IMDS
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("169.254.169.254", { family: 4 }),
                AntiSSRFError
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("0xA9.0Xfe.0xA9.0xFe", { family: 4 }),
                (err: Error) => {
                    if (process.platform === 'win32') {
                        return err.message.includes("getaddrinfo ENOTFOUND 0xA9.0Xfe.0xA9.0xFe");
                    } else {
                        return err.message === "IP address disallowed by policy";
                    }
                }
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("169.254.169.254", { family: 6 }),
                AntiSSRFError
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("::FFFF:169.254.169.254", { family: 4 }),
                AntiSSRFError
            );

            // Rejects with different error in local vs Azure pipeline
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("imds.michaelhendrickx.com", { family: 0, all: true })
            );

            // Disallowed by policy - WireServer
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("168.63.129.16", { family: 4 }),
                AntiSSRFError
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("0xA8.0X3F.0x81.0x10", { family: 4 }),
                (err: Error) => {
                    if (process.platform === 'win32') {
                        return err.message.includes("getaddrinfo ENOTFOUND 0xA8.0X3F.0x81.0x10");
                    } else {
                        return err.message === "IP address disallowed by policy";
                    }
                }
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("168.63.129.16", { family: 6 }),
                AntiSSRFError
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("::FFFF:168.63.129.16", { family: 4 }),
                AntiSSRFError
            );

            // Disallowed by policy - localhost
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("localhost", { family: 4 }),
                AntiSSRFError
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("localhost", { family: 6 }),
                AntiSSRFError
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("127.0.0.1", { family: 4 }),
                AntiSSRFError
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("127.0.0.1", { family: 6 }),
                AntiSSRFError
            );

            // Disallowed by policy - other
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("100.64.0.10", { family: 4 }),
                AntiSSRFError
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("100.64.0.10", { family: 6 }),
                AntiSSRFError
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("::FFFF:100.64.0.10", { family: 4 }),
                AntiSSRFError
            );
            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("::FFFF:100.64.0.10", { family: 6 }),
                AntiSSRFError
            );

            // More allowed by policy
            await AssertMatchResult(policy, "bing.com", { family: 4 });
            await AssertMatchResult(policy, "microsoft.com", { family: 0 });
            await AssertMatchResult(policy, "docs.github.com", { family: 0, all: true });
            await AssertMatchResult(policy, "223.6.7.8", { family: 0, all: true });
            await AssertMatchResult(policy, "::fffF:223.6.7.8", { family: 0, all: true });
        });

        it("addAllowedAddresses", async () => {
            const policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);
            const promisifiedAntiSSRFLookup = customPromisify(antiSSRFDnsLookup(policy));

            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("169.254.0.2", { all: true }),
                AntiSSRFError
            );

            policy.addAllowedAddresses(["169.254.0.2"]);

            await AssertMatchResult(policy, "169.254.0.2", null as any);
            await AssertMatchResult(policy, "google.com", null as any);
        });

        it("addDeniedAddresses", async () => {
            const policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            const promisifiedAntiSSRFLookup = customPromisify(antiSSRFDnsLookup(policy));

            await AssertMatchResult(policy, "192.168.0.0", null as any);

            policy.addDeniedAddresses(["192.168.0.0"]);

            await assert.rejects(
                async () => await promisifiedAntiSSRFLookup("192.168.0.0", null as any),
                AntiSSRFError
            );
            await AssertMatchResult(policy, "google.com", null as any);
        });
    });
});
