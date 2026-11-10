// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Xunit;

using Microsoft.Security.AntiSSRF;

namespace Microsoft.Security.AntiSSRF.UnitTests
{
    public class AntiSSRFPolicyEditLockTests
    {
        // Returns an unrestricted policy that has been locked by creating a handler.
        private static AntiSSRFPolicy LockedPolicy()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            policy.GetHandler();
            return policy;
        }

        private static void AssertThrowsAfterLock(Action<AntiSSRFPolicy> mutate, string expectedMessage)
        {
            AntiSSRFPolicy policy = LockedPolicy();
            var ex = Assert.Throws<AntiSSRFException>(() => mutate(policy));
            Assert.Equal(expectedMessage, ex.Message);
        }

        // ===== Every mutator throws once the policy is locked =====

        [Fact]
        public void AddAllowedAddresses_ThrowsAfterGetHandler() =>
            AssertThrowsAfterLock(
                p => p.AddAllowedAddresses(new[] { "10.0.0.0/8" }),
                "Can't AddAllowedAddresses after policy is used to create a handler");

        [Fact]
        public void AddDeniedAddresses_ThrowsAfterGetHandler() =>
            AssertThrowsAfterLock(
                p => p.AddDeniedAddresses(new[] { "10.0.0.0/8" }),
                "Can't AddDeniedAddresses after policy is used to create a handler");

        [Fact]
        public void AddRequiredHeaders_ThrowsAfterGetHandler() =>
            AssertThrowsAfterLock(
                p => p.AddRequiredHeaders(new[] { "x-required" }),
                "Can't AddRequiredHeaders after policy is used to create a handler");

        [Fact]
        public void AddDeniedHeaders_ThrowsAfterGetHandler() =>
            AssertThrowsAfterLock(
                p => p.AddDeniedHeaders(new[] { "x-denied" }),
                "Can't AddDeniedHeaders after policy is used to create a handler");

        [Fact]
        public void DenyAllUnspecifiedIPs_ThrowsAfterGetHandler() =>
            AssertThrowsAfterLock(
                p => p.DenyAllUnspecifiedIPs = true,
                "Can't change DenyAllUnspecifiedIPs after policy has been used to create a handler");

        [Fact]
        public void AddXFFHeader_ThrowsAfterGetHandler() =>
            AssertThrowsAfterLock(
                p => p.AddXFFHeader = true,
                "Can't change AddXFFHeader after policy has been used to create a handler");

        [Fact]
        public void AllowPlainTextHttp_ThrowsAfterGetHandler() =>
            AssertThrowsAfterLock(
                p => p.AllowPlainTextHttp = true,
                "Can't change AllowPlainTextHttp after policy has been used to create a handler");

        // ===== Every change still works before a handler exists =====

        [Fact]
        public void AddAllowedAddresses_WorksBeforeGetHandler()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            policy.AddAllowedAddresses(new[] { "10.0.0.0/8" });
            Assert.Single(policy.AllowedAddresses);
        }

        [Fact]
        public void AddDeniedAddresses_WorksBeforeGetHandler()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            policy.AddDeniedAddresses(new[] { "10.0.0.0/8" });
            Assert.Single(policy.DeniedAddresses);
        }

        [Fact]
        public void AddRequiredHeaders_WorksBeforeGetHandler()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            policy.AddRequiredHeaders(new[] { "x-required" });
            Assert.Single(policy.RequiredHeaders);
        }

        [Fact]
        public void AddDeniedHeaders_WorksBeforeGetHandler()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            policy.AddDeniedHeaders(new[] { "x-denied" });
            Assert.Single(policy.DeniedHeaders);
        }

        [Fact]
        public void DenyAllUnspecifiedIPs_WorksBeforeGetHandler()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.None) { DenyAllUnspecifiedIPs = true };
            Assert.True(policy.DenyAllUnspecifiedIPs);
        }

        [Fact]
        public void AddXFFHeader_WorksBeforeGetHandler()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.None) { AddXFFHeader = true };
            Assert.True(policy.AddXFFHeader);
        }

        [Fact]
        public void AllowPlainTextHttp_WorksBeforeGetHandler()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.None) { AllowPlainTextHttp = true };
            Assert.True(policy.AllowPlainTextHttp);
        }

        // ===== Integrity checks =====

        [Fact]
        public void RefusedChange_LeavesPolicyUnchanged()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.InternalOnly);
            policy.GetHandler();

            Assert.Throws<AntiSSRFException>(() => policy.AddAllowedAddresses(new[] { "127.0.0.1/32" }));
            Assert.Empty(policy.AllowedAddresses);

            Assert.Throws<AntiSSRFException>(() => policy.AllowPlainTextHttp = true);
            Assert.False(policy.AllowPlainTextHttp);
        }

        [Fact]
        public void MultipleHandlers_FromOnePolicy_DoNotThrow()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            using var handler1 = policy.GetHandler();
            using var handler2 = policy.GetHandler();
            using var handler3 = policy.GetHandler();
        }
    }
}
