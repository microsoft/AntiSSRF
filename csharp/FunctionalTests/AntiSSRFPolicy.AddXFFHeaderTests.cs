// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.Security.AntiSSRF.FunctionalTests
{
    public class AntiSSRFPolicy_AddXFFHeaderTests
    {
        private static readonly string TestDomain = "ambitious-flower-0611c910f.2.azurestaticapps.net";

        [Fact]
        public void CheckDefaults()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.InternalOnly);
            var policy2 = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1);
            var policy3 = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);
            var policy4 = new AntiSSRFPolicy(PolicyConfigOptions.None);
            Assert.False(policy.AddXFFHeader);
            Assert.True(policy2.AddXFFHeader);
            Assert.True(policy3.AddXFFHeader);
            Assert.False(policy4.AddXFFHeader);
        }

        [Fact]
        public async Task OnTrue()
        {
            AntiSSRFPolicy policy = new(PolicyConfigOptions.None)
            {
                AddXFFHeader = true
            };
            HttpClient client = new(policy.GetHandler());

            var response = await client.GetAsync($"https://{TestDomain}/api/header-check?header=X-Forwarded-For", CancellationToken.None);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        // TODO: public void OnFalse()
        // Having trouble not auto-adding XFF

        [Fact]
        public async Task DoesNotOverwriteHeader()
        {
            AntiSSRFPolicy policy = new(PolicyConfigOptions.None)
            {
                AddXFFHeader = true
            };
            HttpClient client = new(policy.GetHandler());

            var request = new HttpRequestMessage(HttpMethod.Get, $"https://{TestDomain}/api/header-check?header=X-Forwarded-For");
            request.Headers.Add("X-Forwarded-For", "1.2.3.4");

            var response = await client.SendAsync(request, CancellationToken.None);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var contents = await response.Content.ReadAsStringAsync();
            Assert.Contains("1.2.3.4", contents);
        }

        // TODO: public void HoldsOnRedirect()
        // Having trouble not auto-adding XFF

        [Fact]
        public void NoEditsAfterHandler()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1);
            var handler = policy.GetHandler();

            Assert.Throws<AntiSSRFException>(() => policy.AddXFFHeader = true);
        }
    }
}
