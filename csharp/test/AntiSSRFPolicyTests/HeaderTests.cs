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

namespace Microsoft.Security.AntiSSRF.Tests
{
    public class AntiSSRFPolicy_HeaderTests
    {
        private static readonly string TestDomain = "ambitious-flower-0611c910f.2.azurestaticapps.net";

        [Fact]
        public void APICheck()
        {
            var policyType = typeof(AntiSSRFPolicy);

            // Check DeniedHeaders property visibility and accessibility
            var deniedHeadersProp = policyType.GetProperty("DeniedHeaders");
            Assert.NotNull(deniedHeadersProp);
            Assert.True(deniedHeadersProp.CanRead, "DeniedHeaders should be readable");
            Assert.False(deniedHeadersProp.CanWrite, "DeniedHeaders should be read-only");
            Assert.Equal(typeof(IReadOnlyList<string>), deniedHeadersProp.PropertyType);
            Assert.True(deniedHeadersProp.GetMethod!.IsPublic, "DeniedHeaders getter should be public");
            Assert.Null(deniedHeadersProp.SetMethod);

            // Check RequiredHeaders property visibility and accessibility
            var requiredHeadersProp = policyType.GetProperty("RequiredHeaders");
            Assert.NotNull(requiredHeadersProp);
            Assert.True(requiredHeadersProp.CanRead, "RequiredHeaders should be readable");
            Assert.False(requiredHeadersProp.CanWrite, "RequiredHeaders should be read-only");
            Assert.Equal(typeof(IReadOnlyList<string>), requiredHeadersProp.PropertyType);
            Assert.True(requiredHeadersProp.GetMethod!.IsPublic, "RequiredHeaders getter should be public");
            Assert.Null(requiredHeadersProp.SetMethod);

            // Check AddRequiredHeaders method visibility
            var addRequiredHeadersMethod = policyType.GetMethod("AddRequiredHeaders");
            Assert.NotNull(addRequiredHeadersMethod);
            Assert.True(addRequiredHeadersMethod.IsPublic, "AddRequiredHeaders method should be public");
            Assert.Equal(typeof(void), addRequiredHeadersMethod.ReturnType);
            var addRequiredHeadersParams = addRequiredHeadersMethod.GetParameters();
            Assert.Single(addRequiredHeadersParams);
            Assert.Equal(typeof(string[]), addRequiredHeadersParams[0].ParameterType);

            // Check AddDeniedHeaders method visibility
            var addDeniedHeadersMethod = policyType.GetMethod("AddDeniedHeaders");
            Assert.NotNull(addDeniedHeadersMethod);
            Assert.True(addDeniedHeadersMethod.IsPublic, "AddDeniedHeaders method should be public");
            Assert.Equal(typeof(void), addDeniedHeadersMethod.ReturnType);
            var addDeniedHeadersParams = addDeniedHeadersMethod.GetParameters();
            Assert.Single(addDeniedHeadersParams);
            Assert.Equal(typeof(string[]), addDeniedHeadersParams[0].ParameterType);

            // Verify that the backing fields are private
            var deniedHeadersField = policyType.GetField("_deniedHeaders",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(deniedHeadersField);
            Assert.True(deniedHeadersField.IsPrivate, "_deniedHeaders should be private");

            var requiredHeadersField = policyType.GetField("_requiredHeaders",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(requiredHeadersField);
            Assert.True(requiredHeadersField.IsPrivate, "_requiredHeaders should be private");
        }

        [Fact]
        public void BadInputs()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1);

            // Invalid arrays
            Assert.Throws<ArgumentNullException>(() => policy.AddDeniedHeaders(null));
            Assert.Throws<ArgumentNullException>(() => policy.AddRequiredHeaders(null));

            // Invalid array elements
            Assert.Throws<ArgumentException>(() => policy.AddDeniedHeaders([""]));
            Assert.Throws<ArgumentException>(() => policy.AddRequiredHeaders([""]));
            Assert.Throws<ArgumentNullException>(() => policy.AddDeniedHeaders(["X-Valid-Header", null!, "Another-Header"]));
            Assert.Throws<ArgumentNullException>(() => policy.AddRequiredHeaders([null!, "X-Test-Header"]));
        }

        [Fact]
        public void CheckDefaults()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.InternalOnly);
            var policy2 = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1);
            var policy3 = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);
            var policy4 = new AntiSSRFPolicy(PolicyConfigOptions.None);
            Assert.Empty(policy.RequiredHeaders);
            Assert.Empty(policy2.RequiredHeaders);
            Assert.Empty(policy3.RequiredHeaders);
            Assert.Empty(policy4.RequiredHeaders);
            Assert.Empty(policy.DeniedHeaders);
            Assert.Empty(policy2.DeniedHeaders);
            Assert.Empty(policy3.DeniedHeaders);
            Assert.Empty(policy4.DeniedHeaders);
        }

        [Fact]
        public async Task RequiredHeader()
        {
            AntiSSRFPolicy policy = new(PolicyConfigOptions.None);
            policy.AddRequiredHeaders(["X-Test-Header"]);
            HttpClient client = new(policy.GetHandler());
            string Url = $"https://{TestDomain}/api/header-check?header=X-Test-Header";

            HttpRequestMessage request = new(HttpMethod.Get, Url);
            request.Headers.Add("Not-X-Test-Header", "test-value");
            await Assert.ThrowsAsync<AntiSSRFException>(() => client.SendAsync(request, CancellationToken.None));

            HttpRequestMessage request2 = new(HttpMethod.Get, Url);
            request2.Headers.Add("X-Test-Header", "test-value");
            var response = await client.SendAsync(request2, CancellationToken.None);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task DeniedHeader()
        {
            AntiSSRFPolicy policy = new(PolicyConfigOptions.None);
            policy.AddDeniedHeaders(["X-Test-Header"]);
            HttpClient client = new(policy.GetHandler());
            string url = $"https://{TestDomain}/";

            HttpRequestMessage request = new(HttpMethod.Get, url);
            request.Headers.Add("X-Test-Header", "test-value");
            await Assert.ThrowsAsync<AntiSSRFException>(() => client.SendAsync(request, CancellationToken.None));

            HttpRequestMessage request2 = new(HttpMethod.Get, url);
            request2.Headers.Add("Not-X-Test-Header", "test-value");
            var response = await client.SendAsync(request2, CancellationToken.None);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task BothRequiredAndDenied()
        {
            AntiSSRFPolicy policy = new(PolicyConfigOptions.None);
            policy.AddRequiredHeaders(["X-Test-Header"]);
            policy.AddDeniedHeaders(["X-Test-Header"]);
            HttpClient client = new(policy.GetHandler());
            string Url = $"https://{TestDomain}/api/header-check?header=X-Test-Header";

            HttpRequestMessage request = new(HttpMethod.Get, Url);
            request.Headers.Add("X-Test-Header", "test-value");
            await Assert.ThrowsAsync<AntiSSRFException>(() => client.SendAsync(request, CancellationToken.None));

            HttpRequestMessage request2 = new(HttpMethod.Get, Url);
            request2.Headers.Add("Not-X-Test-Header", "test-value");
            await Assert.ThrowsAsync<AntiSSRFException>(() => client.SendAsync(request2, CancellationToken.None));
        }

        [Fact]
        public async Task WithAddXFFHeader()
        {
            string Url = $"https://{TestDomain}/api/header-check?header=X-Forwarded-For";

            AntiSSRFPolicy policy = new(PolicyConfigOptions.None)
            {
                AddXFFHeader = true
            };
            policy.AddRequiredHeaders(["X-Forwarded-For", "X-Test-Header"]);
            HttpClient client = new(policy.GetHandler());

            HttpRequestMessage request = new(HttpMethod.Get, Url);
            request.Headers.Add("X-Test-Header", "test-value");
            var response = await client.SendAsync(request, CancellationToken.None);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            AntiSSRFPolicy policy2 = new(PolicyConfigOptions.None)
            {
                AddXFFHeader = true
            };
            policy2.AddDeniedHeaders(["X-Forwarded-For", "Not-X-Test-Header"]);
            HttpClient client2 = new(policy2.GetHandler());

            HttpRequestMessage request2 = new(HttpMethod.Get, Url);
            request2.Headers.Add("X-Test-Header", "test-value");
            await Assert.ThrowsAsync<AntiSSRFException>(() => client2.SendAsync(request2, CancellationToken.None));
        }

        [Fact]
        public async Task HoldsOnRedirect()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            policy.AddRequiredHeaders(["X-Required-Header"]);
            HttpClient client = new(policy.GetHandler());

            HttpRequestMessage req = new(HttpMethod.Get, $"https://{TestDomain}/api/redirect?num=3");
            req.Headers.Add("X-Required-Header", "test-value");

            // Should succeed since the required header is present and maintained through redirects
            var response = await client.SendAsync(req, CancellationToken.None);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task RequiredHeaderDroppedOnRedirect()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.None);
            policy.AddRequiredHeaders(["Authorization"]);
            HttpClient client = new(policy.GetHandler());

            HttpRequestMessage req = new(HttpMethod.Get, $"https://{TestDomain}/api/redirect?num=3");
            req.Headers.Add("Authorization", "Bearer test-token");

            // Should fail because Authorization header gets dropped by HttpClient during redirects
            await Assert.ThrowsAsync<AntiSSRFException>(() => client.SendAsync(req, CancellationToken.None));
        }

        [Fact]
        public void NoEditsAfterHandler()
        {
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1);
            var handler = policy.GetHandler();

            Assert.Throws<AntiSSRFException>(() => policy.AddRequiredHeaders(["X-Test-Header"]));
            Assert.Throws<AntiSSRFException>(() => policy.AddDeniedHeaders(["X-Test-Header"]));
        }
    }
}
