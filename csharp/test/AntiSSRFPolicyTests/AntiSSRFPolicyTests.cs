// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using Xunit;

namespace Microsoft.Security.AntiSSRF.Tests
{
    public class AntiSSRFPolicyTests
    {
        [Fact]
        public void Constructor_APICheck()
        {
            var policyType = typeof(AntiSSRFPolicy);

            var constructor = policyType.GetConstructor(new[] { typeof(PolicyConfigOptions) });
            Assert.NotNull(constructor);
            Assert.True(constructor.IsPublic, "Constructor with PolicyConfigOptions should be public");
            
            var parameters = constructor.GetParameters();
            Assert.Single(parameters);
            Assert.Equal(typeof(PolicyConfigOptions), parameters[0].ParameterType);
        }

        [Fact]
        public void GetHandler_APICheck()
        {
            var policyType = typeof(AntiSSRFPolicy);

            var getHandlerMethod = policyType.GetMethod("GetHandler");
            Assert.NotNull(getHandlerMethod);
            Assert.True(getHandlerMethod.IsPublic, "GetHandler method should be public");
            Assert.Equal(typeof(AntiSSRFHandler), getHandlerMethod.ReturnType);
            Assert.Empty(getHandlerMethod.GetParameters());

            var handler = new AntiSSRFPolicy(PolicyConfigOptions.None).GetHandler();
            Assert.NotNull(handler);
            Assert.True(handler is HttpMessageHandler);
            Assert.True(handler is AntiSSRFHandler);
        }

        [Fact]
        public void NonPublicMembers_APICheck()
        {
            var policyType = typeof(AntiSSRFPolicy);

            var isNetworkConnectionAllowedMethod = policyType.GetMethod("IsNetworkConnectionAllowed", 
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(isNetworkConnectionAllowedMethod);
            Assert.False(isNetworkConnectionAllowedMethod.IsPublic, "IsNetworkConnectionAllowed should not be public");

            var isHttpRequestAllowedMethod = policyType.GetMethod("IsHttpRequestAllowed", 
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(isHttpRequestAllowedMethod);
            Assert.False(isHttpRequestAllowedMethod.IsPublic, "IsHttpRequestAllowed should not be public");

            var editLockField = policyType.GetField("_editLock", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(editLockField);
            Assert.False(editLockField.IsPublic, "_editLock field should not be public");
            Assert.Equal(typeof(bool), editLockField.FieldType);
        }

        [Fact]
        public void PolicyConfigOptions_APICheck()
        {
            var configOptionsType = typeof(PolicyConfigOptions);

            Assert.True(configOptionsType.IsEnum, "PolicyConfigOptions should be an enum");
            Assert.True(configOptionsType.IsPublic, "PolicyConfigOptions should be public");
            Assert.Equal(typeof(int), Enum.GetUnderlyingType(configOptionsType));

            Assert.True(Enum.IsDefined(configOptionsType, "InternalOnly"), "InternalOnly should be defined");
            Assert.Equal(0, (int)PolicyConfigOptions.InternalOnly);
            
            Assert.True(Enum.IsDefined(configOptionsType, "ExternalOnlyV1"), "ExternalOnlyV1 should be defined");
            Assert.Equal(1, (int)PolicyConfigOptions.ExternalOnlyV1);
            
            Assert.True(Enum.IsDefined(configOptionsType, "ExternalOnlyLatest"), "ExternalOnlyLatest should be defined");
            Assert.Equal(2, (int)PolicyConfigOptions.ExternalOnlyLatest);

            Assert.True(Enum.IsDefined(configOptionsType, "None"), "None should be defined");
            Assert.Equal(3, (int)PolicyConfigOptions.None);
        }

    }
}
