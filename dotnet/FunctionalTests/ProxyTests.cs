using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace Microsoft.Security.AntiSSRF.FunctionalTests
{
    [CollectionDefinition("Proxy tests", DisableParallelization = true)]
    public sealed class ProxyTestCollection
    {
    }

    [Collection("Proxy tests")]
    public class ProxyTests
    {
        // Starts a minimal forwarding proxy for this test and relays a single HTTP request to its destination.
        // The proxy address should be allowed by AntiSSRF.
        private static (TcpListener Proxy, Task ProxyTask) StartForwardingProxy(string proxyIp, int proxyPort, CancellationToken cancellationToken)
        {
            var proxy = new TcpListener(IPAddress.Parse(proxyIp), proxyPort);
            proxy.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            proxy.Start();

            var proxyTask = Task.Run(async () =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    TcpClient? client = null;
                    try
                    {
                        client = await proxy.AcceptTcpClientAsync().ConfigureAwait(false);
                    }
                    catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
                    {
                        return;
                    }
                    catch (SocketException) when (cancellationToken.IsCancellationRequested)
                    {
                        return;
                    }

                    using (client)
                    using (var downstream = client.GetStream())
                    {
                        var buffer = new byte[8192];
                        int bytesRead = await downstream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                        if (bytesRead <= 0)
                        {
                            return;
                        }

                        var request = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                        var lines = request.Split(new[] { "\r\n" }, StringSplitOptions.None);
                        var firstLine = lines[0].Split(' ');
                        var uri = new Uri(firstLine[1]);

                        lines[0] = $"{firstLine[0]} {uri.PathAndQuery} {firstLine[2]}";
                        for (int i = 1; i < lines.Length; i++)
                        {
                            if (lines[i].StartsWith("Proxy-Connection:", StringComparison.OrdinalIgnoreCase))
                            {
                                lines[i] = "Connection: close";
                            }
                        }

                        var rewrittenRequest = string.Join("\r\n", lines);

                        using var upstream = new TcpClient();
                        await upstream.ConnectAsync(uri.Host, uri.Port).ConfigureAwait(false);
                        using var upstreamStream = upstream.GetStream();

                        var requestBytes = Encoding.ASCII.GetBytes(rewrittenRequest);
                        await upstreamStream.WriteAsync(requestBytes, 0, requestBytes.Length).ConfigureAwait(false);
                        try
                        {
                            await upstreamStream.CopyToAsync(downstream).ConfigureAwait(false);
                        }
                        catch (Exception)
                        {
                            // Client closed socket while proxy was relaying response.
                        }
                    }

                    return;
                }
            }, cancellationToken);

            return (proxy, proxyTask);
        }

        // Starts a one-shot HTTP listener for the provided address and signals when a request reaches the target.
        // This is the address that should be blocked by AntiSSRF, but will be allowed through a proxy.
        private static (HttpListener Target, Task TargetTask) StartTargetListener(string targetIp, int targetPort, TaskCompletionSource<bool> targetReached)
        {
            var target = new HttpListener();
            target.Prefixes.Add($"http://{targetIp}:{targetPort}/");
            target.Start();

            var targetTask = Task.Run(async () =>
            {
                try
                {
                    var ctx = await target.GetContextAsync().ConfigureAwait(false);
                    targetReached.TrySetResult(true);
                    ctx.Response.StatusCode = (int)HttpStatusCode.NoContent;
                    ctx.Response.Close();
                }
                catch (HttpListenerException)
                {
                    // Expected when the listener is stopped during test cleanup.
                }
            });

            return (target, targetTask);
        }

        [Fact]
        public async Task ProxyEnvironmentVariableWithDefaultPolicy()
        {
            // Set up 'blocked' target
            const string targetIp = "127.0.0.2";
            const int targetPort = 18181;
            var targetReached = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var (target, targetTask) = StartTargetListener(targetIp, targetPort, targetReached);

            // Set up proxy
            const string proxyIp = "127.0.0.1";
            const int proxyPort = 18888;
            var cts = new CancellationTokenSource();
            var (proxy, proxyTask) = StartForwardingProxy(proxyIp, proxyPort, cts.Token);

            // Set up client with policy
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1)
            {
                AllowPlainTextHttp = true
            };
            policy.AddAllowedAddresses(new[] { $"{proxyIp}/32" });
            using var handler = policy.GetHandler();
            using var client = new HttpClient(handler);

            // Attempt to set the proxy environment variable and test if the proxy is used
            string? originalProxy = Environment.GetEnvironmentVariable("HTTP_PROXY");
            try
            {
                Environment.SetEnvironmentVariable("HTTP_PROXY", $"http://{proxyIp}:{proxyPort}");

                var url = $"http://{targetIp}:{targetPort}/test";
                AntiSSRFException? ex = null;
                try
                {
                    await client.GetAsync(url);
                    Assert.Fail("Expected AntiSSRFException when default policy is used with a denied target address.");
                }
                catch (AntiSSRFException caught)
                {
                    ex = caught;
                }

                Assert.NotNull(ex);
                Assert.Contains(targetIp, ex.Message);

                var completed = await Task.WhenAny(targetReached.Task, Task.Delay(TimeSpan.FromSeconds(1)));
                Assert.NotSame(targetReached.Task, completed);
            }
            finally
            {
                Environment.SetEnvironmentVariable("HTTP_PROXY", originalProxy);
                target.Stop();
                cts.Cancel();
                proxy.Stop();

                await targetTask;
                await proxyTask;
            }
        }

#if NET8_0_OR_GREATER
        [Fact]
        public async Task ProxyDefaultProxyWithCustomPolicy()
        {
            // Set up 'blocked' target
            const string targetIp = "127.0.0.3";
            const int targetPort = 28282;
            var targetReached = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var (target, targetTask) = StartTargetListener(targetIp, targetPort, targetReached);

            // Set up proxy
            const string proxyIp = "127.0.0.2";
            const int proxyPort = 28888;
            var cts = new CancellationTokenSource();
            var (proxy, proxyTask) = StartForwardingProxy(proxyIp, proxyPort, cts.Token);

            // Set up client with policy
            var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1)
            {
                AllowPlainTextHttp = true
            };
            policy.AddAllowedAddresses(new[] { $"{proxyIp}/32" });
            using var handler = policy.GetHandler();
            using var client = new HttpClient(handler);

            // Attempt to set the default proxyand test if the proxy is used
            IWebProxy originalDefaultProxy = HttpClient.DefaultProxy;
            IWebProxy customProxy = new WebProxy(new Uri($"http://{proxyIp}:{proxyPort}"));
            HttpClient.DefaultProxy = customProxy;

            try
            {
                var url = $"http://{targetIp}:{targetPort}/test";
                AntiSSRFException? ex = null;
                try
                {
                    await client.GetAsync(url);
                    Assert.Fail("Expected AntiSSRFException when default policy is used with a denied target address.");
                }
                catch (AntiSSRFException caught)
                {
                    ex = caught;
                }

                Assert.NotNull(ex);
                Assert.Contains(targetIp, ex.Message);

                var completed = await Task.WhenAny(targetReached.Task, Task.Delay(TimeSpan.FromSeconds(1)));
                Assert.NotSame(targetReached.Task, completed);
            }
            finally
            {
                HttpClient.DefaultProxy = originalDefaultProxy;
                target.Stop();
                cts.Cancel();
                proxy.Stop();

                await targetTask;
                await proxyTask;
            }
        }
#endif
    }
}