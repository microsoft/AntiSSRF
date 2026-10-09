// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.Security.AntiSSRF.FunctionalTests
{
    // Single-threaded SynchronizationContext, like AspNetSynchronizationContext.
    sealed class SingleThreadSyncCtx : SynchronizationContext
    {
        readonly BlockingCollection<(SendOrPostCallback, object?)> _queue = new BlockingCollection<(SendOrPostCallback, object?)>();

        public override void Post(SendOrPostCallback d, object? state) => _queue.Add((d, state));
    }

    public sealed class LocalHttpListenerFixture : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly Task _listenerTask;
        private readonly CancellationTokenSource _listenerCts;

        public LocalHttpListenerFixture()
        {
            int port = GetFreeTcpPort();
            Url = $"http://127.0.0.1:{port}/";

            _listener = new HttpListener();
            _listener.Prefixes.Add(Url);
            _listener.Start();

            _listenerCts = new CancellationTokenSource();
            _listenerTask = Task.Run(async () =>
            {
                while (!_listenerCts.Token.IsCancellationRequested)
                {
                    HttpListenerContext context;
                    try
                    {
                        context = await _listener.GetContextAsync().ConfigureAwait(false);
                    }
                    catch (HttpListenerException) when (_listenerCts.Token.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (ObjectDisposedException) when (_listenerCts.Token.IsCancellationRequested)
                    {
                        break;
                    }

                    await Task.Delay(TimeSpan.FromMilliseconds(50)).ConfigureAwait(false);
                    context.Response.StatusCode = (int)HttpStatusCode.NoContent;
                    context.Response.Close();
                }
            }, _listenerCts.Token);
        }

        public string Url { get; }

        public void Dispose()
        {
            _listenerCts.Cancel();
            _listener.Stop();
            _listener.Close();
            _listenerTask.GetAwaiter().GetResult();
            _listenerCts.Dispose();
        }

        private static int GetFreeTcpPort()
        {
            var tcpListener = new TcpListener(IPAddress.Loopback, 0);
            try
            {
                tcpListener.Start();
                return ((IPEndPoint)tcpListener.LocalEndpoint).Port;
            }
            finally
            {
                tcpListener.Stop();
            }
        }
    }

    public class ThreadTests : IClassFixture<LocalHttpListenerFixture>
    {
        private readonly LocalHttpListenerFixture _listener;

        public ThreadTests(LocalHttpListenerFixture listener)
        {
            _listener = listener;
        }

        [Fact]
        public void Deadlock_Test()
        {
            Exception? workerFailure = null;
            const int timeoutSeconds = 10;
            using (var workerCompleted = new ManualResetEventSlim())
            {
                var worker = new Thread(() =>
                {
                    var previousContext = SynchronizationContext.Current;
                    SynchronizationContext.SetSynchronizationContext(new SingleThreadSyncCtx());
                    try
                    {
                        var policy = new AntiSSRFPolicy(PolicyConfigOptions.None)
                        {
                            AllowPlainTextHttp = true
                        };
                        policy.AddAllowedAddresses(new[] { "127.0.0.1/32" });

                        using var handler = policy.GetHandler();
                        using var client = new HttpClient(handler);
#pragma warning disable xUnit1031 // Blocking is intentional to verify the handler does not capture the synchronization context.
                        using var response = client.GetAsync(_listener.Url).GetAwaiter().GetResult();
#pragma warning restore xUnit1031
                        Console.WriteLine(response.StatusCode);
                    }
                    catch (Exception ex)
                    {
                        // Capture any worker failure so it can be reported by the test thread.
                        workerFailure = ex;
                    }
                    finally
                    {
                        SynchronizationContext.SetSynchronizationContext(previousContext);
                        workerCompleted.Set();
                    }
                })
                {
                    IsBackground = true
                };

                worker.Start();

                Assert.True(workerCompleted.Wait(TimeSpan.FromSeconds(timeoutSeconds)),
                    $"The request did not complete under a single-threaded synchronization context within {timeoutSeconds} seconds.");

                Assert.True(workerFailure is null, workerFailure?.ToString());
            }
        }
    }
}