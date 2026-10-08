// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#if NET5_0_OR_GREATER

using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace Microsoft.Security.AntiSSRF
{
    internal class InnerHandler
    {
        internal static SocketsHttpHandler GetHandler(AntiSSRFPolicy policy)
        {
            return new SocketsHttpHandler()
            {
                AllowAutoRedirect = false,
                UseProxy = false,
                ConnectCallback = async (connectionContext, cancellationToken) =>
                {
                    IPAddress[] resolvedIPs = await Dns.GetHostAddressesAsync(connectionContext.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);
                    if (resolvedIPs.Length == 0)
                        throw new AntiSSRFException($"DNS lookup failed for {connectionContext.DnsEndPoint.Host}.");

                    if (!policy.IsNetworkConnectionAllowed(resolvedIPs))
                        throw new AntiSSRFException($"The connection to {connectionContext.DnsEndPoint.Host} is not allowed per policy.");

                    Socket socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    try
                    {
                        await socket.ConnectAsync(resolvedIPs, connectionContext.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }
            };
        }
    }
}

#endif