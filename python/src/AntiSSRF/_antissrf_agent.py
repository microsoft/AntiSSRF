# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from ._ipaddr import IPAddress
from .antissrf_error import AntiSSRFError
from .antissrf_policy import AntiSSRFPolicy

from requests import Session, PreparedRequest
from requests.adapters import HTTPAdapter
import socket

def _resolve_host(hostname: str) -> list[IPAddress]:
    """Resolve a hostname to a list of IPAddress objects.
    
    Returns a list of IPAddress objects.
    """
    # If the input is already an IP literal, parse it directly
    try:
        return [IPAddress(hostname)]
    except ValueError:
        # Not a direct IP literal; fall back to DNS resolution
        pass
    
    addrs = []
    
    # Use getaddrinfo to resolve both IPv4 and IPv6 addresses
    infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    for _, _, _, _, sockaddr in infos:
        addr_text = sockaddr[0]
        try:
            addrs.append(IPAddress(addr_text))
        except Exception:
            raise AntiSSRFError(f"A resolved address for host {hostname!r} is invalid")
    
    return addrs


def _validate_request_host(policy, host) -> list[IPAddress]:
        """Resolve and validate the request host.

        Returns the list of resolved IPAddress objects
        if validation succeeds. Raises AntiSSRFError on failure.
        """
        if not host:
            return []

        addrs = _resolve_host(host)

        if not addrs:
            raise AntiSSRFError(f"Host {host!r} did not resolve to an address")

        if not policy._is_network_connection_allowed(addrs):
            raise AntiSSRFError(f"Resolved address for host {host!r} is denied by policy")
        
        return addrs


class _AntiSSRFAdapter(HTTPAdapter):
    """A requests Adapter that enforces AntiSSRF policies."""
    def __init__(self, policy: AntiSSRFPolicy, **kwargs):
        super().__init__(**kwargs)
        self._policy = policy
    
    
    def build_connection_pool_key_attributes(self, request: PreparedRequest, verify, cert = None) -> tuple[dict, dict]:
        """Override to enforce AntiSSRF policy before connection is made.
        
        This method is called by requests before establishing a connection.
        We use it to:
        1. Validate the scheme and headers against the policy
        2. Resolve the hostname to IP addresses and validate them
        3. Replace the hostname with a validated IP (DNS rebinding protection)
        4. Preserve the original hostname for TLS SNI and certificate validation
        """
        host_param, pool_kwargs = super().build_connection_pool_key_attributes(request, verify, cert)
                            
        # Check scheme (http/https) and headers against policy
        allowed, request = self._policy._is_http_request_allowed(host_param["scheme"], request)
        if not allowed:
            raise AntiSSRFError("HTTP request is not allowed by policy")
        
        # Save the original hostname before we replace it with an IP
        original_host = host_param["host"]
            
        # Set Host header to original hostname (required by HTTP/1.1 and virtual hosting)
        request.headers['Host'] = original_host
        
        # For HTTPS, configure TLS to use original hostname:
        # - server_hostname: Sent via SNI so server returns correct certificate
        # - assert_hostname: Client validates certificate CN/SAN against this
        # Without these, TLS would fail since we connect to an IP but cert is for hostname
        if host_param["scheme"] == 'https':
            pool_kwargs['assert_hostname'] = original_host
            pool_kwargs['server_hostname'] = original_host
        
        # Resolve hostname to IPs and validate ALL resolved addresses against policy.
        # This prevents DNS records from pointing to internal/blocked IPs.
        addrs = _validate_request_host(self._policy, original_host)
        if not addrs:
            raise AntiSSRFError(f"Host {original_host!r} did not resolve to an address")
        
        # Replace hostname with validated IP address.
        # This is the key DNS rebinding protection: we connect directly to the IP
        # we just validated, preventing TOCTOU attacks where DNS changes between
        # validation and connection.
        chosen = addrs[0]  # Select the first resolved IP for deterministic behavior
        connect_ip = str(chosen.get_address())
        host_param["host"] = connect_ip
            
        return (host_param, pool_kwargs)
            

class AntiSSRFSession(Session):
    """A requests Session that enforces AntiSSRF policies."""
    def __init__(self, policy: AntiSSRFPolicy):
        super().__init__()
        self._policy = policy
        # Each adapter instance has its own connection pool manager that keeps TCP connections alive for reuse. 
        # Using separate adapters means HTTP and HTTPS connections are pooled independently.
        self.mount("http://", _AntiSSRFAdapter(self._policy))
        self.mount("https://", _AntiSSRFAdapter(self._policy))