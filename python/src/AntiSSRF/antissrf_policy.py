# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from enum import Enum
from ._ipaddr import IPAddress
from ._cidr_block import CIDRBlock
from .antissrf_error import AntiSSRFError
from .ipaddress_ranges import IPAddressRanges
from requests.structures import CaseInsensitiveDict
from requests import PreparedRequest


class PolicyConfigOptions(Enum):
    """Policy configuration options for AntiSSRFPolicy."""
    INTERNAL_ONLY = "InternalOnly"
    EXTERNAL_ONLY_V1 = "ExternalOnlyV1"
    EXTERNAL_ONLY_LATEST = "ExternalOnlyLatest"
    NONE = "None"


class AntiSSRFPolicy:    
    def __init__(self, config: PolicyConfigOptions):
        """
        Initialize AntiSSRFPolicy with the specified configuration.

        Args:
            config: Policy configuration option:
                - PolicyConfigOptions.INTERNAL_ONLY: Denies all connections by default.
                    Use add_allowed_addresses() to permit specific ranges.
                - PolicyConfigOptions.EXTERNAL_ONLY_V1: Blocks recommendedV1 IP ranges.
                    Blocked ranges are stable and currently meet security requirements,
                    but may not meet future security requirements.
                - PolicyConfigOptions.EXTERNAL_ONLY_LATEST: Blocks recommendedLatest IP ranges.
                    Blocked ranges are always updated to meet the latest security requirements,
                    but may change without semantic versioning guarantees.
                - PolicyConfigOptions.NONE: No default restrictions.
        """
        if (config is None):
            raise ValueError("Config argument cannot be None. Please use a valid PolicyConfigOptions.")
        
        # IP address related variables
        self._allowed_addresses = []     # maintains all networks in IPv6
        self._denied_addresses = []      # maintains all networks in IPv6
        self._deny_all_unspecified_ips = False
        
        # Headers related variables
        self._required_headers = []      # maintains all headers are lowercase
        self._denied_headers = []        # maintains all headers are lowercase
        self._add_xff_header = False
        self._allow_plain_text_http = False
        
        # Frozen once the policy is used to create a session
        self._edit_lock = False
        
        match config:
            case PolicyConfigOptions.INTERNAL_ONLY:
                self._deny_all_unspecified_ips = True
                self._add_xff_header = False
            case PolicyConfigOptions.EXTERNAL_ONLY_V1:
                self.add_denied_addresses(IPAddressRanges.recommended_v1)
                self._add_xff_header = True
            case PolicyConfigOptions.EXTERNAL_ONLY_LATEST:
                self.add_denied_addresses(IPAddressRanges.recommended_latest)
                self._add_xff_header = True
            case PolicyConfigOptions.NONE:
                self._add_xff_header = False
            case _:
                raise AntiSSRFError("Invalid policy option. Please use a valid PolicyConfigOption.")    

    def _ensure_unlocked(self) -> None:
        if self._edit_lock:
            raise AntiSSRFError("Policy can't be modified after it has been used to create a session")

    # ===== IP Address Methods =====

    @property
    def deny_all_unspecified_ips(self) -> bool:
        """Whether all unspecified IPs are denied. When True, only explicitly allowed addresses can connect."""
        return self._deny_all_unspecified_ips

    @deny_all_unspecified_ips.setter
    def deny_all_unspecified_ips(self, value: bool) -> None:
        self._ensure_unlocked()
        if value is None:
            raise ValueError("Null or empty argument")
        self._deny_all_unspecified_ips = value

    @property
    def allowed_addresses(self) -> tuple:
        """Read-only tuple of IP networks explicitly allowed by the policy."""
        return tuple(self._allowed_addresses)

    @property
    def denied_addresses(self) -> tuple:
        """Read-only tuple of IP networks explicitly blocked by the policy."""
        return tuple(self._denied_addresses)

    def add_allowed_addresses(self, networks: list[str]) -> None:
        """Add IP addresses and/or CIDR ranges to the policy's allowed set.

        Args:
            networks: List of network strings in CIDR notation or single IPs.

        Raises:
            ValueError: If `networks` is None or empty.
            AntiSSRFError: If any entry is not a valid network string, 
                or editing after a session has been retrieved.
        """
        if networks is None or len(networks) == 0:
            raise ValueError("Null argument")
        self._ensure_unlocked()
        for net in networks:
            try:
                network = CIDRBlock(net)  # validate
                self._allowed_addresses.append(network)
            except ValueError as e:
                raise AntiSSRFError(f"Invalid network string '{net}': {e}")
    
    
    def add_denied_addresses(self, networks: list[str]) -> None:
        """Add IP addresses and/or CIDR ranges to the policy's denied set.

        Args:
            networks: List of network strings in CIDR notation or single IPs.

        Raises:
            ValueError: If `networks` is None or empty.
            AntiSSRFError: If `deny_all_unspecified_ips` is True or any entry 
                is not a valid network string, or editing after a session 
                has been retrieved.
        """
        if networks is None or len(networks) == 0:
            raise ValueError("Null argument")
        
        self._ensure_unlocked()
        
        if self._deny_all_unspecified_ips:
            raise AntiSSRFError("Can't add denied networks when deny_all_unspecified_ips is true")
        
        for net in networks:
            try:
                network = CIDRBlock(net)  # validate
                self._denied_addresses.append(network)
            except ValueError as e:
                raise AntiSSRFError(f"Invalid network string '{net}': {e}")


    def _is_ip_address_connection_allowed(self, address: IPAddress) -> bool:
        """Determine whether an `IPAddress` is allowed by the policy.

        Args:
            address: The IPAddress to evaluate.

        Returns:
            bool: True if the address is allowed, False if it is denied.
        """
        mapped_addr = address.ipv6_mapped()  # always get IPv6-mapped address

        # Check against allowed addresses first
        for net in self._allowed_addresses:
            if mapped_addr in net.get_network():
                return True  # explicitly allowed

        # Check against denied addresses
        if self._deny_all_unspecified_ips:
            return False  # all unspecified are denied

        for net in self._denied_addresses:
            if mapped_addr in net.get_network():
                return False  # explicitly denied

        return True  # allowed if not denied
    

    def _is_str_ip_address_connection_allowed(self, address: str) -> bool:
        """Determine whether an IP address string is allowed by the policy.

        Args:
            address: The IP address string to evaluate.

        Returns:
            bool: True if the address is allowed, False if it is denied or invalid.
        """
        try:
            ip_addr = IPAddress(address)
            mapped_addr = ip_addr.ipv6_mapped()  # always get IPv6-mapped address
        except (ValueError, TypeError):
            return False  # invalid IP address

        # Check against allowed addresses first
        for net in self._allowed_addresses:
            if mapped_addr in net.get_network():
                return True  # explicitly allowed

        # Check against denied addresses
        if self._deny_all_unspecified_ips:
            return False  # all unspecified are denied

        for net in self._denied_addresses:
            if mapped_addr in net.get_network():
                return False  # explicitly denied

        return True  # allowed if not denied
    
    
    def _is_network_connection_allowed(self, addresses: list) -> bool:
        """Determine whether all given addresses are allowed by the policy.

        Args:
            addresses: List of IP address strings or IPAddress objects.

        Returns:
            bool: True if every address is allowed, False if any is denied or invalid.
        """
        if addresses is None:
            return False

        for addr in addresses:
            if isinstance(addr, IPAddress):
                if not self._is_ip_address_connection_allowed(addr):
                    return False  # one denied is enough
            elif isinstance(addr, str):
                if not self._is_str_ip_address_connection_allowed(addr):
                    return False  # one denied is enough
            else:
                return False  # invalid address type
        
        return True  # all allowed
        
    # ===== Header Methods =====

    @property
    def required_headers(self) -> tuple:
        """Read-only tuple of headers required to be present in outgoing requests."""
        return tuple(self._required_headers)

    @property
    def denied_headers(self) -> tuple:
        """Read-only tuple of headers forbidden from outgoing requests."""
        return tuple(self._denied_headers)

    def add_required_headers(self, required_headers: list[str]) -> None:
        """Add header names to the policy's required set.

        Args:
            required_headers: List of header names (case-insensitive).

        Raises:
            ValueError: If `required_headers` is None or empty, or any header is
                None, empty, or whitespace.
            AntiSSRFError: If editing after a session has been retrieved.
        """
        if required_headers is None or len(required_headers) == 0:
            raise ValueError("Null or empty argument")
        self._ensure_unlocked()
        for header in required_headers:
            if header is None:
                raise ValueError("Headers cannot be None")
            if header.strip() == "":
                raise ValueError("Headers cannot be an empty string")
        for header in required_headers:
            self._required_headers.append(header.lower())
            
            
    def add_denied_headers(self, denied_headers: list[str]) -> None:
        """Add header names to the policy's denied set.

        Args:
            denied_headers: List of header names (case-insensitive).

        Raises:
            ValueError: If `denied_headers` is None or empty, or any header is
                None, empty, or whitespace.
            AntiSSRFError: If editing after a session has been retrieved.
        """
        if denied_headers is None or len(denied_headers) == 0:
            raise ValueError("Null or empty argument")
        self._ensure_unlocked()
        for header in denied_headers:
            if header is None:
                raise ValueError("Headers cannot be None")
            if header.strip() == "":
                raise ValueError("Headers cannot be an empty string")
        for header in denied_headers:
            self._denied_headers.append(header.lower())


    @property
    def add_xff_header(self) -> bool:
        """Whether the X-Forwarded-For header is added to outgoing requests that omit it."""
        return self._add_xff_header

    @add_xff_header.setter
    def add_xff_header(self, value: bool) -> None:
        self._ensure_unlocked()
        if value is None:
            raise ValueError("Null or empty argument")
        self._add_xff_header = value

    @property
    def allow_plain_text_http(self) -> bool:
        """Whether plaintext HTTP is allowed. When False, HTTPS is required."""
        return self._allow_plain_text_http

    @allow_plain_text_http.setter
    def allow_plain_text_http(self, value: bool) -> None:
        self._ensure_unlocked()
        if value is None:
            raise ValueError("Null or empty argument")
        self._allow_plain_text_http = value

            
    # check scheme and header
    def _is_http_request_allowed(self, scheme, request: PreparedRequest) -> tuple:
        """Apply required headers and check the request's scheme and headers.

        Args:
            scheme: HTTP scheme ("http" or "https").
            request: PreparedRequest whose headers are inspected and updated.

        Returns:
            tuple: An (allowed, request) tuple where allowed is True if the scheme and
                headers satisfy the policy.
        """
        # Ensure headers is a CaseInsensitiveDict
        if request.headers is None:
            request.headers = CaseInsensitiveDict()            
        
        if scheme is None:
            return (False, request)  # no scheme
        if scheme not in ['http', 'https']:
            return (False, request)  # unsupported scheme

        if not self._allow_plain_text_http and scheme == 'http':
            return (False, request)  # plain http not allowed

        # Add XFF header if required and not already present
        if self._add_xff_header and 'x-forwarded-for' not in request.headers:
            request.headers['X-Forwarded-For'] = 'true'

        # Check denied headers
        for deny_header in self._denied_headers:
            if deny_header in request.headers:
                return (False, request)  # has denied header

        # Check required headers
        for req_header in self._required_headers:
            if req_header not in request.headers:
                return (False, request)  # missing required header
            
        return (True, request)  # allowed


    def get_antissrf_session(self, **kwargs) :
        """Create an AntiSSRFSession that enforces this policy.

        Returns:
            AntiSSRFSession: An AntiSSRFSession bound to this policy. After this call the 
                policy is frozen and can no longer be modified.
        """
        # Import here to avoid circular dependency
        from AntiSSRF._antissrf_agent import AntiSSRFSession # lazy import to prevent circular dependency
        self._edit_lock = True  # freeze policy once it is in use
        return AntiSSRFSession(policy=self, **kwargs)
