# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from urllib3.util import parse_url
from urllib3.exceptions import LocationParseError
from urllib.parse import urlsplit
import idna
from AntiSSRF._domains import _KEYVAULT_DOMAIN_LIST, _STORAGE_DOMAIN_LIST


"""
URI validation helpers used by the AntiSSRF package.

This module provides simple parsing and domain-checking utilities:
- `_encode_idna` encodes a hostname using IDNA (Punycode).
- `_try_parse` normalizes and parses a URI into a hostname.
- `in_domain` checks whether a URL's hostname belongs to a specific domain.
- `in_any_domain` checks a URL against a list of allowed domains.
- `in_keyvault_domain` and `in_storage_domain` test hostnames against
  precompiled domain regexes defined in `AntiSSRF._domains`.
"""

ALLOWED_IN_DOMAIN_SCHEMES = ['http', 'https', 'ws', 'wss']
ALLOWED_KEYVAULT_SCHEMES = ['http', 'https']
ALLOWED_STORAGE_SCHEMES = ['http', 'https']

class URIValidator:
    def _encode_idna(hostname: str) -> str:
        """Encode a hostname to ACE (Punycode) using `idna` (UTS46).

        Args:
            hostname: The hostname to encode.

        Returns:
            str or None: The ASCII/Punycode hostname, or None if `hostname` is falsy or
                cannot be encoded. ``idna.IDNAError`` is caught so callers treat
                unencodable hostnames as "not a match" rather than raising.
        """
        if not hostname:
            return None
        
        try:
            # https://github.com/psf/requests/blob/main/src/requests/models.py Line 404
            return idna.encode(hostname, uts46=True).decode("utf-8")
        except idna.IDNAError as e:
            return None
    
    @staticmethod
    def _try_parse(uri: str, allowed_schemes: list):
        """Parse `uri` and return its hostname, or None on failure.

        Uses the stricter regex-based ``urllib3.util.parse_url`` (RFC 3986)
        cross-checked against ``urllib.parse.urlsplit``. The strict parser
        raises ``LocationParseError`` on malformed authorities instead of
        silently accepting them, rejecting non-numeric or out-of-range ports
        (``host:badPort``), invalid IPv6 literals such as
        ``[0::0%.trusted.com]`` (zone-id smuggling), and disallowed characters
        in the authority (spaces, control characters).

        Args:
            uri: URI or host string (may contain Unicode).
            allowed_schemes: Schemes accepted when a scheme is present.

        Returns:
            str or None: The hostname on success, or None for falsy input, a missing or
                disallowed scheme, or a malformed URI. ``LocationParseError`` is
                caught and treated as "not a match"; other exceptions propagate so
                unexpected bugs are not masked.
        """

        if not uri:
            return None

        try:
            # https://github.com/urllib3/urllib3/blob/8e80f374/src/urllib3/util/url.py#L367-L469
            parsed_url = parse_url(uri)
            # checking consistency between parse_url and urlsplit results
            split_url = urlsplit(uri)
            
            if parsed_url.hostname != URIValidator._encode_idna(split_url.hostname):
                # On the case of http://one.com\@two.com/, parsed_url.hostname will be "one.com" while split_url_hostname will be "two.com"
                # Bracketed IPv6 literals will also be differently parsed. parsed_url will contain the brackets while split_url_hostname will not.
                return None

            if parsed_url.scheme and parsed_url.scheme in allowed_schemes:
                return parsed_url.hostname
            return None
        except LocationParseError:
            # Expected for malformed authorities (bad ports, invalid IPv6
            # literals, disallowed characters). Treat as "not a match".
            # Any other exception is intentionally allowed to propagate so
            # unexpected bugs are not masked.
            return None
        

    @staticmethod
    def _in_domain_check(parsed_hostname: str, domain: str) -> bool:
        """Check whether `parsed_hostname` belongs to `domain`.

        Normalizes `domain` (dropping a leading '.') and encodes it to ACE
        using IDNA (Punycode), then compares the ASCII forms with a
        label-aware suffix check:
        ``('.' + parsed_hostname).endswith('.' + parsed_domain)``.

        Args:
            parsed_hostname: Already-parsed, IDNA-encoded hostname to test.
            domain: The domain to match against (Unicode allowed).

        Returns:
            bool: True if `parsed_hostname` matches `domain` at label boundaries,
                otherwise False (including invalid inputs or IDNA failures).
        """

        # Parse domain safely and Encode the domain using IDNA (Punycode)
        if domain.startswith('.'):
            domain = domain[1:]
        
        parsed_domain = URIValidator._encode_idna(domain)
        
        if not parsed_hostname or not parsed_domain:
            return False
        
        # Perform the suffix match with boundary checks
        return ('.' + parsed_hostname).endswith('.' + parsed_domain)
    
    
    @staticmethod
    def in_domain(url: str, domains) -> bool:
        """Check whether `url` belongs to a trusted domain.

        Args:
            url: URI or hostname string to check.
            domains: A single domain string, or an iterable of domain strings.

        Returns:
            bool: True if the URL's host belongs to any of `domains`, otherwise False.
        """
        
        if not url or not domains:
            return False
        
        parsed_hostname = URIValidator._try_parse(url, ALLOWED_IN_DOMAIN_SCHEMES)
        if not parsed_hostname:
            return False
        
        # Handle single domain string
        if isinstance(domains, str):
            return URIValidator._in_domain_check(parsed_hostname, domains)
        
        # Handle iterable of domains
        if isinstance(domains, (list, tuple, set)):
            for domain in domains:
                if URIValidator._in_domain_check(parsed_hostname, domain):
                    return True
                
        return False


    @staticmethod
    def in_azure_keyvault_domain(uri: str) -> bool:
        """Check whether `uri` is an Azure Key Vault endpoint.

        Args:
            uri: URI or hostname string to check.

        Returns:
            bool: True if the host belongs to an Azure Key Vault domain, otherwise False.
        """
        if not uri:
            return False
        parsed_hostname = URIValidator._try_parse(uri, ALLOWED_KEYVAULT_SCHEMES)
        if not parsed_hostname or '--' in parsed_hostname:
            return False
        for domain in _KEYVAULT_DOMAIN_LIST:
            if URIValidator._in_domain_check(parsed_hostname, domain):
                return True
        return False


    @staticmethod
    def in_azure_storage_domain(uri: str) -> bool:
        """Check whether `uri` is an Azure Storage endpoint.

        Args:
            uri: URI or hostname string to check.

        Returns:
            bool: True if the host belongs to an Azure Storage domain, otherwise False.
        """
        if not uri:
            return False
        parsed_hostname = URIValidator._try_parse(uri, ALLOWED_STORAGE_SCHEMES)
        if not parsed_hostname or '--' in parsed_hostname:
            return False
        for domain in _STORAGE_DOMAIN_LIST:
            if URIValidator._in_domain_check(parsed_hostname, domain):
                return True
        return False
