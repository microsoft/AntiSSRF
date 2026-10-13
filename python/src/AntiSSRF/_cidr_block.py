# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import ipaddress
from ipaddress import NetmaskValueError, AddressValueError
from ._ipaddr import IPAddress


class CIDRBlock:
    """
    Simple IP network class supporting both IPv4 and IPv6 that automatically 
    maps IPv4 addresses to IPv6-mapped space for easy comparisons.
    
    This class accepts flexible IPv4/IPv6 input and exposes:
    - `get_network()` -> an `ipaddress.IPv6Network` representing the network
      (IPv4 inputs are converted to IPv6-mapped form `::ffff:a.b.c.d`).
    - `get_prefix()` -> integer prefix length.

    Notes:
    - When given an IPv4 input the class maps it to IPv6-mapped space and
      increases the prefix by 96. The internal network object is an
      `ipaddress.IPv6Network` and `str()` will print the canonical form.
    - The stdlib `ipaddress` module normalizes networks to their canonical
      network address (host bits cleared). This class uses `strict=False`
      to accept hostful addresses and normalize them.
    """

    def __init__(self, network: str):
        """
        Initialize with a network string.

        Accepts either a bare address (no '/') in which case the default
        host prefix is used (IPv4 -> 32, IPv6 -> 128), or a string in CIDR
        notation (e.g. '192.168.0.0/24' or '[2001:db8::]/32').
        """
        
        self._net = None
        self._prefix = None
        
        try:
            # Check for valid input and CIDR notation
            if network is None or network.strip() == "":
                raise NetmaskValueError("Network string cannot be empty or None")
            if network.count('/') > 1:
                raise NetmaskValueError(f"Invalid network format (multiple '/'): {network}")
        
           # Parse optional CIDR suffix once
            if '/' in network:
                ipaddr_str, prefix_str = network.split('/', 1)
                if not prefix_str.isdigit():
                    raise NetmaskValueError(f"Invalid prefix length (non-numeric): {network}")
                prefix = int(prefix_str)
            else:
                ipaddr_str = network
                prefix = None

            # Create IPAddress once
            addr_wrapper = IPAddress(ipaddr_str)

            # If IPv4, get IPv6-mapped address and adjust prefix
            if addr_wrapper.is_ipv4():
                ipv6_addr = addr_wrapper.ipv6_mapped()  # returns an ipaddress.IPv6Address
                if prefix is None:
                    prefix = 32
                prefix = prefix + 96
            else:
                # IPv6 case
                ipv6_addr = addr_wrapper.get_address()  # an ipaddress.IPv6Address
                if prefix is None:
                    prefix = 128

            # Store prefix and create IPv6Network using native objects (no string conversion)
            self._prefix = prefix
            # ipaddress.IPv6Network accepts (address, prefix) tuple; use strict=False to allow hostful inputs
            self._net = ipaddress.IPv6Network((ipv6_addr, self._prefix), strict=False)

        except AddressValueError as ave:
            # Address parsing failed
            raise NetmaskValueError(f"Invalid IP address in network: {network}") from ave
        except NetmaskValueError:
            # propagate NetmaskValueError as-is (preserves useful message)
            raise
        except Exception as exc:
            # Unexpected errors: wrap but keep cause for debugging
            raise NetmaskValueError(f"Invalid IP network: {network}") from exc
    
        
    def __str__(self):
        return str(self._net)
    
    
    def get_network(self):
        """Return the internal `ipaddress.IPv6Network` object."""
        return self._net
    
    
    def get_prefix(self):  
        """Return the network prefix length as an integer."""
        return int(self._prefix)