# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import ipaddress
from ipaddress import AddressValueError, IPv6Address


# Custom IPAddress class wrapping standard IPv4 and IPv6 parsing
class IPAddress:
    def __init__(self, address: str):
        """
        Initialize with an address string. Parses and stores the IP address (IPv4 or IPv6).
        """
        self._ip = None
        self._type = None

        # If address contains ":" do IPv6
        if ':' in address:
            try:
                # Remove brackets if present (for bracket notation)
                addr = address.strip("[]") if address else address
                """
                    The following constitutes a valid IPv6 address:
                    A string consisting of eight groups of four hexadecimal digits, each group representing 16 bits. 
                    The groups are separated by colons. This describes an exploded (longhand) notation. The string 
                    can also be compressed (shorthand notation) by various means. See RFC 4291 for details. 
                    
                    For example, "0000:0000:0000:0000:0000:0abc:0007:0def" can be compressed to "::abc:7:def".
                    
                    Optionally, the string may also have a scope zone ID, expressed with a suffix %scope_id. If 
                    present, the scope ID must be non-empty, and may not contain %. See RFC 4007 for details. 
                    For example, fe80::1234%1 might identify address fe80::1234 on the first link of the node.
                    
                    An integer that fits into 128 bits.
                    An integer packed into a bytes object of length 16, big-endian.
                    
                    For more info, see https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv6Address
                """
                self._ip = ipaddress.IPv6Address(addr)
                self._type = "ipv6"
            except (AddressValueError, ValueError):
                pass
        else: 
            # try IPv4
            try:
                """
                    The following constitutes a valid IPv4 address:

                    A string in decimal-dot notation, consisting of four decimal integers in the inclusive range 0-255, 
                    separated by dots (e.g. 192.168.0.1). Each integer represents an octet (byte) in the address. Leading 
                    zeroes are not tolerated to prevent confusion with octal notation.
                    
                    An integer that fits into 32 bits.
                    An integer packed into a bytes object of length 4 (most significant octet first).
                """
                self._ip = ipaddress.IPv4Address(address)
                self._type = "ipv4"
            except (AddressValueError, ValueError):
                pass
        
        # Still none at this point, then its an invalid IP
        if self._ip is None:
            raise AddressValueError(f"Invalid IP address: {address}")


    # Custom strings function for IPAddress
    def __str__(self):
        """Return the string representation of the IP address."""
        # Return string format of IP address normally
        return str(self._ip)


    def __int__(self):
        """Return the integer representation of the IP address."""
        return int(self._ip)


    def get_address(self):
        """Return the ipaddress package's IPv4Address or IPv6Address object"""
        return self._ip


    def get_type(self):
        """Return 'ipv4' or 'ipv6' depending on the address type."""
        return self._type


    def is_ipv4(self):
        """Return True if the address is an IPv4 address."""
        return self._type == "ipv4"


    def is_ipv6(self):
        """Return True if the address is an IPv6 address."""
        return self._type == "ipv6"


    def ipv6_mapped(self):
        """
            Return the IPv6-mapped IPv4 address if it exists, otherwise, return the original IP.
            https://github.com/python/cpython/blob/86b8617747699416fcf9cd4ce6ea1da58a66f70e/Lib/ipaddress.py#L1403
        """
        if self._type == "ipv4":
            return IPv6Address(f'::ffff:{self._ip}')
        return self._ip