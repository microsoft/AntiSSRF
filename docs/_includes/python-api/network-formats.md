Networks can be:
* IPv4 addresses in dotted-quad notation
    * ex. `127.0.0.1`
* IPv6 addresses in expanded notation `x:x:x:x:x:x:x:x`, where the `x`s are one to four hexadecimal digits
    * ex. `ABCD:EF01:2345:6789:ABCD:EF01:2345:6789`
* IPv6 addresses in compressed notation, where one group of consecutive 0s is represented with `::`
    * ex. `ABCD::`, `::1`, `ABCD:EF01::2345:6789`
* IPv6 in mixed notation `x:x:x:x:x:x:d.d.d.d`, where the `x`s are hexadecimal values and the `d`s are decimal
    * ex. `::FFFF:127.0.0.1`
* Any of the above addresses with a decimal prefix length `<ip-address>/<prefix-length>` 
    * ex. `192.0.2.0/24`, `2001:db8::/32`
