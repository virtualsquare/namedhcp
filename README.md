# namedhcp
### call me but love.mydomain.org and I'll be new addressed

`namedhcp`  is an IPv6 DHCP server implementation for IPV6 stateful
autoconfiguration.  When `namedhcp` receives a DHCP query including the `fqdn`
option (option 39 as defined in RFC4704) it queries the DNS for an AAAA record.
If there is such a record, the IPv6 address is returned to the DHCP client.

The configuration of the networking nodes (hosts, servers, internet of things
objects, internet of threads processes)
is very simple in this way, it is sufficient to provide  each
node with its own fully qualified domain name.  It very convenient to use this
tool is together with
[`iothnamed`](https://github.com/virtualsquare/iothnamed)
configured to provide hash based IP addresses.
In fact, each node provided with a fully qualified domain name can receive from
`iothnamed` (through  `namedhcp`)  its  corresponding  hash based IPv6 address and
it is reachable by that name without any further configuration.

The same idea of `namedhcp` can be used in IPV4. Hash based addresses cannot be implemented in IPv4 due to the narrow
address space provided by four bytes only.
Anyway the ability to provide hosts with IPv4 addresses depending only on their names (fully qualified names) is useful for
network administrators aiming to manage large numbers of hosts (and networking namespaces).
`namedhcp4` permits to keep the map of the name to address translation in one file. This information is
neither distributed on several hosts or file
nor duplicated.
Without `namedhcp4`, IPv4 addresses need to be configured consistently both on the host (or on the dhcp server)
and in the dns server configuration files.

## Install
Install prerequisite libraries:
libioth volatilestream iothdns iothconf stropt vdeplug

Get the source code, from the root of the source tree run:
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```
