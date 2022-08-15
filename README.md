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

## `namedhcp` and `namedhcp4` command line syntax

The syntax of the `namedhcp` and `namedhcp4` command is the same:
```
namedhcp OPTIONS
namedhcp4 OPTIONS
```
where options are:

* `--rcfile|-f <conffile>`: read the options from a configuration file, see the next section.
* `--stack|-s <ioth_stack_conf> or VNL`: the configuration of the ioth stack to provide the dhcp service
(using the syntax of `ioth_newstackc` in [iothconf](https://github.com/virtualsquare/iothconf)) OR
a VDE VNL  (see [vdeplug4](https://github.com/rd235/vdeplug4)). In this latter case a UDPv6 emulation
is used. `namedhcp` uses the kernel stack if this option is omitted.
* `--dnsstack|-R <resolver_ioth_stack_conf>`: the configuration of the stack used to DNS queries.
If this option is omitted the same stack used for dhcp is used (or the kernel stack if `--stack`
argument is a VNL)
* `--iface|-i <interface>`: select the inteerface for dhcp (default value `vde0`)
* `--resolvconf|-r <resolvconf_file>`: resolv.conf file (see resolv.conf(5)), `/etc/resolv.conf` if omitted.
* `--nameserver|-n <dns_server_list>`: set a list of dns servers (alternative to `--resolvconf`).
* `--macaddr|-m <mac_address>`: set the dhcp server MAC addr.
* `--dns|-D <dns_server_list>`: dhcp option sent to clients (option 23, RFC 8415 -- option 6,
RFC 2132 for IPv4)
* `--dnssearch|-S <domain_list>`: dhcp option sent to clients (option 24, RFC 8415 -- option 15,
RFC 2132 for IPv4)
* `--ntp|-N <ntp_server_list>`: dhcp option sent to clients (option 31, RFC 8415 -- option 42,
RFC 2132 for IPv4)
* `--daemon|-d`: run the program in daemon mode (see daemon(3)).
* `--pidfile|-p <pidfile>`: save the pid in the file (useful for scripts).

## configuration file syntax

The configuration file loaded using the option `-f` or `--rcfile` has the following syntax:

* lines beginning by '#' are comments.
* the other lines have a tag and may have an argument if required by the tag.
The tags have the same name of the long options (`--something`) of the command line, their arguments
have the same syntax and meaning of each equivalent command line option.
Command line arguments have priority on the configuration file specifications:
if the same tag is specified as a command line option and in the configuration file, the value
in the command line is taken and the other ignored.

```
      stack      <ioth_stack_conf> or VNL
      dnsstack   <resolver_ioth_stack_conf>
      iface      <interface>
      resolvconf <resolvconf_file>
      nameserver <dns_server_list>
      macaddr    <mac_address>
      dns        <dns_server_list>
      dnssearch  <domain_list>
      ntp        <ntp_server_list>
      daemon
      pidfile    <pidfile>
```

## `namedhcp` examples:

In IPv6 the network prefix and the router address is normally provided by the Router Advertisement/
Router Solicitation protocol as defined in "Neighbor
Discovery  for  IP Version 6 (IPv6)" (RFC 4861).

DHCPv6 provides the host/node address, and other configuration parameters (like DNS or NTP servers).

The first example tests how to configure some network nodes using pre-defined addresses, in a second
example we'll see how to use hash based addresses.

First of all let we start a VDE network. For example we can use a virtual HUB (useful if you
want to add a vdens and trace all the networks packets using wireshark).

```
$ vde_plug null:// hub:///tmp/hub
```

The IPv6 network used in this test is not connected to the Internet and has no router, thus we
need a router advertisement daemon server to provide nodes with the right prefix.
This step is not needed if real global IPv6 addresses are used and the network is routed to the Internet.
```
iothradvd -s vde:///tmp/hub -P 10 fc00::/64/L/86400/14400
```

Then we need to set up a DNS server providing the IPv6
Let us write the following configuration file for iothnamed (named `iothnamed.dhcp.test`):
```
rstack    stack=vdestack,vnl=vde:///tmp/hub
rstack    mac=80:01:01:01:01:01,eth
rstack    ip=fc00::24/64
fstack    stack=kernel

dns       8.8.8.8
dns       80.80.80.80

net       local fc00::/64
auth      accept local

auth      static local .test.local
auth      static local fc00::/64

static    AAAA one.test.local fc00::1
static    AAAA two.test.local fc00::2
static    PTR fc00::1 one.test.local
static    PTR fc00::2 two.test.local

auth      cache local .
auth      fwd local .
```
and start the DNS server:
```
iothnamed iothnamed.dhcp.test
```

The next step consists of starting the namedhcp server:
```
$ namedhcp -s "stack=vdestack,vnl=vde:///tmp/hub,ip=fc00::ffff/64,eth" -n fc00::24
```

Now the infrastructure is complete and we can start two vdens.
```
$ vdens -R fc00::24 /tmp/hub
$ ip link set vde0 up
$ echo 'send fqdn.fqdn "one.test.local";' > one.conf
$ truncate -s 0 one.leases
$ /sbin/dhclient -6 -cf one.conf -v vde0 -lf one.leases -pf /dev/null
```

ad the other is:
```
$ vdens -R fc00::24 /tmp/hub
$ ip link set vde0 up
$ echo 'send fqdn.fqdn "two.test.local";' > two.conf
$ truncate -s 0 two.leases
$ /sbin/dhclient -6 -cf two.conf -v vde0 -lf two.leases -pf /dev/null
```

Now it is possible to ping one vdens from the other and viceversa.
```
$ ping -n  two.test.local
```
```
$ ping -n one.test.local
```

A second example involves hash based ipv6 addresses.

Use the VDE network previously defined for the first experiment or restart it:
```
vde_plug null:// hub:///tmp/hub
```

the configration for the name server iothnamed is the file `iothnamed.hash.test`:
```
rstack    stack=vdestack,vnl=vde:///tmp/hub
rstack    mac=80:01:01:01:01:01,eth
rstack    ip=fc00::24/64
fstack    stack=kernel

dns       8.8.8.8
dns       80.80.80.80

net       local fc00::/64
auth      accept local

auth      static local hash.local
static    AAAA hash.local fc00::

auth      hash local .hash.local hash.local
auth      hrev local hash.local/64

auth      cache local .
auth      fwd local .

option hrevmode always
```
thus the iothnamed server can be started:
```
iothnamed iothnamed.hash.test
```

The `namedhcp` can be started as in the previous example
```
namedhcp -s "stack=vdestack,vnl=vde:///tmp/hub,ip=fc00::ffff/64,eth" -n fc00::24
```
as well as the radvd (given that the test netowrk has not a real router):
```
iothradvd -s vde:///tmp/hub -P 10 fc00::/64/L/86400/14400
```

Start two (or more) vdens:
```
$ vdens -R fc00::24 /tmp/hub
$ ip link set vde0 up
$ echo 'send fqdn.fqdn "h1.hash.local";' > h1.conf
$ truncate -s 0 h1.leases
$ /sbin/dhclient -6 -cf h1.conf -v vde0 -lf h1.leases -pf /dev/null
```

and
```
$ vdens -R fc00::24 /tmp/hub
$ ip link set vde0 up
$ echo 'send fqdn.fqdn "h2.hash.local";' > h2.conf
$ truncate -s 0 h2.leases
$ /sbin/dhclient -6 -cf h2.conf -v vde0 -lf h2.leases -pf /dev/null
```

... Several nodes can be added just by naming them `something.hash.local`. Each node receives its own
IPv6 address via DHCP and the DNS is able to resolve its name without any specific configuration.

## `namedhcp4` examples:

IPv4 has a narrow address set so it is not possible to use hash based IP addresses.
Anyway a DHCPv4 server retrieving the address from the DNS can be useful: the configuration
of IP addresses, masks, routing can be gotten from the DNS. In this way hosts, as well as namespaces,
virtual machines or IoTh processes can be configured given their fully qualified domain name (FQDN) only.
Updates of the hardware settings (e.g. using a different network interface) or relocating
virtual network nodes require in this way no changes in their configuration.

This example needs a DNS server able to resolve the FQDNs of the hosts. For each host the IP address
returned by `namedhcpv4` is the A record defined in the DNS.
For the other DHCP options `namedhcpv4` uses a TXT record, a list of tag=value entries. e.g.:
```
mask=255.255.255.0,broadcast=192.168.1.255,router=192.168.1.254,dns=192.168.1.24
```

This example uses a VDE network. In a terminal window type:
```
vde_plug null:// hub:///tmp/hub
```

A test configuration file for [iothnamed](https://github.com/virtualsquare/iothnamed) is the follwing:
```
## example: define local names and forward other request.

rstack    stack=vdestack,vnl=vde:///tmp/hub
rstack    mac=80:01:01:01:01:01,eth
rstack    ip=192.168.1.24/24
fstack    stack=kernel

dns       8.8.8.8
dns       80.80.80.80

net       local 192.168.1.0/24
auth      accept local
auth      static local .test.local
auth      static local 192.168.1.0/24
auth      cache local .
auth      fwd local .

static    A one.test.local 192.168.1.1
static    TXT one.test.local "mask=255.255.255.0,broadcast=192.168.1.255,router=192.168.1.254,dns=192.168.1.24"
static    A two.test.local 192.168.1.2
static    TXT two.test.local "mask=255.255.255.0,broadcast=192.168.1.255,router=192.168.1.254,dns=192.168.1.24"
static    PTR 192.168.1.1 one.test.local
static    PTR 192.168.1.2 two.test.local
```

Let us name the configuration above `namedhcp4.named.conf`.

The `iothnamed` service can be start by the command (at a shell prompt, e.g. a terminal window):
```
$ iothnamed namedhcp4.named.conf
```

Now start `namedhcp4`:
```
$ namedhcp4 -s "stack=vdestack,vnl=vde:///tmp/hub,ip=192.168.1.25/24,eth" -n 192.168.1.24
```

The infrastructure is complete.

Let us start two `vdens` and configure them just by naming them `one.test.local` and
`two.test.local`. We need a trick as glibc has the file `/etc/resolv/conf` hardcoded in its source code
(see [this comment on VirtualSquare wiki](http://localhost:8008/#!vbetter/vresolvconf.md))

We'll use `udhcpc` provided as a service by busybox, and the following `dhcpscript`:
```
#!/bin/busybox sh
#set -x

RESOLV_CONF="/etc/resolv.conf"

[ -z "$1" ] && echo 'Error: should be called from udhcpc' && exit 1

case "$1" in
  deconfig)
    # bring interface up, but with no IP configured:
    ip addr flush dev $interface
    ip link set $interface up
    ;;
  bound)
    # configure interface and routes:
    ip addr flush dev $interface
    ip addr add ${ip}/${mask} dev $interface
    [ -n "$router" ] && ip route add default via ${router%% *} dev $interface
    # set the DNS
    [ -n "$domain" ] && R="domain $domain" || R=""
    for i in $dns; do
      R="$R
nameserver $i"
    done
    echo "$R" > "$RESOLV_CONF"

    ;;
  renew)
    ;;
esac

exit 0
```

Start the first vdens:
```
$ touch /tmp/rc1
$ vdens -r /tmp/rc1 /tmp/hub
$ busybox udhcpc -s dhcpscript -f -q -F one.test.local -i vde0
```

and the second:
```
$ touch /tmp/rc2
$ vdens -r /tmp/rc2 /tmp/hub
$ busybox udhcpc -s dhcpscript -f -q -F two.test.local -i vde0
```

Now it is possible to ping the second from the fist and viceversa.
```
$ ping -n two.test.local
PING two.test.local (192.168.1.2) 56(84) bytes of data.
64 bytes from 192.168.1.2: icmp_seq=1 ttl=64 time=0.379 ms
...
```

```
$ ping -n one.test.local
PING one.test.local (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.303 ms
...
```

The two namespaces have been configured just by defining their FQDN, no IP
address appears in any command.
