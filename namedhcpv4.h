#ifndef NAMEDHCPV4_H
#define NAMEDHCPV4_H

#include <stdint.h>
#include <netinet/in.h>

#define   DHCP_CLIENTPORT   68
#define   DHCP_SERVERPORT   67

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

#define OPTION_PAD        0
#define OPTION_MASK       1
#define OPTION_ROUTER     3
#define OPTION_DNS        6
#define OPTION_HOSTNAME  12
#define OPTION_DOMNAME   15
#define OPTION_BROADCAST 28
#define OPTION_NTP       42
#define OPTION_REQIP     50
#define OPTION_LEASETIME 51
#define OPTION_TYPE      53
#define OPTION_SERVID    54
#define OPTION_PARLIST   55
#define OPTION_FQDN      81
#define OPTION_DOMAIN_LIST      119
#define OPTION_END      255

#define STDSERVID 0
#define STDRENEW 0
#define STDREBIND 0
#define STDPREF ~0
#define STDVALID ~0

#define BOOTREQUEST 1
#define BOOTREPLY 2

__attribute__((__packed__)) struct bootphdr {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint8_t xid[4];
	uint8_t secs[2];
	uint8_t flags[2];
	struct in_addr ciaddr;
	struct in_addr yiaddr;
	struct in_addr siaddr;
	struct in_addr giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
};

#define BOOTP_VEND_LEN 64
#define BOOTP_MINLEN (sizeof(struct bootp_hdr) + BOOTP_VEND_LEN)

#endif
