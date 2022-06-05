/*
 * namedhcp: a bridge between dhcpv6 and dns
 * host configuration = just give it a (fully qualified domain) name.
 * its ipv6 address will be given by this dhcp server (using the DNS).
 *
 * Copyright 2021 Renzo Davoli, Virtualsquare & University of Bologna
 *
 * namedhcp is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/random.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <stropt.h>
#include <libvdeplug.h>
#include <ioth.h>
#include <iothdns.h>
#include <iothconf.h>
#include <namedhcpv6.h>
#include <volatilestream.h>
#include <utils.h>
#define PACKETDUMP

#define TIMESHIFT2000 946684800

/* udpv6 headers */
struct udpv6_pkt {
	struct ether_header ethh;
	struct ip6_hdr ipv6h __attribute__((__packed__));
	struct udphdr udph __attribute__((__packed__));
	char payload[];
};

#define STDMTU 1500
#define ETH_HEADER_SIZE sizeof(struct ether_header)
#define ETHMTU (STDMTU + ETH_HEADER_SIZE)
#define DHCP_PACKET_SIZE (ETHMTU - offsetof(struct udpv6_pkt, payload))

static int verbose;
static char *cwd;
static int leave;
static pid_t mypid;

uint8_t macaddr[ETH_ALEN];
static inline int macaddr_isnull(void) {
	static const uint8_t nullmac[ETH_ALEN] = {0};
	return memcmp(macaddr, nullmac, ETH_ALEN) == 0;
}

#ifndef _GNU_SOURCE
static inline char *strchrnul(const char *s, int c) {
	while (*s && *s != c)
		s++;
	return (char *) s;
}
#endif

static void terminate(int signum) {
	pid_t pid = getpid();
	if (pid == mypid) {
		printlog(LOG_INFO, "(%d) leaving on signal %d", pid, signum);
		leave = 1;
	}
}

static void setsignals(void) {
	struct sigaction action = {
		.sa_handler = terminate
	};
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
}

static void copy_option(FILE *fin, FILE *fout, uint16_t opt_type, long pos) {
	if (pos > 0) {
		fput_uint16(fout, opt_type);
		fseek(fin, pos, SEEK_SET);
		uint16_t opt_len = fget_uint16(fin);
		fput_uint16(fout, opt_len);
		uint8_t buf[opt_len];
		fget_data(fin, buf, opt_len);
		fput_data(fout, buf, opt_len);
	}
}

static int cmp_option(FILE *f1, long pos1, FILE *f2, long pos2) {
	int retval;
	if (pos1 == 0 || pos2 == 0)
		return 0;
	fseek(f1, pos1, SEEK_SET);
	fseek(f2, pos2, SEEK_SET);
	uint16_t len1 = fget_uint16(f1);
	uint16_t len2 = fget_uint16(f2);
	if ((retval = len1 - len2) == 0) {
		uint8_t buf1[len1];
		uint8_t buf2[len2];
		fget_data(f1, buf1, len1);
		fget_data(f2, buf2, len2);
		retval = memcmp(buf1, buf2, len1);
	}
	//printf("cmp_optioncmp_option %d\n",retval);
	return retval;
}

/* backpatch option len */
static void set_optlen(FILE *f, long lenpos) {
	long endpos = ftell(f);
	fseek(f, lenpos, SEEK_SET);
	fput_uint16(f, endpos - lenpos - 2);
	fseek(f, endpos, SEEK_SET);
}

static void add_serverid(FILE *f, void *macaddr) {
	fput_uint16(f, OPTION_SERVERID);
	fput_uint16(f, 14);
	fput_uint16(f, 0x01); // DUID+TIME
	fput_uint16(f, 0x01); // Ethernet
	fput_uint32(f, time(NULL) - TIMESHIFT2000);
	fput_data(f, macaddr, 6);
}

static void add_aaaa_list(FILE *f, struct iothdns *iothdns, uint16_t optiontag, const char *inlist) {
	int tagc;
	if(inlist && (tagc = stropt(inlist, NULL, NULL, NULL)) > 0) {
		char buf[strlen(inlist)+1];
		char *tags[tagc];
		stropt(inlist, tags, NULL, buf);
		fput_uint16(f, optiontag);
		long lenpos = ftell(f);
		fput_uint16(f, 0); // len
		for (int i=0; i < tagc - 1; i++) {
			struct in6_addr ipv6addr[1];
			if (iothdns_lookup_aaaa(iothdns, tags[i], ipv6addr, 1) > 0)
				fput_data(f, ipv6addr, sizeof(ipv6addr[0]));
		}
		set_optlen(f, lenpos);
	}
}

static void add_fqdn_list(FILE *f, uint16_t optiontag, const char *inlist) {
	int tagc;
	if(inlist && (tagc = stropt(inlist, NULL, NULL, NULL)) > 0) {
		char buf[strlen(inlist)+1];
		char *tags[tagc];
		stropt(inlist, tags, NULL, buf);
		fput_uint16(f, optiontag);
		long lenpos = ftell(f);
		fput_uint16(f, 0); // len
		for (int i=0; i < tagc - 1; i++)
			fput_name(f, tags[i]);
		set_optlen(f, lenpos);
	}
}

static void add_iaaddr(FILE *f, void *ipaddr, uint32_t pref, uint32_t valid) {
	fput_uint16(f, OPTION_IAADDR);
	fput_uint16(f, 24); //len
	fput_data(f, ipaddr, 16);
	fput_uint32(f, pref);
	fput_uint32(f, valid);
}

#if 0
static void add_ipprefix(FILE *f, void *ipaddr, uint32_t pref, uint32_t valid, uint8_t prefixlen) {
	fput_uint16(f, OPTION_IAPREFIX);
	fput_uint16(f, 25); //len
	fput_uint32(f, pref);
	fput_uint32(f, valid);
	fput_uint8(f, prefixlen);
	fput_data(f, ipaddr, 16);
}
#endif

static void add_status_code(FILE *f, uint16_t code, char *msg) {
	size_t msglen = strlen(msg);
	fput_uint16(f, OPTION_STATUS_CODE);
	fput_uint16(f, 2 + msglen); //len
	fput_uint16(f, code);
	fput_data(f, msg, msglen);
}

static void hashiaid(void *ipaddr, void *iaid) {
	uint32_t *_ipaddr = ipaddr;
	uint32_t *_iaid = iaid;
	_iaid[0] = _ipaddr[2] ^ _ipaddr[3];
}

/* IANA stands for ID association for non-temporary address */
static void add_iana(FILE *f, void *ipaddr, void *iaid) {
	fput_uint16(f, OPTION_IA_NA);
	long lenpos = ftell(f);
	fput_uint16(f, 0); // len
	if (iaid)
		fput_data(f, iaid, 4);
	else {
		uint8_t _iaid[4];
		hashiaid(ipaddr, _iaid);
		fput_data(f, _iaid, 4);
	}
	fput_uint32(f, 0); // T1
	fput_uint32(f, 0); // T2
	add_iaaddr(f, ipaddr, ~0, ~0);
	set_optlen(f, lenpos);
}

static void add_oro_options(FILE *fin, FILE *fout, FILE *fopt, long oropos, long *pos) {
	if (oropos) {
		fseek(fin, oropos, SEEK_SET);
		for (uint16_t len = fget_uint16(fin); len > 0; len -= 2) {
			uint16_t orotag = fget_uint16(fin);
			copy_option(fopt, fout, orotag, pos[orotag]);
		}
	}
}

static void add_client_server_id(FILE *fin, FILE *fout, FILE *fopt, long clientpos, long serverpos) {
	if (clientpos) {
		copy_option(fin, fout, OPTION_CLIENTID, clientpos);
		copy_option(fopt, fout, OPTION_SERVERID, serverpos);
	}
}

static void parseopts(FILE *f, long *pos, int npos) {
	while (1) {
		uint16_t opt_type = fget_uint16(f);
		if (opt_type == 0)
			break;
		if (opt_type < npos)
			pos[opt_type] = ftell(f);
		uint16_t opt_len = fget_uint16(f);
		// printf("opt %d\n", opt_type);
		fseek(f, opt_len, SEEK_CUR);
	}
}

ssize_t dhcpparse(FILE *fin, FILE *fout, FILE *fopt, struct iothdns *iothdns) {
	/* -------------- parse the incoming dhcp request from fin -------------- */
	uint8_t dhcp_type = fget_uint8(fin);
	uint8_t dhcp_tid[3];
	long finpos[DHCPV6_OPTIONS] = {0};
	static long foptpos[DHCPV6_OPTIONS] = {0};
	if (foptpos[0] == 0) {
		foptpos[0] = 1;
		fseek(fopt, 0, SEEK_SET);
		parseopts(fopt, foptpos, DHCPV6_OPTIONS);
	}
	fget_data(fin, dhcp_tid, 3);
	parseopts(fin, finpos, DHCPV6_OPTIONS);
	/* -------------- compose the dhcp reply to fout -------------- */
	if (finpos[OPTION_CLIENT_FQDN] != 0 &&
			(finpos[OPTION_SERVERID] == 0 ||
			 cmp_option(fin, finpos[OPTION_SERVERID], fopt, foptpos[OPTION_SERVERID]) == 0)) {
		fseek(fin, finpos[OPTION_CLIENT_FQDN], SEEK_SET);
		uint16_t fqdn_len = fget_uint16(fin);
		char fqdn[fqdn_len];
		/* uint8_t fqdn_flags = */ fget_uint8(fin); // unused
		fget_name(fin, fqdn, fqdn_len);
		struct in6_addr ipv6addr[1];
		// printf("%d %s \n", fqdn_len, fqdn);
		switch (dhcp_type) {
			case DHCP_SOLICIT:
				if (iothdns_lookup_aaaa(iothdns, fqdn, ipv6addr, 1) > 0) {
					fput_uint8(fout, DHCP_ADVERTISE);
					fput_data(fout, dhcp_tid, 3);
					add_client_server_id(fin, fout, fopt, finpos[OPTION_CLIENTID], foptpos[OPTION_SERVERID]);
					add_iana(fout, ipv6addr, NULL);
					copy_option(fin, fout, OPTION_CLIENT_FQDN, finpos[OPTION_CLIENT_FQDN]);
					add_oro_options(fin, fout, fopt, finpos[OPTION_ORO], foptpos); // add_oro?
				}
				break;
			case DHCP_REQUEST:
			case DHCP_CONFIRM:
			case DHCP_RENEW:
			case DHCP_REBIND:
				fput_uint8(fout, DHCP_REPLY);
				fput_data(fout, dhcp_tid, 3);
				add_client_server_id(fin, fout, fopt, finpos[OPTION_CLIENTID], foptpos[OPTION_SERVERID]);
				if (iothdns_lookup_aaaa(iothdns, fqdn, ipv6addr, 1) > 0) { /// missing check iana
					add_iana(fout, ipv6addr, NULL);
					copy_option(fin, fout, OPTION_CLIENT_FQDN, finpos[OPTION_CLIENT_FQDN]);
					add_oro_options(fin, fout, fopt, finpos[OPTION_ORO], foptpos);
				} else {
					add_status_code(fout, 4, "invalid addr");
					copy_option(fin, fout, OPTION_CLIENT_FQDN, finpos[OPTION_CLIENT_FQDN]);
				}
				break;
			case DHCP_RELEASE:
			case DHCP_DECLINE:
				add_client_server_id(fin, fout, fopt, finpos[OPTION_CLIENTID], foptpos[OPTION_SERVERID]);
				add_status_code(fout, 0, "success");
		}
		return ftell(fout);
	}
	return 0;
}

/* UDP via ioth stack */
int open_iface(struct ioth *stack, char *ifname) {
	static const uint8_t dhcpip[16] = {0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x02};
	int fd = -1;
	struct sockaddr_in6 bindaddr = {
		.sin6_family = AF_INET6
	};
	int ttl=1;
	int one=1;
	unsigned int ifindex;
	struct ipv6_mreq mc_req;
	if ((ifindex = ioth_if_nametoindex(stack, ifname)) == 0)
		goto error;
	if (macaddr_isnull() && ioth_linkgetaddr(stack, ifindex, macaddr) < 0)
		goto error;
	if ((fd=ioth_msocket(stack, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		goto error;
	if ((ioth_setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
					&ttl, sizeof(ttl))) < 0)
		goto error;
	if ((ioth_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
					&one, sizeof(one))) < 0)
		goto error;
	if (ioth_setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				ifname, strlen(ifname) + 1) < 0)
		goto error;
	memcpy(&bindaddr.sin6_addr, &in6addr_any, sizeof(in6addr_any));
	bindaddr.sin6_port        = htons(DHCP_SERVERPORT);
	bindaddr.sin6_scope_id    = ifindex;
	if ((ioth_bind(fd, (struct sockaddr *) &bindaddr, sizeof(bindaddr))) < 0)
		goto error;
	memcpy(&mc_req.ipv6mr_multiaddr, dhcpip, 16);
	mc_req.ipv6mr_interface = ifindex;
	if ((ioth_setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
					&mc_req, sizeof(mc_req))) < 0)
		goto error;
	if (macaddr_isnull()) ioth_linkgetaddr(stack, ifindex, macaddr);
	return fd;
error:
	printlog(LOG_ERR, "Error opening interface %s: %s", ifname, strerror(errno));
	if (fd >= 0)
		ioth_close(fd);
	return -1;
}

void main_iface_loop(int fd, FILE *fopt, struct iothdns *iothdns) {
	struct sockaddr_in6 from;
	socklen_t fromlen;
	ssize_t inlen;
	ssize_t outlen;

	while (! leave) {
		uint8_t inbuf[DHCP_PACKET_SIZE], outbuf[DHCP_PACKET_SIZE];
		inlen = ioth_recvfrom(fd, inbuf, sizeof(inbuf), 0, (struct sockaddr *) &from, &fromlen);
		if (inlen < 0)
			break;
		FILE *fin = fmemopen(inbuf, inlen, "r");
		FILE *fout = fmemopen(outbuf, DHCP_PACKET_SIZE, "w");
#ifdef PACKETDUMP
		if (verbose) {
			fprintf(stderr, "INPACKET %zd\n", inlen);
			packetdump(stderr, inbuf, inlen);
		}
#endif
		if ((outlen = dhcpparse(fin, fout, fopt, iothdns)) > 0) {
#ifdef PACKETDUMP
			if (verbose) {
				fprintf(stderr, "OUTPACKET %zd\n", outlen);
				packetdump(stderr, outbuf, outlen);
			}
#endif
			fflush(fout);
			ioth_sendto(fd, outbuf, outlen, 0,  (struct sockaddr *) &from, fromlen);
		}
		fclose(fin);
		fclose(fout);
	}
}

/* UDP emulation via VDE */

static uint8_t myllip[16] = {0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xfe,0x00,0x00,0x00};
static void vde_macaddr(void) {
	if (macaddr_isnull()) {
		ssize_t n = getrandom(macaddr, ETH_ALEN, 0);
		(void) n;
		macaddr[0] = (macaddr[0] & ~0x1) | 0x02;
	}
	myllip[8]  = macaddr[0] ^ 0x02;
	myllip[9]  = macaddr[1];
	myllip[10] = macaddr[2];
	myllip[13] = macaddr[3];
	myllip[14] = macaddr[4];
	myllip[15] = macaddr[5];
}

/* checksum computation helper function */
static unsigned int chksum(unsigned int sum, const void *vbuf, size_t len) {
	unsigned const char *buf = vbuf;
	size_t i;
	for (i = 0; i < len; i++)
		sum += (i % 2) ? buf[i] : buf[i] << 8;
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);
	return sum;
}

/* select input packets */
static int ch_inpkt(struct udpv6_pkt *inpkt) {
	/* multicast IPv6 address for DHCP */
	static uint8_t dhcp_ethernet_addr[]={0x33,0x33,0x00,0x01,0x00,0x02};
	if (! (memcmp(inpkt->ethh.ether_dhost, dhcp_ethernet_addr, ETH_ALEN) == 0 ||
				memcmp(inpkt->ethh.ether_dhost, macaddr, ETH_ALEN) == 0))
		return 0;
	if (ntohs(inpkt->ethh.ether_type) != 0x86dd) return 0; // this is not IPv6
	if (inpkt->ipv6h.ip6_vfc >> 4 != 6) return 0; //this is not IPv6
	if (! IN6_IS_ADDR_LINKLOCAL(inpkt->ipv6h.ip6_src.s6_addr)) return 0; //this is not Link Local
	if (inpkt->ipv6h.ip6_nxt != 17) return 0; //this is not UDP
	if (ntohs(inpkt->udph.dest) != DHCP_SERVERPORT) return 0; /* wrong destination port */
	return 1;
}

/* fill in fields of output packets */
static void fill_outpkt(struct udpv6_pkt *outpkt, long outlen) {
	unsigned int sum = 0;
	static const char isudp[2] = {0x00,0x11};
	long iplen = outlen - offsetof(struct udpv6_pkt, udph);
	/* ETH */
	memcpy(outpkt->ethh.ether_dhost, outpkt->ethh.ether_shost, ETH_ALEN);
	memcpy(outpkt->ethh.ether_shost, macaddr, ETH_ALEN);
	/* IP */
	memcpy(outpkt->ipv6h.ip6_dst.s6_addr, outpkt->ipv6h.ip6_src.s6_addr, 16);
	memcpy(outpkt->ipv6h.ip6_src.s6_addr, myllip, 16);
	outpkt->ipv6h.ip6_plen = htons(iplen);
	/* UDP */
	outpkt->udph.dest = outpkt->udph.source;
	outpkt->udph.source = htons(DHCP_SERVERPORT);
	outpkt->udph.len = outpkt->ipv6h.ip6_plen;
	/* udp checkum */
	outpkt->udph.check = 0;
	sum = chksum(sum, outpkt->ipv6h.ip6_src.s6_addr, 16);
	sum = chksum(sum, outpkt->ipv6h.ip6_dst.s6_addr, 16);
	sum = chksum(sum, isudp, 2);
	sum = chksum(sum, &outpkt->ipv6h.ip6_plen, 2);
	sum = chksum(sum, (char *) &outpkt->udph, iplen);
	outpkt->udph.check = htons(~sum);
}

void main_vde_loop(VDECONN *conn, FILE *fopt, struct iothdns *iothdns) {
	while (! leave) {
		uint8_t inbuf[ETHMTU];
		uint8_t outbuf[ETHMTU];
		ssize_t inlen;
		ssize_t outlen;
		inlen = vde_recv(conn, inbuf, ETHMTU, 0);
		if (inlen >= (ssize_t) sizeof(struct udpv6_pkt)) {
			struct udpv6_pkt *inpkt = (void *) inbuf;
			struct udpv6_pkt *outpkt = (void *) outbuf;
			if (! ch_inpkt(inpkt)) continue;
			*outpkt = *inpkt; // copy the headers
#ifdef PACKETDUMP
			if (verbose) {
				fprintf(stderr, "INPACKET vde %zd\n",inlen);
				packetdump(stderr, inbuf, inlen);
			}
#endif
			FILE *fin = fmemopen(inpkt->payload, inlen - sizeof(struct udpv6_pkt), "r");
			FILE *fout = fmemopen(outpkt->payload, DHCP_PACKET_SIZE, "w");
			if ((outlen = dhcpparse(fin, fout, fopt, iothdns)) > 0) {
				fflush(fout);
				outlen += sizeof(struct udpv6_pkt);
				fill_outpkt(outpkt, outlen);
#ifdef PACKETDUMP
				if (verbose) {
					fprintf(stderr, "OUTPACKET vde %zd\n", outlen);
					packetdump(stderr, outbuf, outlen);
				}
#endif
				vde_send(conn, outbuf, outlen, 0);
			}
			fclose(fin);
			fclose(fout);
		}
	}
}

/* Main and command line args management */
void usage(char *progname)
{
	fprintf(stderr,"Usage: %s OPTIONS\n"
			"\t--stack|-s <ioth_stack_conf> or VNL\n"
			"\t           (it uses a udpv6 emulation if this is a VDE VNL)\n"
			"\t--dnsstack|-R <resolver_ioth_stack_conf>)\n"
			"\t           (default: kernel stack if the --stack is a VNL, the same of --stack otherwise)\n"
			"\t--rcfile|-f <conffile>\n"
			"\t--iface|-i <interface>            (only for ioth stack,	default value vde0)\n"
			"\t--resolvconf|-r <resolvconf_file> (used by this dhcp server, syntax see resolv.conf(5))\n"
			"\t--nameserver|-n <dns_server_list> (used by this dhcp server)\n"
			"\t--macaddr|-m <mac_address>        (set the dhcp server MAC addr\n"
			"\t--dns|-D <dns_server_list>        (dhcp option sent to clients)\n"
			"\t--dnssearch|-S <domain_list>      (dhcp option sent to clients)\n"
			"\t--ntp|-N <ntp_server_list>        (dhcp option sent to clients)\n"
			"\t--daemon|-d\n"
			"\t--pidfile|-p <pidfile>\n"
			"\t--verbose|-v\n"
			"\t--help|-h\n",
			progname);
	exit(1);
}

static char *short_options = "hdvf:p:s:R:i:n:r:m:D:N:S:";
static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"daemon", 0, 0, 'd'},
	{"verbose", 0, 0, 'v'},
	{"rcfile", 1, 0, 'f'},
	{"pidfile", 1, 0, 'p'},
	{"stack", 1, 0, 's'},
	{"dnsstack", 1, 0, 'R'},
	{"iface", 1, 0, 'i'},
	{"nameserver", 1, 0, 'n'},
	{"resolvconf", 1, 0, 'r'},
	{"macaddr", 1, 0, 'm'},
	{"dns", 1, 0, 'D'},
	{"ntp", 1, 0, 'N'},
	{"dnssearch", 1, 0, 'S'},
	{0,0,0,0}
};

static char *arg_tags = "dvpsRinrmDNS";
static union {
	struct {
		char *daemon;
		char *verbose;
		char *pidfile;
		char *stack;
		char *dnsstack;
		char *iface;
		char *nameserver;
		char *resolvconf;
		char *macaddr;
		char *dns;
		char *ntp;
		char *dnssearch;
	};
	char *argv[sizeof(arg_tags)];
} args;

static inline int argindex(char tag) {
	return strchrnul(arg_tags, tag) - arg_tags;
}

int parsercfile(char *path, struct option *options) {
	int retvalue = 0;
	FILE *f = fopen(path, "r");
	if (f == NULL) return -1;
	char *line = NULL;
	size_t len;
	for (int lineno = 1; getline(&line, &len, f) > 0; lineno++) { //foreach line
		char *scan = line;
		while (*scan && strchr("\t ", *scan)) scan++; //ship heading spaces
		if (strchr("#\n", *scan)) continue; // comments and empty lines
		int len = strlen(scan);
		char optname[len], value[len];
		// parse the line
		*value = 0;
		/* optname <- the first alphanumeric field (%[a-zA-Z0-9])
			 value <- the remaining of the line not including \n (%[^\n])
			 and discard the \n (%*c) */
		if (sscanf (line, "%[a-zA-Z0-9] %[^\n]%*c", optname, value) > 0) {
			struct option *optscan;
			for (optscan = options; optscan->name; optscan++) // search tag
				if (strcmp(optscan->name, optname) == 0)
					break;
			int index; // index of short opt tag in arg_tags
			if (optscan->name == NULL ||
					arg_tags[index = strchrnul(arg_tags, optscan->val) - arg_tags] == '\0') {
				fprintf(stderr,"%s (line %d): parameter error %s\n", path, lineno, optname);
				errno = EINVAL, retvalue |= -1;
			} else if (args.argv[index] == NULL) // overwrite only if NULL
				args.argv[index] = *value ? strdup(value) : "";
		} else {
			fprintf(stderr,"%s (line %d): syntax error\n", path, lineno);
			errno = EINVAL, retvalue |= -1;
		}
	}
	fclose(f);
	if (line) free(line);
	return retvalue;
}

/* fopt is a volatile file. it stores the server defined
 * options whose value does not depend from the query.
 * these options are ready to be copied when needed in the output packets */

FILE *foptcreate(struct iothdns *iothdns) {
	FILE *fopt = volstream_open();
	add_aaaa_list(fopt, iothdns, OPTION_DNS_SERVERS, args.dns);
	add_fqdn_list(fopt, OPTION_DOMAIN_LIST, args.dnssearch);
	add_aaaa_list(fopt, iothdns, OPTION_SNTP_SERVERS, args.ntp);
	add_serverid(fopt, macaddr);
	return fopt;
}

struct iothdns *open_iothdns(struct ioth *dnsstack) {
	char *dnsconfig = NULL;
	if (args.nameserver) {
		size_t flen = 0;
		FILE *f = open_memstream(&dnsconfig, &flen);
		int tagc;
		if((tagc = stropt(args.nameserver, NULL, NULL, NULL)) > 0) {
			char buf[strlen(args.nameserver)+1];
			char *tags[tagc];
			stropt(args.nameserver, tags, NULL, buf);
			for (int i=0; i < tagc - 1; i++)
				fprintf(f,"nameserver %s\n", tags[i]);
		}
		fclose(f);
	}
	if (dnsconfig == NULL && dnsstack != NULL && args.resolvconf == NULL)
		dnsconfig = ioth_resolvconf(dnsstack, NULL);
	if (dnsconfig != NULL) {
		struct iothdns *retval = iothdns_init_strcfg(dnsstack, dnsconfig);
		free(dnsconfig);
		return retval;
	} else {
		return iothdns_init(dnsstack, args.resolvconf);
	}
}

int main(int argc, char *argv[])
{
	char *progname = basename(argv[0]);
	char *rcfile = NULL;
	int option_index;
	while(1) {
		int c;
		if ((c = getopt_long (argc, argv, short_options,
						long_options, &option_index)) < 0)
			break;
		switch (c) {
			case 'f':
				rcfile = optarg;
				break;
			case -1:
			case '?':
			case 'h': usage(progname); break;
			default: {
								 int index = argindex(c);
								 if (args.argv[index] == NULL)
									 args.argv[index] = optarg ? optarg : "";
							 }
								break;
		}
	}
	if (argc == 1 || optind < argc)
		usage(progname);

	if (rcfile && parsercfile(rcfile, long_options) < 0) {
		fprintf(stderr, "configfile %s: %s\n", rcfile, strerror(errno));
		exit(1);
	}

	if (args.verbose) verbose = 1;

	startlog(progname, args.daemon != NULL);
	mypid = getpid();
	setsignals();
	/* saves current path in cwd, because otherwise with daemon() we
	 * forget it */
	if((cwd = getcwd(NULL, 0)) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	if (args.daemon && daemon(0, 0)) {
		printlog(LOG_ERR,"daemon: %s", strerror(errno));
		exit(1);
	}

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(args.pidfile) save_pidfile(args.pidfile, cwd);

	struct ioth *dnsstack = NULL;
	if (args.dnsstack) {
		if ((dnsstack = ioth_newstackc(args.dnsstack)) == NULL) {
			printlog(LOG_ERR, "dnsstack: %s", strerror(errno));
			exit(1);
		}
	}
	if (args.macaddr) {
		if (sscanf(args.macaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
					macaddr, macaddr + 1, macaddr + 2, macaddr + 3, macaddr + 4, macaddr + 5) < 6) {
			printlog(LOG_ERR, "macaddr: format error");
			exit(1);
		}
	}
	if (stropt(args.stack, NULL, NULL, NULL) == 2 // 1 arg
			&& strstr(args.stack, "://")) { // and it has a VNL syntax
		/* VDE case, + UDP emulation */
		VDECONN *vdeconn = vde_open(args.stack, "DHCPv6", NULL);
		if (vdeconn == NULL) {
			printlog(LOG_ERR, "vde_open: %s", strerror(errno));
			exit(1);
		}
		vde_macaddr();
		struct iothdns *iothdns = open_iothdns(dnsstack);
		FILE *fopt = foptcreate(iothdns);
		main_vde_loop(vdeconn, fopt, iothdns);
		vde_close(vdeconn);
		fclose(fopt);
	} else {
		/* ioth stack case */
		struct ioth *stack = ioth_newstackc(args.stack);
		if (stack == NULL) {
			printlog(LOG_ERR, "ioth_newstack: %s", strerror(errno));
			exit(1);
		}
		if (dnsstack == NULL) dnsstack = stack;
		if (args.iface == NULL) args.iface = "vde0";
		int fd = open_iface(stack, args.iface);
		// printf("%d\n", fd);
		if (fd >= 0) {
			struct iothdns *iothdns = open_iothdns(dnsstack);
			FILE *fopt = foptcreate(iothdns);
			main_iface_loop(fd, fopt, iothdns);
			ioth_close(fd);
			fclose(fopt);
		}
	}
}
