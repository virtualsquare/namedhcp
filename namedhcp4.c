/*
 * namedhcp4: a bridge between dhcp and dns (for IPv4)
 * host configuration = just give it a (fully qualified domain) name.
 * its ip address will be given by this dhcp server (using the DNS).

 * Copyright 2021 Renzo Davoli, Virtualsquare & University of Bologna
 *
 * namedhcp4 is free software; you can redistribute it and/or
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
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <net/if.h>
#include <stropt.h>
#include <strcase.h>
#include <libvdeplug.h>
#include <ioth.h>
#include <iothdns.h>
#include <iothconf.h>
#include <namedhcpv4.h>
#include <volatilestream.h>
#include <utils.h>
#define PACKETDUMP

struct bootp_pkt {
	struct ether_header ethh;
	struct iphdr iph __attribute__((__packed__));
	struct udphdr udph __attribute__((__packed__));
	struct bootphdr bootph __attribute__((__packed__));
	char dhcpdata[];
};

#define STDMTU 1500
#define ETH_HEADER_SIZE sizeof(struct ether_header)
#define ETHMTU (STDMTU + ETH_HEADER_SIZE)
#define DHCP_PACKET_SIZE (ETHMTU - offsetof(struct bootp_pkt, dhcpdata))
#define BOOTP_VEND_LEN 64

static int verbose;
static char *cwd;
static int leave;
static pid_t mypid;

uint8_t macaddr[ETH_ALEN];

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

static inline int macaddr_isnull(void) {
	static const uint8_t nullmac[ETH_ALEN] = {0};
	return memcmp(macaddr, nullmac, ETH_ALEN) == 0;
}

static int copy_option(FILE *fin, FILE *fout, uint8_t opt_type, long *finpos) {
	long pos = finpos[opt_type];
	if (pos  > 0) {
		fput_uint8(fout, opt_type);
		fseek(fin, pos, SEEK_SET);
		uint16_t opt_len = fget_uint8(fin);
		fput_uint8(fout, opt_len);
		uint8_t buf[opt_len];
		fget_data(fin, buf, opt_len);
		fput_data(fout, buf, opt_len);
		return 0;
	} else
		return -1;
}

static int cmp_option(FILE *f1, long pos1, FILE *f2, long pos2) {
	int retval;
	if (pos1 == 0 || pos2 == 0)
		return 0;
	fseek(f1, pos1, SEEK_SET);
	fseek(f2, pos2, SEEK_SET);
	uint16_t len1 = fget_uint8(f1);
	uint16_t len2 = fget_uint8(f2);
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

static void set_optlen(FILE *f, long lenpos) {
	long endpos = ftell(f);
	fseek(f, lenpos, SEEK_SET);
	fput_uint8(f, endpos - lenpos - 1);
	fseek(f, endpos, SEEK_SET);
}

// add options, tag only, then integer...
static void add_tag(FILE *f, uint8_t optiontag) {
	fput_uint8(f, optiontag);
}

static void add_uint8(FILE *f, uint8_t optiontag, uint8_t value) {
	fput_uint8(f, optiontag);
	fput_uint8(f, sizeof(value));
	fput_uint8(f, value);
}

#if 0 // unused
static void add_uint16(FILE *f, uint8_t optiontag, uint16_t value) {
	fput_uint8(f, optiontag);
	fput_uint8(f, sizeof(value));
	fput_uint16(f, value);
}
#endif

static void add_uint32(FILE *f, uint8_t optiontag, uint32_t value) {
	fput_uint8(f, optiontag);
	fput_uint8(f, sizeof(value));
	fput_uint32(f, value);
}

// add a string option
static void add_string(FILE *f, uint8_t optiontag, char *value) {
	if (value) {
		size_t len = strlen(value);
		fput_uint8(f, optiontag);
		fput_uint8(f, len);
		fput_data(f, value, len);
	}
}

// add an ip address (query the DNS if it is a name)
static void add_a(FILE *f, struct iothdns *iothdns, uint8_t optiontag, char *value) {
	struct in_addr ipaddr[1];
	size_t len = sizeof(ipaddr[0]);
	if (value && iothdns_lookup_a(iothdns, value, ipaddr, 1) > 0) {
		fput_uint8(f, optiontag);
		fput_uint8(f, len);
		fput_data(f, ipaddr, len);
	}
}

// add a list of ip addresses (query the DNS for names)
static void add_a_list(FILE *f, struct iothdns *iothdns, uint8_t optiontag, const char *inlist) {
	int tagc;
	if(inlist && (tagc = stropt(inlist, NULL, NULL, NULL)) > 0) {
		char buf[strlen(inlist)+1];
		char *tags[tagc];
		stropt(inlist, tags, NULL, buf);
		fput_uint8(f, optiontag);
		long lenpos = ftell(f);
		fput_uint8(f, 0); // len
		for (int i=0; i < tagc - 1; i++) {
			struct in_addr ipaddr[1];
			if (iothdns_lookup_a(iothdns, tags[i], ipaddr, 1) > 0)
				fput_data(f, ipaddr, sizeof(ipaddr[0]));
		}
		set_optlen(f, lenpos);
	}
}

// parse options: fpos is an array of 255 elements.
// fpos[tap] is the position of the opt_len field of option 'tag' in f
static void parseopts(FILE *f, long *fpos) {
	while (1) {
		int opt_type = fgetc(f);
		if (opt_type < 0 || opt_type == OPTION_END) // OPTION_END or EOF
			break;
		fpos[opt_type] = ftell(f);
		uint8_t opt_len = fget_uint8(f);
		printf("opt %d\n", opt_type);
		fseek(f, opt_len, SEEK_CUR);
	}
}

// process the Parameter Request List option (55)
// add the opptions in fout if available from a DNS txt query (ftxt) or global option (fopt)
static void add_prl_options(FILE *fin, FILE *fout, FILE *fopt, FILE *ftxt, long prlpos, long *foptpos) {
	long ftxtpos[UINT8_MAX] = {0};
	fseek(ftxt, SEEK_SET, 0);
	parseopts(ftxt, ftxtpos);
	if (prlpos) {
		fseek(fin, prlpos, SEEK_SET);
		for (uint8_t len = fget_uint8(fin); len > 0; len--) {
			uint8_t prltag = fget_uint8(fin);
			if (copy_option(ftxt, fout, prltag, ftxtpos) < 0)
				copy_option(fopt, fout, prltag, foptpos);
		}
	}
}

// get configuration options from a DNS txt query
struct get_txtopts_cb_arg {
	FILE *ftxt;
	struct iothdns *iothdns;
};

static int get_txtopts_cb(int section, struct iothdns_rr *rr, struct iothdns_pkt *vpkt, void *arg) {
	struct get_txtopts_cb_arg *cbarg = arg;
	(void) section;
	if (rr->type == IOTHDNS_TYPE_TXT) {
		char txt[rr->rdlength];
		iothdns_get_string(vpkt, txt);
		int tagc = stropt(txt, NULL, NULL, NULL);
		if(tagc > 0) {
			char buf[strlen(txt)+1];
			char *tags[tagc];
			char *args[tagc];
			stropt(txt, tags, args, buf);
			for (int i=0; i<tagc; i++) {
				printf("%s = %s\n",tags[i], args[i]);
				if (args[i] != NULL) {
					switch (strcase(tags[i])) {
						case STRCASE(m,a,s,k):
							add_a(cbarg->ftxt, cbarg->iothdns, OPTION_MASK, args[i]);
							break;
						case STRCASE(r,o,u,t,e,r):
							add_a_list(cbarg->ftxt, cbarg->iothdns, OPTION_ROUTER, args[i]);
							break;
						case STRCASE(b,r,o,a,d,c,a,s,t):
							add_a(cbarg->ftxt, cbarg->iothdns, OPTION_BROADCAST, args[i]);
							break;
						case STRCASE(d,n,s):
							add_a_list(cbarg->ftxt, cbarg->iothdns, OPTION_DNS, args[i]);
							break;
						case STRCASE(d,o,m,n,a,m,e):
							add_string(cbarg->ftxt, OPTION_DOMNAME, args[i]);
							break;
						case STRCASE(n,t,p):
							add_a_list(cbarg->ftxt, cbarg->iothdns, OPTION_NTP, args[i]);
							break;

					}
				}
			}
		}
	}
	return 0;
}

static FILE *get_txtopts(struct iothdns *iothdns, const char *fqdn) {
	struct get_txtopts_cb_arg cbarg = {
		.ftxt = volstream_open(),
		.iothdns = iothdns};
	iothdns_lookup_cb(iothdns, fqdn, IOTHDNS_TYPE_TXT, get_txtopts_cb, &cbarg);
	return cbarg.ftxt;
}

// parse and process a dhcp query
static const uint8_t dhcp_cookie[] = {0x63,0x82,0x53,0x63};
ssize_t dhcpparse(FILE *fin, FILE *fout, FILE *fopt, void *clientip, struct iothdns *iothdns) {
	uint8_t cookie_ck[4];
	long finpos[UINT8_MAX] = {0};
	static long foptpos[UINT8_MAX] = {0};
	if (foptpos[0] == 0) {
		foptpos[0] = 1;
		fseek(fopt, 0, SEEK_SET);
		parseopts(fopt, foptpos);
	}
	fget_data(fin, cookie_ck, 4);
	if (memcmp(cookie_ck, dhcp_cookie, 4) != 0) return 0;
	fput_data(fout, dhcp_cookie, 4);
	parseopts(fin, finpos);
	if (finpos[OPTION_TYPE] != 0 &&
			finpos[OPTION_FQDN] != 0) { // XXX plus other checks
		fseek(fin, finpos[OPTION_TYPE], SEEK_SET);
		if (fget_uint8(fin) != 1) goto err;
		uint8_t dhcp_type = fget_uint8(fin);
		fseek(fin, finpos[OPTION_FQDN], SEEK_SET);
		uint8_t fqdn_len = fget_uint8(fin) - 2;
		uint8_t fqdn_flags = fget_uint8(fin);
		fget_uint8(fin); // A-RR
		fget_uint8(fin); // PTR-RR
		char fqdn[fqdn_len];
		fqdn[fqdn_len - 1] = 0;
		if (fqdn_flags & (1 << 2)) // "E" bit
			fget_name(fin, fqdn, fqdn_len); // Section 3.1. RFCC1035 uncompressed
		else
			fget_data(fin, fqdn, fqdn_len - 1); // ASCII deprecated encoding
		//printf("fqdn %s\n", fqdn);
		switch (dhcp_type) {
			case DHCPDISCOVER:
				if (iothdns_lookup_a(iothdns, fqdn, clientip, 1) > 0) {
					FILE *ftxt = get_txtopts(iothdns, fqdn);
					add_uint8(fout, OPTION_TYPE, DHCPOFFER);
					copy_option(fopt, fout, OPTION_SERVID, foptpos);
					add_uint32(fout, OPTION_LEASETIME, STDVALID);
					add_prl_options(fin, fout, fopt, ftxt, finpos[OPTION_PARLIST], foptpos);
					fclose(ftxt);
				} else
					goto err;
				break;
			case DHCPREQUEST:
				if (cmp_option(fin, finpos[OPTION_SERVID], fopt, foptpos[OPTION_SERVID]) == 0 &&
						iothdns_lookup_a(iothdns, fqdn, clientip, 1) > 0) {
					FILE *ftxt = get_txtopts(iothdns, fqdn);
					add_uint8(fout, OPTION_TYPE, DHCPACK);
					copy_option(fopt, fout, OPTION_SERVID, foptpos);
					add_uint32(fout, OPTION_LEASETIME, STDVALID);
					add_prl_options(fin, fout, fopt, ftxt, finpos[OPTION_PARLIST], foptpos);
					fclose(ftxt);
				} else
					goto err;
				break;
			default:
				goto err;
		}
		add_tag(fout, OPTION_END);
		while (ftell(fout) < BOOTP_VEND_LEN)
			fput_uint8(fout, 0);
		return ftell(fout);
	}
err:
	return 0;
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

/* select the input packets */
static int ch_inpkt(struct bootp_pkt *inpkt) {
	static uint8_t bcast_ethernet_addr[]={0xff,0xff,0xff,0xff,0xff,0xff};
	if (! (memcmp(inpkt->ethh.ether_dhost, bcast_ethernet_addr, ETH_ALEN) == 0 ||
				memcmp(inpkt->ethh.ether_dhost, macaddr, ETH_ALEN) == 0))
		return 0;
	if (ntohs(inpkt->ethh.ether_type) != 0x0800) return 0; // this is not IPv4
	if (inpkt->iph.version != 4) return 0; //this is not IPv4
	if (inpkt->iph.protocol != 17) return 0; //this is not UDP
	if (ntohs(inpkt->udph.dest) != DHCP_SERVERPORT) return 0; /* wrong destination port */
	if (inpkt->bootph.op != BOOTREQUEST) return 0; // Boot req
	if (inpkt->bootph.op != ARPHRD_ETHER) return 0;
	if (inpkt->bootph.hlen != ETH_ALEN) return 0;
	return 1;
}

/* fill the output packet headers */
static void fill_outpkt(struct bootp_pkt *outpkt, long outlen) {
	unsigned int sum = 0;
	long iplen = outlen - offsetof(struct bootp_pkt, iph);
	long udplen = outlen - offsetof(struct bootp_pkt, udph);
	/* ETH */
	memcpy(outpkt->ethh.ether_dhost, outpkt->ethh.ether_shost, ETH_ALEN);
	memcpy(outpkt->ethh.ether_shost, macaddr, ETH_ALEN);
	/* IP */
	outpkt->iph.daddr = 0xffffffff;
	outpkt->iph.saddr = 0;
	outpkt->iph.tot_len = htons(iplen);
	outpkt->iph.check = 0;
	sum = chksum(sum, &outpkt->iph, sizeof(outpkt->iph));
	outpkt->iph.check = htons(~sum);
	/* UDP */
	outpkt->udph.dest = outpkt->udph.source;
	outpkt->udph.source = htons(DHCP_SERVERPORT);
	outpkt->udph.len = htons(udplen);
	outpkt->udph.check = 0;
	/* BOOTP */
	outpkt->bootph.op = BOOTREPLY;
}


/* UDP via ioth stack */
static struct sock_filter filterprog[] = {
	// It is IPv4
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offsetof(struct ethhdr, h_proto)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETH_P_IP, 0, 9),
	// to 255.255.255.255
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ETH_HLEN + offsetof(struct iphdr, daddr)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xffffffff, 0, 7),
	// it is UDP
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, ETH_HLEN + offsetof(struct iphdr, protocol)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_UDP, 0, 5),
	// it is not a fragment
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, ETH_HLEN + offsetof(struct iphdr, frag_off)),
	BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 0x1fff, 3, 0),
	// UDP port == 67
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, ETH_HLEN + sizeof(struct iphdr) +
			offsetof(struct udphdr, dest)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x43, 0, 1),
	// return the entire packet
	BPF_STMT(BPF_RET+BPF_K, 0x640),
	// filter this packet
	BPF_STMT(BPF_RET+BPF_K, 0),
};

static struct sock_fprog filter = {
	.filter = filterprog,
	.len = sizeof(filterprog) / sizeof(filterprog[0])
};

int open_iface(struct ioth *stack, char *ifname) {
	int fd = -1;
	unsigned int ifindex;
	if ((ifindex = ioth_if_nametoindex(stack, ifname)) == 0)
		goto error;
	if (macaddr_isnull() && ioth_linkgetaddr(stack, ifindex, macaddr) < 0)
		goto error;
	if ((fd = ioth_msocket(stack, AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
		goto error;
	// no error if fails
	ioth_setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
	struct sockaddr_ll bindaddr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
		.sll_ifindex = ifindex,
		.sll_halen = sizeof(macaddr),
		.sll_pkttype = PACKET_BROADCAST,
	};
	memcpy(bindaddr.sll_addr, &macaddr, sizeof(macaddr));
	if ((ioth_bind(fd, (struct sockaddr *) &bindaddr, sizeof(bindaddr))) < 0)
		goto error;
	return fd;
error:
	printlog(LOG_ERR, "Error opening interface %s: %s", ifname, strerror(errno));
	if (fd >= 0)
		ioth_close(fd);
	return -1;
}

static ssize_t packet_process(
		uint8_t *inbuf, ssize_t inlen,
		uint8_t *outbuf, ssize_t outlen,
		FILE *fopt, struct iothdns *iothdns) {
	if (inlen < (ssize_t) sizeof(struct bootp_pkt))
		return 0;
	struct bootp_pkt *inpkt = (void *) inbuf;
	struct bootp_pkt *outpkt = (void *) outbuf;
	*outpkt = *inpkt;
	if (! ch_inpkt(inpkt)) return 0;
#ifdef PACKETDUMP
	if (verbose) {
		fprintf(stderr, "INPACKET %zd\n",inlen);
		packetdump(stderr, inbuf, inlen);
	}
#endif
	FILE *fin = fmemopen(inpkt->dhcpdata, inlen - sizeof(struct bootp_pkt), "r");
	FILE *fout = fmemopen(outpkt->dhcpdata, outlen, "w");
	if ((outlen = dhcpparse(fin, fout, fopt, &outpkt->bootph.yiaddr, iothdns)) > 0) {
		fflush(fout);
		outlen += sizeof(struct bootp_pkt);
		fill_outpkt(outpkt, outlen);
#ifdef PACKETDUMP
		if (verbose) {
			fprintf(stderr, "OUTPACKET %zd\n", outlen);
			packetdump(stderr, outbuf, outlen);
		}
#endif
	}
	fclose(fin);
	fclose(fout);
	return outlen;
}

void main_iface_loop(int fd, FILE *fopt, struct iothdns *iothdns) {
	struct sockaddr_ll from;
	socklen_t fromlen;
	while (! leave) {
		uint8_t inbuf[ETHMTU];
		uint8_t outbuf[ETHMTU];
		ssize_t inlen;
		ssize_t outlen;
		inlen = ioth_recvfrom(fd, inbuf, ETHMTU, 0, (struct sockaddr *) &from, &fromlen);
		if ((outlen = packet_process(inbuf, inlen, outbuf, DHCP_PACKET_SIZE, fopt, iothdns)) > 0)
			ioth_send(fd, outbuf, outlen, 0);
	}
}

/* UDP emulation via VDE */

void main_vde_loop(VDECONN *conn, FILE *fopt, struct iothdns *iothdns) {
	while (! leave) {
		uint8_t inbuf[ETHMTU];
		uint8_t outbuf[ETHMTU];
		ssize_t inlen;
		ssize_t outlen;
		inlen = vde_recv(conn, inbuf, ETHMTU, 0);
		if ((outlen = packet_process(inbuf, inlen, outbuf, DHCP_PACKET_SIZE, fopt, iothdns)) > 0)
			vde_send(conn, outbuf, outlen, 0);
	}
}

static void vde_macaddr(void) {
	if (macaddr_isnull()) {
		ssize_t n = getrandom(macaddr, ETH_ALEN, 0);
		(void) n;
		macaddr[0] = (macaddr[0] & ~0x1) | 0x0;
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
			"\t--macaddr|-m <mac_address>        (set the dhcp server MAC addr)\n"
			"\t--serverid|-I <ipaddr>            (set the dhcp server ID)\n"
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

static char *short_options = "hdvnf:p:s:R:i:n:r:m:D:N:S:I:";
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

static char *arg_tags = "dvpsRinrmDNSI";
union {
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
		char *serverid;
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
				args.argv[index] = strdup(value);
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
	add_a_list(fopt, iothdns, OPTION_DNS, args.dns);
	add_string(fopt, OPTION_DOMNAME, args.dnssearch);
	add_a_list(fopt, iothdns, OPTION_NTP, args.ntp);
	add_a(fopt, iothdns, OPTION_SERVID, args.serverid);
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
								 int index = argindex(c);;
								 if (args.argv[index] == NULL)
									 args.argv[index] = optarg ? optarg : "";
							 }
								break;
		}
	}
	if (optind < argc)
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
		VDECONN *vdeconn = vde_open(args.stack, "DHCP", NULL);
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
		printf("%d\n", fd);
		if (fd >= 0) {
			struct iothdns *iothdns = open_iothdns(dnsstack);
			FILE *fopt = foptcreate(iothdns);
			main_iface_loop(fd, fopt, iothdns);
			ioth_close(fd);
			fclose(fopt);
		}
	}
}
