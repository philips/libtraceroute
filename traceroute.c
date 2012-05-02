/* 
 * Librarization done by Brandon Philips
 * Copyright (c) 2012 Rackspace, Inc
 *
 * Copyright (c) 1988, 1989, 1991, 1994, 1995, 1996, 1997, 1998, 1999, 2000
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#define _BSD_SOURCE 

#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/socket.h>
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#include <sys/time.h>


#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#ifdef	IPSEC
#include <net/route.h>
#include <netipsec/ipsec.h>	/* XXX */
#endif	/* IPSEC */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <memory.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "traceroute.h"
#include "traceroute_private.h"

#define Fprintf (void)fprintf
#define Printf (void)printf

static char host[] = "ifup.org";
static char prog[] = "traceroute";

struct traceroute {
	u_char	packet[512];		/* last inbound (icmp) packet */

	struct ip *outip;		/* last output ip packet */
	u_char *outp;		/* last output inner protocol packet */

	struct ip *hip;		/* Quoted IP header */
	int hiplen;

	/* loose source route gateway list (including room for final destination) */
	u_int32_t gwlist[NGATEWAYS + 1];

	int s;				/* receive (icmp) socket file descriptor */
	int sndsock;			/* send (udp) socket file descriptor */

	struct sockaddr whereto;	/* Who to try to reach */
	struct sockaddr wherefrom;	/* Who we are */
	int packlen;			/* total length of packet */
	int protlen;			/* length of protocol part of packet */
	int minpacket;			/* min ip packet size */
	int maxpacket;	/* max ip packet size */
	int pmtu;			/* Path MTU Discovery (RFC1191) */
	u_int pausemsecs;

	char *prog;
	char *source;
	char *hostname;
	char *device;

	int nprobes;
	int max_ttl;
	int first_ttl;
	u_short ident;
	u_short port;			/* protocol specific base "port" */

	int options;			/* socket options */
	int verbose;
	int waittime;		/* time to wait for response (in seconds) */
	int nflag;			/* print addresses numerically */
	int as_path;			/* print as numbers for each hop */
	char *as_server;
	void *asn;
	int optlen;			/* length of ip options */
	int fixedPort;		/* Use fixed destination port for TCP and UDP */
	int printdiff;		/* Print the difference between sent and quoted */
};

struct traceroute *
traceroute_alloc() {
	return calloc(1, sizeof(struct traceroute));
}

void
traceroute_init(struct traceroute *t) {
	t->hip = NULL;
	t->hiplen = 0;
	t->maxpacket = 32 * 1024;
	t->hostname = host;
	t->nprobes = -1;
	t->max_ttl = 30;
	t->first_ttl = 1;
	t->waittime = 5;
	t->as_server = NULL;
	t->fixedPort = 0;
	t->printdiff = 0;
}

extern int optind;
extern int opterr;
extern char *optarg;

/* Forwards */
double	deltaT(struct timeval *, struct timeval *);
void	freehostinfo(struct hostinfo *);
void	getaddr(u_int32_t *, char *);
struct	hostinfo *gethostinfo(const char *);
u_short	in_cksum(u_short *, int);
char	*inetname(struct traceroute *t, struct in_addr);
int	main(int, char **);
u_short p_cksum(struct ip *, u_short *, int);
int	packet_ok(struct traceroute *t, u_char *, int, struct sockaddr_in *, int);
char	*pr_type(u_char);
void	print(struct traceroute *t, u_char *, int, struct sockaddr_in *);
#ifdef	IPSEC
int	setpolicy __P((int so, char *policy));
#endif
void	send_probe(struct traceroute *, int, int);
struct outproto *setproto(char *);
int	str2val(const char *, const char *, int, int);
void	tvsub(struct timeval *, struct timeval *);
void usage(void);
int	wait_for_reply(struct traceroute *, int, struct sockaddr_in *, const struct timeval *);
void pkt_compare(const u_char *, int, const u_char *, int);
#ifndef HAVE_USLEEP
int	usleep(u_int);
#endif

void	udp_prep(struct traceroute *, struct outdata *);
int	udp_check(struct traceroute *, const u_char *, int);
void	tcp_prep(struct traceroute *, struct outdata *);
int	tcp_check(struct traceroute *, const u_char *, int);
void	gre_prep(struct traceroute *, struct outdata *);
int	gre_check(struct traceroute *, const u_char *, int);
void	gen_prep(struct traceroute *, struct outdata *);
int	gen_check(struct traceroute *, const u_char *, int);
void	icmp_prep(struct traceroute *, struct outdata *);
int	icmp_check(struct traceroute *, const u_char *, int);

/* Descriptor structure for each outgoing protocol we support */
struct outproto {
	char	*name;		/* name of protocol */
	const char *key;	/* An ascii key for the bytes of the header */
	u_char	num;		/* IP protocol number */
	u_short	hdrlen;		/* max size of protocol header */
	u_short	port;		/* default base protocol-specific "port" */
	void	(*prepare)(struct traceroute *, struct outdata *);
				/* finish preparing an outgoing packet */
	int	(*check)(struct traceroute *, const u_char *, int);
				/* check an incoming packet */
};

/* List of supported protocols. The first one is the default. The last
   one is the handler for generic protocols not explicitly listed. */
struct	outproto protos[] = {
	{
		"udp",
		"spt dpt len sum",
		IPPROTO_UDP,
		sizeof(struct udphdr),
		32768 + 666,
		udp_prep,
		udp_check
	},
	{
		"tcp",
		"spt dpt seq     ack     xxflwin sum urp",
		IPPROTO_TCP,
		sizeof(struct tcphdr),
		32768 + 666,
		tcp_prep,
		tcp_check
	},
	{
		"gre",
		"flg pro len clid",
		IPPROTO_GRE,
		sizeof(struct grehdr),
		GRE_PPTP_PROTO,
		gre_prep,
		gre_check
	},
	{
		"icmp",
		"typ cod sum ",
		IPPROTO_ICMP,
		sizeof(struct icmp),
		0,
		icmp_prep,
		icmp_check
	},
	{
		NULL,
		NULL,
		0,
		2 * sizeof(u_short),
		0,
		gen_prep,
		gen_check
	},
};
struct	outproto *proto = &protos[0];

const char *ip_hdr_key = "vhtslen id  off tlprsum srcip   dstip   opts";

int
main(int argc, char **argv)
{
	struct traceroute *t = traceroute_alloc();
	register int op, code, n;
	register char *cp;
	register const char *err;
	register u_int32_t *ap;
	register struct sockaddr_in *from = (struct sockaddr_in *)&t->wherefrom;
	register struct sockaddr_in *to = (struct sockaddr_in *)&t->whereto;
	register struct hostinfo *hi;
	int on = 1;
	register struct protoent *pe;
	register int ttl, probe, i;
	register int seq = 0;
	int tos = 0, settos = 0;
	register int lsrr = 0;
	register u_short off = 0;
	struct ifaddrlist *al;
	char errbuf[132];
	int requestPort = -1;
	int sump = 0;
	int sockerrno;
	const char devnull[] = "/dev/null";

	traceroute_init(t);

	/* Insure the socket fds won't be 0, 1 or 2 */
	if (open(devnull, O_RDONLY) < 0 ||
	    open(devnull, O_RDONLY) < 0 ||
	    open(devnull, O_RDONLY) < 0) {
		Fprintf(stderr, "%s: open \"%s\": %s\n",
		    prog, devnull, strerror(errno));
		exit(1);
	}
	/*
	 * Do the setuid-required stuff first, then lose priveleges ASAP.
	 * Do error checking for these two calls where they appeared in
	 * the original code.
	 */
	cp = "icmp";
	pe = getprotobyname(cp);
	if (pe) {
		if ((t->s = socket(AF_INET, SOCK_RAW, pe->p_proto)) < 0)
			sockerrno = errno;
		else if ((t->sndsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
			sockerrno = errno;
	}

	if (setuid(getuid()) != 0) {
		perror("setuid()");
		exit(1);
	}

#ifdef IPCTL_DEFTTL
	{
		int mib[4] = { CTL_NET, PF_INET, IPPROTO_IP, IPCTL_DEFTTL };
		size_t sz = sizeof(max_ttl);

		if (sysctl(mib, 4, &max_ttl, &sz, NULL, 0) == -1) {
			perror("sysctl(net.inet.ip.ttl)");
			exit(1);
		}
	}
#else
	t->max_ttl = 30;
#endif

	/* Set requested port, if any, else default for this protocol */
	t->port = (requestPort != -1) ? requestPort : proto->port;

	if (t->nprobes == -1)
		t->nprobes = t->printdiff ? 1 : 3;

	if (t->first_ttl > t->max_ttl) {
		Fprintf(stderr,
		    "%s: first ttl (%d) may not be greater than max ttl (%d)\n",
		    prog, t->first_ttl, t->max_ttl);
		exit(1);
	}

	if (lsrr > 0)
		t->optlen = (lsrr + 1) * sizeof(t->gwlist[0]);
	t->minpacket = sizeof(*t->outip) + proto->hdrlen + sizeof(struct outdata) + t->optlen;
	t->packlen = t->minpacket;			/* minimum sized packet */

	hi = gethostinfo(t->hostname);
	setsin(to, hi->addrs[0]);
	if (hi->n > 1)
		Fprintf(stderr,
	    "%s: Warning: %s has multiple addresses; using %s\n",
			prog, t->hostname, inet_ntoa(to->sin_addr));
	t->hostname = hi->name;
	hi->name = NULL;
	freehostinfo(hi);

#ifdef HAVE_SETLINEBUF
	setlinebuf (stdout);
#else
	setvbuf(stdout, NULL, _IOLBF, 0);
#endif

	t->protlen = t->packlen - sizeof(*t->outip) - t->optlen;

	t->outip = (struct ip *)malloc((unsigned)t->packlen);
	if (t->outip == NULL) {
		Fprintf(stderr, "%s: malloc: %s\n", prog, strerror(errno));
		exit(1);
	}
	memset((char *)t->outip, 0, t->packlen);

	t->outip->ip_v = IPVERSION;
	if (settos)
		t->outip->ip_tos = tos;
#ifdef BYTESWAP_IP_HDR
	t->outip->ip_len = htons(packlen);
	t->outip->ip_off = htons(off);
#else
	t->outip->ip_len = t->packlen;
	t->outip->ip_off = off;
#endif
	t->outip->ip_p = proto->num;
	t->outp = (u_char *)(t->outip + 1);
#ifdef HAVE_RAW_OPTIONS
	if (lsrr > 0) {
		register u_char *optlist;

		optlist = outp;
		outp += optlen;

		/* final hop */
		gwlist[lsrr] = to->sin_addr.s_addr;

		outip->ip_dst.s_addr = gwlist[0];

		/* force 4 byte alignment */
		optlist[0] = IPOPT_NOP;
		/* loose source route option */
		optlist[1] = IPOPT_LSRR;
		i = lsrr * sizeof(gwlist[0]);
		optlist[2] = i + 3;
		/* Pointer to LSRR addresses */
		optlist[3] = IPOPT_MINOFF;
		memcpy(optlist + 4, gwlist + 1, i);
	} else
#endif
		t->outip->ip_dst = to->sin_addr;

	t->outip->ip_hl = (t->outp - (u_char *)t->outip) >> 2;
	t->ident = (getpid() & 0xffff) | 0x8000;

	if (pe == NULL) {
		Fprintf(stderr, "%s: unknown protocol %s\n", prog, cp);
		exit(1);
	}
	if (t->s < 0) {
		errno = sockerrno;
		Fprintf(stderr, "%s: icmp socket: %s\n", prog, strerror(errno));
		exit(1);
	}
	if (t->options & SO_DEBUG)
		(void)setsockopt(t->s, SOL_SOCKET, SO_DEBUG, (char *)&on,
		    sizeof(on));
	if (t->options & SO_DONTROUTE)
		(void)setsockopt(t->s, SOL_SOCKET, SO_DONTROUTE, (char *)&on,
		    sizeof(on));

#if	defined(IPSEC) && defined(IPSEC_POLICY_IPSEC)
	if (setpolicy(s, "in bypass") < 0)
		errx(1, "%s", ipsec_strerror());

	if (setpolicy(s, "out bypass") < 0)
		errx(1, "%s", ipsec_strerror());
#endif	/* defined(IPSEC) && defined(IPSEC_POLICY_IPSEC) */

	if (t->sndsock < 0) {
		errno = sockerrno;
		Fprintf(stderr, "%s: raw socket: %s\n", prog, strerror(errno));
		exit(1);
	}

#if defined(IP_OPTIONS) && !defined(HAVE_RAW_OPTIONS)
	if (lsrr > 0) {
		u_char optlist[MAX_IPOPTLEN];

		cp = "ip";
		if ((pe = getprotobyname(cp)) == NULL) {
			Fprintf(stderr, "%s: unknown protocol %s\n", prog, cp);
			exit(1);
		}

		/* final hop */
		t->gwlist[lsrr] = to->sin_addr.s_addr;
		++lsrr;

		/* force 4 byte alignment */
		optlist[0] = IPOPT_NOP;
		/* loose source route option */
		optlist[1] = IPOPT_LSRR;
		i = lsrr * sizeof(t->gwlist[0]);
		optlist[2] = i + 3;
		/* Pointer to LSRR addresses */
		optlist[3] = IPOPT_MINOFF;
		memcpy(optlist + 4, t->gwlist, i);

		if ((setsockopt(t->sndsock, pe->p_proto, IP_OPTIONS,
		    (char *)optlist, i + sizeof(t->gwlist[0]))) < 0) {
			Fprintf(stderr, "%s: IP_OPTIONS: %s\n",
			    prog, strerror(errno));
			exit(1);
		    }
	}
#endif

#ifdef SO_SNDBUF
	if (setsockopt(t->sndsock, SOL_SOCKET, SO_SNDBUF, (char *)&t->packlen,
	    sizeof(t->packlen)) < 0) {
		Fprintf(stderr, "%s: SO_SNDBUF: %s\n", prog, strerror(errno));
		exit(1);
	}
#endif
#ifdef IP_HDRINCL
	if (setsockopt(t->sndsock, IPPROTO_IP, IP_HDRINCL, (char *)&on,
	    sizeof(on)) < 0) {
		Fprintf(stderr, "%s: IP_HDRINCL: %s\n", prog, strerror(errno));
		exit(1);
	}
#else
#ifdef IP_TOS
	if (settos && setsockopt(t->sndsock, IPPROTO_IP, IP_TOS,
	    (char *)&tos, sizeof(tos)) < 0) {
		Fprintf(stderr, "%s: setsockopt tos %d: %s\n",
		    prog, tos, strerror(errno));
		exit(1);
	}
#endif
#endif
	if (t->options & SO_DEBUG)
		(void)setsockopt(t->sndsock, SOL_SOCKET, SO_DEBUG, (char *)&on,
		    sizeof(on));
	if (t->options & SO_DONTROUTE)
		(void)setsockopt(t->sndsock, SOL_SOCKET, SO_DONTROUTE, (char *)&on,
		    sizeof(on));

	t->outip->ip_src = from->sin_addr;

	/* Check the source address (-s), if any, is valid */
	if (bind(t->sndsock, (struct sockaddr *)from, sizeof(*from)) < 0) {
		Fprintf(stderr, "%s: bind: %s\n",
		    prog, strerror(errno));
		exit (1);
	}

#if	defined(IPSEC) && defined(IPSEC_POLICY_IPSEC)
	if (setpolicy(t->sndsock, "in bypass") < 0)
		errx(1, "%s", ipsec_strerror());

	if (setpolicy(t->sndsock, "out bypass") < 0)
		errx(1, "%s", ipsec_strerror());
#endif	/* defined(IPSEC) && defined(IPSEC_POLICY_IPSEC) */

	Fprintf(stderr, "%s to %s (%s)",
	    prog, t->hostname, inet_ntoa(to->sin_addr));
	if (t->source)
		Fprintf(stderr, " from %s", t->source);
	Fprintf(stderr, ", %d hops max, %d byte packets\n", t->max_ttl, t->packlen);
	(void)fflush(stderr);

	for (ttl = t->first_ttl; ttl <= t->max_ttl; ++ttl) {
		u_int32_t lastaddr = 0;
		int gotlastaddr = 0;
		int got_there = 0;
		int unreachable = 0;
		int sentfirst = 0;
		int loss;

		Printf("%2d ", ttl);
		for (probe = 0, loss = 0; probe < t->nprobes; ++probe) {
			register int cc;
			struct timeval t1, t2;
			register struct ip *ip;
			struct outdata outdata;

			if (sentfirst && t->pausemsecs > 0)
				usleep(t->pausemsecs * 1000);
			/* Prepare outgoing data */
			outdata.seq = ++seq;
			outdata.ttl = ttl;

			/* Avoid alignment problems by copying bytewise: */
			(void)gettimeofday(&t1, NULL);
			memcpy(&outdata.tv, &t1, sizeof(outdata.tv));

			/* Finalize and send packet */
			(*proto->prepare)(t, &outdata);
			send_probe(t, seq, ttl);
			++sentfirst;

			/* Wait for a reply */
			while ((cc = wait_for_reply(t, t->s, from, &t1)) != 0) {
				double T;
				int precis;

				(void)gettimeofday(&t2, NULL);
				i = packet_ok(t, t->packet, cc, from, seq);
				/* Skip short packet */
				if (i == 0)
					continue;
				if (!gotlastaddr ||
				    from->sin_addr.s_addr != lastaddr) {
					if (gotlastaddr) printf("\n   ");
					print(t, t->packet, cc, from);
					lastaddr = from->sin_addr.s_addr;
					++gotlastaddr;
				}
				T = deltaT(&t1, &t2);
#ifdef SANE_PRECISION
				if (T >= 1000.0)
					precis = 0;
				else if (T >= 100.0)
					precis = 1;
				else if (T >= 10.0)
					precis = 2;
				else
#endif
					precis = 3;
				Printf("  %.*f ms", precis, T);
				if (t->printdiff) {
					Printf("\n");
					Printf("%*.*s%s\n",
					    -(t->outip->ip_hl << 3),
					    t->outip->ip_hl << 3,
					    ip_hdr_key,
					    proto->key);
					pkt_compare((void *)t->outip, t->packlen,
					    (void *)t->hip, t->hiplen);
				}
				if (i == -2) {
#ifndef ARCHAIC
					ip = (struct ip *)t->packet;
					if (ip->ip_ttl <= 1)
						Printf(" !");
#endif
					++got_there;
					break;
				}
				/* time exceeded in transit */
				if (i == -1)
					break;
				code = i - 1;
				switch (code) {

				case ICMP_UNREACH_PORT:
#ifndef ARCHAIC
					ip = (struct ip *)t->packet;
					if (ip->ip_ttl <= 1)
						Printf(" !");
#endif
					++got_there;
					break;

				case ICMP_UNREACH_NET:
					++unreachable;
					Printf(" !N");
					break;

				case ICMP_UNREACH_HOST:
					++unreachable;
					Printf(" !H");
					break;

				case ICMP_UNREACH_PROTOCOL:
					++got_there;
					Printf(" !P");
					break;

				case ICMP_UNREACH_NEEDFRAG:
					++unreachable;
					Printf(" !F-%d", t->pmtu);
					break;

				case ICMP_UNREACH_SRCFAIL:
					++unreachable;
					Printf(" !S");
					break;

				case ICMP_UNREACH_NET_UNKNOWN:
					++unreachable;
					Printf(" !U");
					break;

				case ICMP_UNREACH_HOST_UNKNOWN:
					++unreachable;
					Printf(" !W");
					break;

				case ICMP_UNREACH_ISOLATED:
					++unreachable;
					Printf(" !I");
					break;

				case ICMP_UNREACH_NET_PROHIB:
					++unreachable;
					Printf(" !A");
					break;

				case ICMP_UNREACH_HOST_PROHIB:
					++unreachable;
					Printf(" !Z");
					break;

				case ICMP_UNREACH_TOSNET:
					++unreachable;
					Printf(" !Q");
					break;

				case ICMP_UNREACH_TOSHOST:
					++unreachable;
					Printf(" !T");
					break;

				case ICMP_UNREACH_FILTER_PROHIB:
					++unreachable;
					Printf(" !X");
					break;

				case ICMP_UNREACH_HOST_PRECEDENCE:
					++unreachable;
					Printf(" !V");
					break;

				case ICMP_UNREACH_PRECEDENCE_CUTOFF:
					++unreachable;
					Printf(" !C");
					break;

				default:
					++unreachable;
					Printf(" !<%d>", code);
					break;
				}
				break;
			}
			if (cc == 0) {
				loss++;
				Printf(" *");
			}
			(void)fflush(stdout);
		}
		if (sump) {
			Printf(" (%d%% loss)", (loss * 100) / t->nprobes);
		}
		putchar('\n');
		if (got_there ||
		    (unreachable > 0 && unreachable >= t->nprobes - 1))
			break;
	}
	exit(0);
}

int
wait_for_reply(struct traceroute *t, register int sock, register struct sockaddr_in *fromp,
    register const struct timeval *tp)
{
	fd_set *fdsp;
	size_t nfds;
	struct timeval now, wait;
	register int cc = 0;
	register int error;
	int fromlen = sizeof(*fromp);

	nfds = howmany(sock + 1, NFDBITS);
	if ((fdsp = malloc(nfds * sizeof(fd_mask))) == NULL)
		err(1, "malloc");
	memset(fdsp, 0, nfds * sizeof(fd_mask));
	FD_SET(sock, fdsp);

	wait.tv_sec = tp->tv_sec + t->waittime;
	wait.tv_usec = tp->tv_usec;
	(void)gettimeofday(&now, NULL);
	tvsub(&wait, &now);
	if (wait.tv_sec < 0) {
		wait.tv_sec = 0;
		wait.tv_usec = 1;
	}

	error = select(sock + 1, fdsp, NULL, NULL, &wait);
	if (error == -1 && errno == EINVAL) {
		Fprintf(stderr, "%s: botched select() args\n", prog);
		exit(1);
	}
	if (error > 0)
		cc = recvfrom(sock, (char *)t->packet, sizeof(t->packet), 0,
			    (struct sockaddr *)fromp, &fromlen);

	free(fdsp);
	return(cc);
}

void
send_probe(struct traceroute *t, int seq, int ttl)
{
	register int cc;

	t->outip->ip_ttl = ttl;
	t->outip->ip_id = htons(t->ident + seq);

	/* XXX undocumented debugging hack */
	if (t->verbose > 1) {
		register const u_short *sp;
		register int nshorts, i;

		sp = (u_short *)t->outip;
		nshorts = (u_int)t->packlen / sizeof(u_short);
		i = 0;
		Printf("[ %d bytes", t->packlen);
		while (--nshorts >= 0) {
			if ((i++ % 8) == 0)
				Printf("\n\t");
			Printf(" %04x", ntohs(*sp++));
		}
		if (t->packlen & 1) {
			if ((i % 8) == 0)
				Printf("\n\t");
			Printf(" %02x", *(u_char *)sp);
		}
		Printf("]\n");
	}

#if !defined(IP_HDRINCL) && defined(IP_TTL)
	if (setsockopt(t->sndsock, IPPROTO_IP, IP_TTL,
	    (char *)&ttl, sizeof(ttl)) < 0) {
		Fprintf(stderr, "%s: setsockopt ttl %d: %s\n",
		    prog, ttl, strerror(errno));
		exit(1);
	}
#endif

	cc = sendto(t->sndsock, (char *)t->outip,
	    t->packlen, 0, &t->whereto, sizeof(t->whereto));
	if (cc < 0 || cc != t->packlen)  {
		if (cc < 0)
			Fprintf(stderr, "%s: sendto: %s\n",
			    prog, strerror(errno));
		Printf("%s: wrote %s %d chars, ret=%d\n",
		    prog, t->hostname, t->packlen, cc);
		(void)fflush(stdout);
	}
}

#if	defined(IPSEC) && defined(IPSEC_POLICY_IPSEC)
int
setpolicy(so, policy)
	int so;
	char *policy;
{
	char *buf;

	buf = ipsec_set_policy(policy, strlen(policy));
	if (buf == NULL) {
		warnx("%s", ipsec_strerror());
		return -1;
	}
	(void)setsockopt(so, IPPROTO_IP, IP_IPSEC_POLICY,
		buf, ipsec_get_policylen(buf));

	free(buf);

	return 0;
}
#endif

double
deltaT(struct timeval *t1p, struct timeval *t2p)
{
	register double dt;

	dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
	     (double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;
	return (dt);
}

/*
 * Convert an ICMP "type" field to a printable string.
 */
char *
pr_type(register u_char t)
{
	static char *ttab[] = {
	"Echo Reply",	"ICMP 1",	"ICMP 2",	"Dest Unreachable",
	"Source Quench", "Redirect",	"ICMP 6",	"ICMP 7",
	"Echo",		"ICMP 9",	"ICMP 10",	"Time Exceeded",
	"Param Problem", "Timestamp",	"Timestamp Reply", "Info Request",
	"Info Reply"
	};

	if (t > 16)
		return("OUT-OF-RANGE");

	return(ttab[t]);
}

int
packet_ok(struct traceroute *t, register u_char *buf, int cc, register struct sockaddr_in *from,
    register int seq)
{
	register struct icmp *icp;
	register u_char type, code;
	register int hlen;
#ifndef ARCHAIC
	register struct ip *ip;

	ip = (struct ip *) buf;
	hlen = ip->ip_hl << 2;
	if (cc < hlen + ICMP_MINLEN) {
		if (t->verbose)
			Printf("packet too short (%d bytes) from %s\n", cc,
				inet_ntoa(from->sin_addr));
		return (0);
	}
	cc -= hlen;
	icp = (struct icmp *)(buf + hlen);
#else
	icp = (struct icmp *)buf;
#endif
	type = icp->icmp_type;
	code = icp->icmp_code;
	/* Path MTU Discovery (RFC1191) */
	if (code != ICMP_UNREACH_NEEDFRAG)
		t->pmtu = 0;
	else {
#ifdef HAVE_ICMP_NEXTMTU
		t->pmtu = ntohs(icp->icmp_nextmtu);
#else
		t->pmtu = ntohs(((struct my_pmtu *)&icp->icmp_void)->ipm_nextmtu);
#endif
	}
	if (type == ICMP_ECHOREPLY
	    && proto->num == IPPROTO_ICMP
	    && (*proto->check)(t, (u_char *)icp, (u_char)seq))
		return -2;
	if ((type == ICMP_TIMXCEED && code == ICMP_TIMXCEED_INTRANS) ||
	    type == ICMP_UNREACH) {
		u_char *inner;

		t->hip = &icp->icmp_ip;
		t->hiplen = ((u_char *)icp + cc) - (u_char *)t->hip;
		hlen = t->hip->ip_hl << 2;
		inner = (u_char *)((u_char *)t->hip + hlen);
		if (hlen + 12 <= cc
		    && t->hip->ip_p == proto->num
		    && (*proto->check)(t, inner, (u_char)seq))
			return (type == ICMP_TIMXCEED ? -1 : code + 1);
	}
#ifndef ARCHAIC
	if (t->verbose) {
		register int i;
		u_int32_t *lp = (u_int32_t *)&icp->icmp_ip;

		Printf("\n%d bytes from %s to ", cc, inet_ntoa(from->sin_addr));
		Printf("%s: icmp type %d (%s) code %d\n",
		    inet_ntoa(ip->ip_dst), type, pr_type(type), icp->icmp_code);
		for (i = 4; i < cc ; i += sizeof(*lp))
			Printf("%2d: x%8.8x\n", i, *lp++);
	}
#endif
	return(0);
}

void
icmp_prep(struct traceroute *t, struct outdata *outdata)
{
	struct icmp *const icmpheader = (struct icmp *) t->outp;

	icmpheader->icmp_type = ICMP_ECHO;
	icmpheader->icmp_id = htons(t->ident);
	icmpheader->icmp_seq = htons(outdata->seq);
	icmpheader->icmp_cksum = 0;
	icmpheader->icmp_cksum = in_cksum((u_short *)icmpheader, t->protlen);
	if (icmpheader->icmp_cksum == 0)
		icmpheader->icmp_cksum = 0xffff;
}

int
icmp_check(struct traceroute *t, const u_char *data, int seq)
{
	struct icmp *const icmpheader = (struct icmp *) data;

	return (icmpheader->icmp_id == htons(t->ident)
	    && icmpheader->icmp_seq == htons(seq));
}

void
udp_prep(struct traceroute *t, struct outdata *outdata)
{
	struct udphdr *const outudp = (struct udphdr *) t->outp;

	outudp->uh_sport = htons(t->ident + (t->fixedPort ? outdata->seq : 0));
	outudp->uh_dport = htons(t->port + (t->fixedPort ? 0 : outdata->seq));
	outudp->uh_ulen = htons((u_short)t->protlen);
	outudp->uh_sum = 0;

	return;
}

int
udp_check(struct traceroute *t, const u_char *data, int seq)
{
	struct udphdr *const udp = (struct udphdr *) data;

	return (ntohs(udp->uh_sport) == t->ident + (t->fixedPort ? seq : 0) &&
	    ntohs(udp->uh_dport) == t->port + (t->fixedPort ? 0 : seq));
}

void
tcp_prep(struct traceroute *t, struct outdata *outdata)
{
	struct tcphdr *const tcp = (struct tcphdr *) t->outp;

	tcp->th_sport = htons(t->ident);
	tcp->th_dport = htons(t->port + (t->fixedPort ? 0 : outdata->seq));
	tcp->th_seq = (tcp->th_sport << 16) | (tcp->th_dport +
	    (t->fixedPort ? outdata->seq : 0));
	tcp->th_ack = 0;
	tcp->th_off = 5;
	tcp->th_flags = TH_SYN;
	tcp->th_sum = 0;
}

int
tcp_check(struct traceroute *t, const u_char *data, int seq)
{
	struct tcphdr *const tcp = (struct tcphdr *) data;

	return (ntohs(tcp->th_sport) == t->ident
	    && ntohs(tcp->th_dport) == t->port + (t->fixedPort ? 0 : seq))
	    && tcp->th_seq == (((tcp_seq)t->ident << 16) | (t->port + seq));
}

void
gre_prep(struct traceroute *t, struct outdata *outdata)
{
	struct grehdr *const gre = (struct grehdr *) t->outp;

	gre->flags = htons(0x2001);
	gre->proto = htons(t->port);
	gre->length = 0;
	gre->callId = htons(t->ident + outdata->seq);
}

int
gre_check(struct traceroute *t, const u_char *data, int seq)
{
	struct grehdr *const gre = (struct grehdr *) data;

	return(ntohs(gre->proto) == t->port
	    && ntohs(gre->callId) == t->ident + seq);
}

void
gen_prep(struct traceroute *t, struct outdata *outdata)
{
	u_int16_t *const ptr = (u_int16_t *) t->outp;

	ptr[0] = htons(t->ident);
	ptr[1] = htons(t->port + outdata->seq);
}

int
gen_check(struct traceroute *t, const u_char *data, int seq)
{
	u_int16_t *const ptr = (u_int16_t *) data;

	return(ntohs(ptr[0]) == t->ident
	    && ntohs(ptr[1]) == t->port + seq);
}

void
print(struct traceroute *t, register u_char *buf, register int cc, register struct sockaddr_in *from)
{
	register struct ip *ip;
	register int hlen;
	char addr[INET_ADDRSTRLEN];

	ip = (struct ip *) buf;
	hlen = ip->ip_hl << 2;
	cc -= hlen;

	strncpy(addr, inet_ntoa(from->sin_addr), sizeof(addr));

	if (t->nflag)
		Printf(" %s", addr);
	else
		Printf(" %s (%s)", inetname(t, from->sin_addr), addr);

	if (t->verbose)
		Printf(" %d bytes to %s", cc, inet_ntoa (ip->ip_dst));
}

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 */
u_short
in_cksum(register u_short *addr, register int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += *(u_char *)w;

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/*
 * Subtract 2 timeval structs:  out = out - in.
 * Out is assumed to be within about LONG_MAX seconds of in.
 */
void
tvsub(register struct timeval *out, register struct timeval *in)
{

	if ((out->tv_usec -= in->tv_usec) < 0)   {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

/*
 * Construct an Internet address representation.
 * If the nflag has been supplied, give
 * numeric value, otherwise try for symbolic name.
 */
char *
inetname(struct traceroute *t, struct in_addr in)
{
	register char *cp;
	register struct hostent *hp;
	static int first = 1;
	static char domain[MAXHOSTNAMELEN + 1], line[MAXHOSTNAMELEN + 1];

	if (first && !t->nflag) {
		first = 0;
		if (gethostname(domain, sizeof(domain) - 1) < 0)
			domain[0] = '\0';
		else {
			cp = strchr(domain, '.');
			if (cp == NULL) {
				hp = gethostbyname(domain);
				if (hp != NULL)
					cp = strchr(hp->h_name, '.');
			}
			if (cp == NULL)
				domain[0] = '\0';
			else {
				++cp;
				(void)strncpy(domain, cp, sizeof(domain) - 1);
				domain[sizeof(domain) - 1] = '\0';
			}
		}
	}
	if (!t->nflag && in.s_addr != INADDR_ANY) {
		hp = gethostbyaddr((char *)&in, sizeof(in), AF_INET);
		if (hp != NULL) {
			if ((cp = strchr(hp->h_name, '.')) != NULL &&
			    strcmp(cp + 1, domain) == 0)
				*cp = '\0';
			(void)strncpy(line, hp->h_name, sizeof(line) - 1);
			line[sizeof(line) - 1] = '\0';
			return (line);
		}
	}
	return (inet_ntoa(in));
}

struct hostinfo *
gethostinfo(const char *hostname)
{
	int n;
	struct hostent *hp;
	struct hostinfo *hi;
	char **p;
	u_int32_t addr, *ap;

	if (strlen(hostname) >= MAXHOSTNAMELEN) {
		Fprintf(stderr, "%s: hostname \"%.32s...\" is too long\n",
		    prog, hostname);
		exit(1);
	}
	hi = calloc(1, sizeof(*hi));
	if (hi == NULL) {
		Fprintf(stderr, "%s: calloc %s\n", prog, strerror(errno));
		exit(1);
	}
	addr = inet_addr(hostname);
	if ((int32_t)addr != -1) {
		hi->name = strdup(hostname);
		hi->n = 1;
		hi->addrs = calloc(1, sizeof(hi->addrs[0]));
		if (hi->addrs == NULL) {
			Fprintf(stderr, "%s: calloc %s\n",
			    prog, strerror(errno));
			exit(1);
		}
		hi->addrs[0] = addr;
		return (hi);
	}

	hp = gethostbyname(hostname);
	if (hp == NULL) {
		Fprintf(stderr, "%s: unknown host %s\n", prog, hostname);
		exit(1);
	}
	if (hp->h_addrtype != AF_INET || hp->h_length != 4) {
		Fprintf(stderr, "%s: bad host %s\n", prog, hostname);
		exit(1);
	}
	hi->name = strdup(hp->h_name);
	for (n = 0, p = hp->h_addr_list; *p != NULL; ++n, ++p)
		continue;
	hi->n = n;
	hi->addrs = calloc(n, sizeof(hi->addrs[0]));
	if (hi->addrs == NULL) {
		Fprintf(stderr, "%s: calloc %s\n", prog, strerror(errno));
		exit(1);
	}
	for (ap = hi->addrs, p = hp->h_addr_list; *p != NULL; ++ap, ++p) {
		memcpy(ap, *p, sizeof(*ap));
	}
	return (hi);
}

void
freehostinfo(register struct hostinfo *hi)
{
	if (hi->name != NULL) {
		free(hi->name);
		hi->name = NULL;
	}
	free((char *)hi->addrs);
	free((char *)hi);
}

void
getaddr(register u_int32_t *ap, register char *hostname)
{
	register struct hostinfo *hi;

	hi = gethostinfo(hostname);
	*ap = hi->addrs[0];
	freehostinfo(hi);
}

void
setsin(register struct sockaddr_in *sin, register u_int32_t addr)
{

	memset(sin, 0, sizeof(*sin));
#ifdef HAVE_SOCKADDR_SA_LEN
	sin->sin_len = sizeof(*sin);
#endif
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr;
}

/* String to value with optional min and max. Handles decimal and hex. */
int
str2val(register const char *str, register const char *what,
    register int mi, register int ma)
{
	register const char *cp;
	register int val;
	char *ep;

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
		cp = str + 2;
		val = (int)strtol(cp, &ep, 16);
	} else
		val = (int)strtol(str, &ep, 10);
	if (*ep != '\0') {
		Fprintf(stderr, "%s: \"%s\" bad value for %s \n",
		    prog, str, what);
		exit(1);
	}
	if (val < mi && mi >= 0) {
		if (mi == 0)
			Fprintf(stderr, "%s: %s must be >= %d\n",
			    prog, what, mi);
		else
			Fprintf(stderr, "%s: %s must be > %d\n",
			    prog, what, mi - 1);
		exit(1);
	}
	if (val > ma && ma >= 0) {
		Fprintf(stderr, "%s: %s must be <= %d\n", prog, what, ma);
		exit(1);
	}
	return (val);
}

struct outproto *
setproto(char *pname)
{
	struct outproto *proto;
	int i;

	for (i = 0; protos[i].name != NULL; i++) {
		if (strcasecmp(protos[i].name, pname) == 0) {
			break;
		}
	}
	proto = &protos[i];
	if (proto->name == NULL) {	/* generic handler */
		struct protoent *pe;
		u_long pnum;

		/* Determine the IP protocol number */
		if ((pe = getprotobyname(pname)) != NULL)
			pnum = pe->p_proto;
		else
			pnum = str2val(optarg, "proto number", 1, 255);
		proto->num = pnum;
	}
	return proto;
}

void
pkt_compare(const u_char *a, int la, const u_char *b, int lb) {
	int l;
	int i;

	for (i = 0; i < la; i++)
		Printf("%02x", (unsigned int)a[i]);
	Printf("\n");
	l = (la <= lb) ? la : lb;
	for (i = 0; i < l; i++)
		if (a[i] == b[i])
			Printf("__");
		else
			Printf("%02x", (unsigned int)b[i]);
	for (; i < lb; i++)
		Printf("%02x", (unsigned int)b[i]);
	Printf("\n");
}


void
usage(void)
{
	Fprintf(stderr,
	    "Usage: %s [-adDeFInrSvx] [-f first_ttl] [-g gateway] [-i iface]\n"
	    "\t[-m max_ttl] [-p port] [-P proto] [-q nqueries] [-s src_addr]\n"
	    "\t[-t tos] [-w waittime] [-A as_server] [-z pausemsecs] host [packetlen]\n", prog);
	exit(1);
}
