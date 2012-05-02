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

#include "traceroute.h"
#include "traceroute_private.h"

struct	outproto *proto = &protos[0];

struct traceroute *
traceroute_alloc() {
	return calloc(1, sizeof(struct traceroute));
}

void
traceroute_init(struct traceroute *t) {
	t->proto = proto;
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
	double dt;

	dt = (t2p->tv_sec - t1p->tv_sec) * 1000.0;
	dt += (t2p->tv_usec - t1p->tv_usec) / 1000.0;

	return dt;
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
