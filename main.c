#include "traceroute.h"

const char *ip_hdr_key = "vhtslen id  off tlprsum srcip   dstip   opts";

int
main(int argc, char **argv)
{
	struct traceroute *t = traceroute_alloc();
	int op, code, n;
	char *cp;
	const char *err;
	u_int32_t *ap;
	struct sockaddr_in *from = (struct sockaddr_in *)&t->wherefrom;
	struct sockaddr_in *to = (struct sockaddr_in *)&t->whereto;
	int on = 1;
	struct protoent *pe;
	int ttl, probe, i;
	int seq = 0;
	int tos = 0, settos = 0;
	struct ifaddrlist *al;
	char errbuf[132];
	int requestPort = -1;
	int sump = 0;
	int sockerrno;
	const char devnull[] = "/dev/null";
	int printdiff = 0; /* Print the difference between sent and quoted */

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

	traceroute_init(t);
	if (argc == 2) {
		traceroute_set_hostname(t, argv[1]);
	} else {
		fprintf(stderr, "usage: traceroute hostname\n");
		return 1;
	}

	setvbuf(stdout, NULL, _IOLBF, 0);

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
			int cc;
			struct timeval t1, t2;
			struct ip *ip;
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
			(*t->proto->prepare)(t, &outdata);
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
				if (printdiff) {
					Printf("\n");
					Printf("%*.*s%s\n",
					    -(t->outip->ip_hl << 3),
					    t->outip->ip_hl << 3,
					    ip_hdr_key,
					    t->proto->key);
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
