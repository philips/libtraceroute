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
	int ret;

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
	traceroute_init(t);
	ret = traceroute_set_proto(t, "icmp");
	if (ret != 0) {
		fprintf(stderr, "traceroute_set_proto failed: %i\n", ret);
		return ret;
	}

	if (setuid(getuid()) != 0) {
		perror("setuid()");
		exit(1);
	}

	if (argc == 2) {
		traceroute_set_hostname(t, argv[1]);
	} else {
		fprintf(stderr, "usage: traceroute hostname\n");
		return 1;
	}

	ret = traceroute_bind(t);
	if (ret != 0) {
		fprintf(stderr, "traceroute_bind failed: %i\n", ret);
		return ret;
	}

	setvbuf(stdout, NULL, _IOLBF, 0);

	Fprintf(stderr, "%s to %s (%s)",
	    prog, t->hostname, inet_ntoa(t->to->sin_addr));
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
			while ((cc = wait_for_reply(t, t->s, t->from, &t1)) != 0) {
				double T;
				int precis;

				(void)gettimeofday(&t2, NULL);
				i = packet_ok(t, t->packet, cc, t->from, seq);
				/* Skip short packet */
				if (i == 0)
					continue;
				if (!gotlastaddr ||
				    t->from->sin_addr.s_addr != lastaddr) {
					if (gotlastaddr) printf("\n   ");
					print(t, t->packet, cc, t->from);
					lastaddr = t->from->sin_addr.s_addr;
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
