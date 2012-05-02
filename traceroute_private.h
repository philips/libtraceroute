#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	64
#endif

/* rfc1716 */
#ifndef ICMP_UNREACH_FILTER_PROHIB
#define ICMP_UNREACH_FILTER_PROHIB	13	/* admin prohibited filter */
#endif
#ifndef ICMP_UNREACH_HOST_PRECEDENCE
#define ICMP_UNREACH_HOST_PRECEDENCE	14	/* host precedence violation */
#endif
#ifndef ICMP_UNREACH_PRECEDENCE_CUTOFF
#define ICMP_UNREACH_PRECEDENCE_CUTOFF	15	/* precedence cutoff */
#endif

/* Maximum number of gateways (include room for one noop) */
#define NGATEWAYS ((int)((MAX_IPOPTLEN - IPOPT_MINOFF - 1) / sizeof(u_int32_t)))

/* Host name and address list */
struct hostinfo {
	char *name;
	int n;
	u_int32_t *addrs;
};

/* Data section of the probe packet */
struct outdata {
	u_char seq;		/* sequence number of this packet */
	u_char ttl;		/* ttl packet left with */
	struct timeval tv;	/* time packet left */
};

#ifndef HAVE_ICMP_NEXTMTU
/* Path MTU Discovery (RFC1191) */
struct my_pmtu {
	u_short ipm_void;
	u_short ipm_nextmtu;
};
#endif

/* What a GRE packet header looks like */
struct grehdr {
	u_int16_t   flags;
	u_int16_t   proto;
	u_int16_t   length;	/* PPTP version of these fields */
	u_int16_t   callId;
};
#ifndef IPPROTO_GRE
#define IPPROTO_GRE	47
#endif

/* For GRE, we prepare what looks like a PPTP packet */
#define GRE_PPTP_PROTO	0x880b
