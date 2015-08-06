/* ----------------------------------------------------------------------- *
 *   
 *  parse_subs.c - misc parser subroutines
 *                automounter map
 * 
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *   Copyright 2004-2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <libgen.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "automount.h"

#define MAX_OPTIONS_LEN		256
#define MAX_OPTION_LEN		40

#define MAX_NETWORK_LEN		255

#define MAX_IFC_BUF		2048
static int volatile ifc_buf_len = MAX_IFC_BUF;
static int volatile ifc_last_len = 0;

#define MASK_A  0x7F000000
#define MASK_B  0xBFFF0000
#define MASK_C  0xDFFFFF00

/* Get numeric value of the n bits starting at position p */
#define getbits(x, p, n)	((x >> (p + 1 - n)) & ~(~0 << n))

#define EXPAND_LEADING_SLASH	0x0001
#define EXPAND_TRAILING_SLASH	0x0002
#define EXPAND_LEADING_DOT	0x0004
#define EXPAND_TRAILING_DOT	0x0008

#define SELECTOR_HASH_SIZE	20

static struct sel sel_table[] = {
	{ SEL_ARCH,	  "arch",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_KARCH,	  "karch",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_OS,	  "os",		SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_OSVER,	  "osver",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_FULL_OS,	  "full_os",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_VENDOR,	  "vendor",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_HOST,	  "host",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_HOSTD,	  "hostd",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_XHOST,	  "xhost",	SEL_FLAG_FUNC1|SEL_FLAG_BOOL, NULL },
	{ SEL_DOMAIN,	  "domain",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_BYTE,	  "byte",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_CLUSTER,	  "cluster",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_NETGRP,	  "netgrp",	SEL_FLAG_FUNC2|SEL_FLAG_BOOL, NULL },
	{ SEL_NETGRPD,	  "netgrpd",	SEL_FLAG_FUNC2|SEL_FLAG_BOOL, NULL },
	{ SEL_IN_NETWORK, "in_network",	SEL_FLAG_FUNC1|SEL_FLAG_BOOL, NULL },
	{ SEL_IN_NETWORK, "netnumber",	SEL_FLAG_FUNC1|SEL_FLAG_BOOL, NULL },
	{ SEL_IN_NETWORK, "network",	SEL_FLAG_FUNC1|SEL_FLAG_BOOL, NULL },
	{ SEL_IN_NETWORK, "wire",	SEL_FLAG_FUNC1|SEL_FLAG_BOOL, NULL },
	{ SEL_UID,	  "uid",	SEL_FLAG_MACRO|SEL_FLAG_NUM, NULL },
	{ SEL_GID,	  "gid",	SEL_FLAG_MACRO|SEL_FLAG_NUM, NULL },
	{ SEL_KEY,	  "key",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_MAP,	  "map",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_PATH,	  "path",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_EXISTS,	  "exists",	SEL_FLAG_FUNC1|SEL_FLAG_BOOL, NULL },
	{ SEL_AUTODIR,	  "autodir",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_DOLLAR,	  "dollar",	SEL_FLAG_MACRO|SEL_FLAG_STR, NULL },
	{ SEL_TRUE,	  "true",	SEL_FLAG_FUNC1|SEL_FLAG_BOOL, NULL },
	{ SEL_FALSE,	  "false",	SEL_FLAG_FUNC1|SEL_FLAG_BOOL, NULL },
};
static unsigned int sel_count = sizeof(sel_table)/sizeof(struct sel);

static struct sel *sel_hash[SELECTOR_HASH_SIZE];
static unsigned int sel_hash_init_done = 0;
static pthread_mutex_t sel_hash_mutex = PTHREAD_MUTEX_INITIALIZER;

struct types {
	char *type;
	unsigned int len;
};

static struct types map_type[] = {
	{ "file", 4 },
	{ "program", 7 },
	{ "yp", 2 },
	{ "nis", 3 },
	{ "nisplus", 7 },
	{ "ldap", 4 },
	{ "ldaps", 5 },
	{ "hesiod", 6 },
	{ "userdir", 7 },
	{ "hosts", 5 },
};
static unsigned int map_type_count = sizeof(map_type)/sizeof(struct types);

static struct types format_type[] = {
	{ "sun", 3 },
	{ "hesiod", 6 },
	{ "amd", 3},
};
static unsigned int format_type_count = sizeof(format_type)/sizeof(struct types);

static void sel_add(struct sel *sel)
{
	u_int32_t hval = hash(sel->name, SELECTOR_HASH_SIZE);
	struct sel *old;

	old = sel_hash[hval];
	sel_hash[hval] = sel;
	sel_hash[hval]->next = old;
}

void sel_hash_init(void)
{
	int i;

	pthread_mutex_lock(&sel_hash_mutex);
	if (sel_hash_init_done) {
		pthread_mutex_unlock(&sel_hash_mutex);
		return;
	}
	for (i = 0; i < SELECTOR_HASH_SIZE; i++)
		sel_hash[i] = NULL;

	for (i = 0; i < sel_count; i++)
		sel_add(&sel_table[i]);

	sel_hash_init_done = 1;
	pthread_mutex_unlock(&sel_hash_mutex);
}

struct sel *sel_lookup(const char *name)
{
	u_int32_t hval = hash(name, SELECTOR_HASH_SIZE);
	struct sel *sel;

	pthread_mutex_lock(&sel_hash_mutex);
	for (sel = sel_hash[hval]; sel != NULL; sel = sel->next) {
		if (strcmp(name, sel->name) == 0) {
			pthread_mutex_unlock(&sel_hash_mutex);
			return sel;
		}
	}
	pthread_mutex_unlock(&sel_hash_mutex);
	return NULL;
}

struct selector *get_selector(char *name)
{
	struct sel *sel;

	sel = sel_lookup(name);
	if (sel) {
		struct selector *new = malloc(sizeof(struct selector));
		if (!new)
			return NULL;
		memset(new, 0, sizeof(*new));
		new->sel = sel;
		return new;
	}
	return NULL;
}

void free_selector(struct selector *selector)
{
	struct selector *s = selector;
	struct selector *next = s;

	while (s) {
		next = s->next;
		if (s->sel->flags & SEL_FREE_VALUE_MASK)
			free(s->comp.value);
		if (s->sel->flags & SEL_FREE_ARG1_MASK)
			free(s->func.arg1);
		if (s->sel->flags & SEL_FREE_ARG2_MASK)
			free(s->func.arg2);
		s = next;
	}
	return;
}

static unsigned int ipv6_mask_cmp(uint32_t *host, uint32_t *iface, uint32_t *mask)
{
	unsigned int ret = 1;
	unsigned int i;

	for (i = 0; i < 4; i++) {
		if ((host[i] & mask[i]) != (iface[i] & mask[i])) {
			ret = 0;
			break;
		}
	}
	return ret;
}

unsigned int get_proximity(struct sockaddr *host_addr)
{
	struct ifaddrs *ifa = NULL;
	struct ifaddrs *this;
	struct sockaddr_in *addr, *msk_addr, *if_addr;
	struct sockaddr_in6 *addr6, *msk6_addr, *if6_addr;
	struct in_addr *hst_addr;
	struct in6_addr *hst6_addr;
	int addr_len;
	char buf[MAX_ERR_BUF];
	uint32_t mask, ha, ia, *mask6, *ha6, *ia6;
	int ret;

	addr = NULL;
	addr6 = NULL;
	hst_addr = NULL;
	hst6_addr = NULL;
	mask6 = NULL;
	ha6 = NULL;
	ia6 = NULL;
	ha = 0;

	switch (host_addr->sa_family) {
	case AF_INET:
		addr = (struct sockaddr_in *) host_addr;
		hst_addr = (struct in_addr *) &addr->sin_addr;
		ha = ntohl((uint32_t) hst_addr->s_addr);
		addr_len = sizeof(*hst_addr);
		break;

	case AF_INET6:
#ifndef WITH_LIBTIRPC
		return PROXIMITY_UNSUPPORTED;
#else
		addr6 = (struct sockaddr_in6 *) host_addr;
		hst6_addr = (struct in6_addr *) &addr6->sin6_addr;
		ha6 = &hst6_addr->s6_addr32[0];
		addr_len = sizeof(*hst6_addr);
		break;
#endif

	default:
		return PROXIMITY_ERROR;
	}

	ret = getifaddrs(&ifa);
	if (ret) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("getifaddrs: %s", estr);
		return PROXIMITY_ERROR;
	}

	this = ifa;
	while (this) {
		if (!(this->ifa_flags & IFF_UP) ||
		    this->ifa_flags & IFF_POINTOPOINT ||
		    this->ifa_addr == NULL) {
			this = this->ifa_next;
			continue;
		}

		switch (this->ifa_addr->sa_family) {
		case AF_INET:
			if (host_addr->sa_family == AF_INET6)
				break;
			if_addr = (struct sockaddr_in *) this->ifa_addr;
			ret = memcmp(&if_addr->sin_addr, hst_addr, addr_len);
			if (!ret) {
				freeifaddrs(ifa);
				return PROXIMITY_LOCAL;
			}
			break;

		case AF_INET6:
#ifdef WITH_LIBTIRPC
			if (host_addr->sa_family == AF_INET)
				break;
			if6_addr = (struct sockaddr_in6 *) this->ifa_addr;
			ret = memcmp(&if6_addr->sin6_addr, hst6_addr, addr_len);
			if (!ret) {
				freeifaddrs(ifa);
				return PROXIMITY_LOCAL;
			}
#endif
		default:
			break;
		}
		this = this->ifa_next;
	}

	this = ifa;
	while (this) {
		if (!(this->ifa_flags & IFF_UP) ||
		    this->ifa_flags & IFF_POINTOPOINT ||
		    this->ifa_addr == NULL) {
			this = this->ifa_next;
			continue;
		}

		switch (this->ifa_addr->sa_family) {
		case AF_INET:
			if (host_addr->sa_family == AF_INET6)
				break;
			if_addr = (struct sockaddr_in *) this->ifa_addr;
			ia =  ntohl((uint32_t) if_addr->sin_addr.s_addr);

			/* Is the address within a localy attached subnet */

			msk_addr = (struct sockaddr_in *) this->ifa_netmask;
			mask = ntohl((uint32_t) msk_addr->sin_addr.s_addr);

			if ((ia & mask) == (ha & mask)) {
				freeifaddrs(ifa);
				return PROXIMITY_SUBNET;
			}

			/*
			 * Is the address within a local ipv4 network.
			 *
			 * Bit position 31 == 0 => class A.
			 * Bit position 30 == 0 => class B.
			 * Bit position 29 == 0 => class C.
			 */

			if (!getbits(ia, 31, 1))
				mask = MASK_A;
			else if (!getbits(ia, 30, 1))
				mask = MASK_B;
			else if (!getbits(ia, 29, 1))
				mask = MASK_C;
			else
				break;

			if ((ia & mask) == (ha & mask)) {
				freeifaddrs(ifa);
				return PROXIMITY_NET;
			}
			break;

		case AF_INET6:
#ifdef WITH_LIBTIRPC
			if (host_addr->sa_family == AF_INET)
				break;
			if6_addr = (struct sockaddr_in6 *) this->ifa_addr;
			ia6 = &if6_addr->sin6_addr.s6_addr32[0];

			/* Is the address within the network of the interface */

			msk6_addr = (struct sockaddr_in6 *) this->ifa_netmask;
			mask6 = &msk6_addr->sin6_addr.s6_addr32[0];

			if (ipv6_mask_cmp(ha6, ia6, mask6)) {
				freeifaddrs(ifa);
				return PROXIMITY_SUBNET;
			}

			/* How do we define "local network" in ipv6? */
#endif
		default:
			break;
		}
		this = this->ifa_next;
	}

	freeifaddrs(ifa);

	return PROXIMITY_OTHER;
}

static char *inet_fill_net(const char *net_num, char *net)
{
	char *np;
	int dots = 3;

	if (strlen(net_num) > INET_ADDRSTRLEN)
		return NULL;

	if (!isdigit(*net_num))
		return NULL;

	*net = '\0';
	strcpy(net, net_num);

	np = net;
	while (*np++) {
		if (*np == '.') {
			np++;
			dots--;
			if (!*np && dots)
				strcat(net, "0");
			continue;
		}

		if ((*np && !isdigit(*np)) || dots < 0) {
			*net = '\0';
			return NULL;
		}
	}

	while (dots--)
		strcat(net, ".0");

	return net;
}

static char *get_network_number(const char *network)
{
	struct netent *netent;
	char cnet[MAX_NETWORK_LEN];
	uint32_t h_net;
	size_t len;

	len = strlen(network) + 1;
	if (len > MAX_NETWORK_LEN)
		return NULL;

	netent = getnetbyname(network);
	if (!netent)
		return NULL;
	h_net = ntohl(netent->n_net);

	if (!inet_ntop(AF_INET, &h_net, cnet, INET_ADDRSTRLEN))
		return NULL;

	return strdup(cnet);
}

unsigned int get_network_proximity(const char *name)
{
	struct addrinfo hints;
	struct addrinfo *ni, *this;
	char name_or_num[NI_MAXHOST + 1];
	unsigned int proximity;
	char *net;
	int ret;

	if (!name)
		return PROXIMITY_ERROR;

	net = get_network_number(name);
	if (net) {
		strcpy(name_or_num, net);
		free(net);
	} else {
		char this[NI_MAXHOST + 1];
		char *mask;

		if (strlen(name) > NI_MAXHOST)
			return PROXIMITY_ERROR;
		strcpy(this, name);
		if ((mask = strchr(this, '/')))
			*mask++ = '\0';
		if (!strchr(this, '.'))
			strcpy(name_or_num, this);
		else {
			char buf[NI_MAXHOST + 1], *new;
			new = inet_fill_net(this, buf);
			if (!new)
				return PROXIMITY_ERROR;
			strcpy(name_or_num, new);
		}
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(name_or_num, NULL, &hints, &ni);
	if (ret) {
		logerr("getaddrinfo: %s", gai_strerror(ret));
		return PROXIMITY_ERROR;
	}

	proximity = PROXIMITY_OTHER;

	this = ni;
	while (this) {
		unsigned int prx = get_proximity(this->ai_addr);
		if (prx < proximity)
			proximity = prx;
		this = this->ai_next;
	}

	return proximity;
}

unsigned int in_network(char *network)
{
	unsigned int proximity = get_network_proximity(network);
	if (proximity == PROXIMITY_ERROR ||
	    proximity > PROXIMITY_SUBNET)
		return 0;
	return 1;
}

struct mapent *match_cached_key(struct autofs_point *ap,
				const char *err_prefix,
				struct map_source *source,
				const char *key)
{
	char buf[MAX_ERR_BUF];
	struct mapent_cache *mc;
	struct mapent *me;

	mc = source->mc;

	if (!(source->flags & MAP_FLAG_FORMAT_AMD)) {
		int ret;

		me = cache_lookup(mc, key);
		/*
		 * Stale mapent => check for entry in alternate source or
		 * wildcard. Note, plus included direct mount map entries
		 * are included as an instance (same map entry cache), not
		 * in a distinct source.
		 */
		if (me && (!me->mapent ||
		   (me->source != source && *me->key != '/'))) {
			while ((me = cache_lookup_key_next(me)))
				if (me->source == source)
					break;
			if (!me)
				me = cache_lookup_distinct(mc, "*");
		}

		if (!me)
			goto done;

		/*
		 * If this is a lookup add wildcard match for later validation
		 * checks and negative cache lookups.
		 */
		if (!(ap->flags & MOUNT_FLAG_REMOUNT) &&
		    ap->type == LKP_INDIRECT && *me->key == '*') {
			ret = cache_update(mc, source, key, me->mapent, me->age);
			if (!(ret & (CHE_OK | CHE_UPDATED)))
				me = NULL;
		}
	} else {
		char *lkp_key = strdup(key);
		if (!lkp_key) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, "%s strdup: %s", err_prefix, estr);
			return NULL;
		}

		/* If it's found we're done */
		me = cache_lookup_distinct(mc, lkp_key);
		if (me)
			goto free;

		/*
		 * Otherwise strip successive directory components and try
		 * a match against map entries ending with a wildcard and
		 * finally try the wilcard entry itself.
		*/
		while (!me) {
			char *prefix;

			while ((prefix = strrchr(lkp_key, '/'))) {
				*prefix = '\0';
				me = cache_partial_match_wild(mc, lkp_key);
				if (me)
					goto free;
			}

			me = cache_lookup_distinct(mc, "*");
			if (me)
				goto free;

			break;
		}
free:
		free(lkp_key);
	}
done:
	return me;
}

/*
 * Skip whitespace in a string; if we hit a #, consider the rest of the
 * entry a comment.
 */
const char *skipspace(const char *whence)
{
	while (1) {
		switch (*whence) {
		case ' ':
		case '\b':
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
			whence++;
			break;
		case '#':	/* comment: skip to end of string */
			while (*whence != '\0')
				whence++;
			/* FALLTHROUGH */

		default:
			return whence;
		}
	}
}

/*
 * Check a string to see if a colon appears before the next '/'.
 */
int check_colon(const char *str)
{
	char *ptr = (char *) str;

	/* Colon escape */
	if (!strncmp(ptr, ":/", 2))
		return 1;

	while (*ptr && strncmp(ptr, ":/", 2))
		ptr++;

	if (!*ptr)
		return 0;

	return 1;
}

/* Get the length of a chunk delimitered by whitespace */
int chunklen(const char *whence, int expect_colon)
{
	char *str = (char *) whence;
	int n = 0;
	int quote = 0;

	for (; *str; str++, n++) {
		switch (*str) {
		case '\\':
			if( quote ) {
				break;
			} else {
				quote = 1;
				continue;
			}
		case '"':
			if (quote)
				break;
			while (*str) {
				str++;
				n++;
				if (*str == '"')
					break;
				if (!strncmp(str, ":/", 2))
					expect_colon = 0;
			}
			break;
		case ':':
			if (expect_colon && !strncmp(str, ":/", 2))
				expect_colon = 0;
			continue;
		case ' ':
		case '\t':
			/* Skip space or tab if we expect a colon */
			if (expect_colon)
				continue;
		case '\b':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case '\0':
			if (!quote)
				return n;
			/* FALLTHROUGH */
		default:
			break;
		}
		quote = 0;
	}

	return n;
}

/*
 * Compare str with pat.  Return 0 if compare equal or
 * str is an abbreviation of pat of no less than mchr characters.
 */
int strmcmp(const char *str, const char *pat, int mchr)
{
	int nchr = 0;

	while (*str == *pat) {
		if (!*str)
			return 0;
		str++;
		pat++;
		nchr++;
	}

	if (!*str && nchr > mchr)
		return 0;

	return *pat - *str;
}

char *dequote(const char *str, int origlen, unsigned int logopt)
{
	char *ret = malloc(origlen + 1);
	char *cp = ret;
	const char *scp;
	int len = origlen;
	int quote = 0, dquote = 0;
	int i, j;

	if (ret == NULL)
		return NULL;

	/* first thing to do is strip white space from the end */
	i = len - 1;
	while (isspace(str[i])) {
		/* of course, we have to keep escaped white-space */
		j = i - 1;
		if (j > 0 && (str[j] == '\\' || str[j] == '"'))
			break;
		i--;
		len--;
	}

	for (scp = str; len > 0 && *scp; scp++, len--) {
		if (!quote) {
			if (*scp == '"') {
				if (dquote)
					dquote = 0;
				else
					dquote = 1;
				continue;
			}

			if (!dquote) {
				if (*scp == '\\') {
					quote = 1;
					continue;
				}
			}
		}
		quote = 0;
		*cp++ = *scp;
	}
	*cp = '\0';

	if (dquote) {
		debug(logopt, "unmatched quote in %.*s", origlen, str);
		free(ret);
		return NULL;
	}

	return ret;
}

int span_space(const char *str, unsigned int maxlen)
{
	const char *p = str;
	unsigned int len = 0;

	while (*p && !isblank(*p) && len < maxlen) {
		if (*p == '"') {
			while (*p++ && len++ < maxlen) {
				if (*p == '"')
					break;
			}
		} else if (*p == '\\') {
			p += 2;
			len += 2;
			continue;
		}
		p++;
		len++;
	}
	return len;
}

char *sanitize_path(const char *path, int origlen, unsigned int type, unsigned int logopt)
{
	char *slash, *cp, *s_path;
	const char *scp;
	int len = origlen;
	unsigned int seen_slash = 0, quote = 0, dquote = 0;

	if (type & (LKP_INDIRECT | LKP_DIRECT)) {
		slash = strchr(path, '/');
		if (slash) {
			if (type == LKP_INDIRECT)
				return NULL;
			if (*path != '/')
				return NULL;
		} else {
			if (type == LKP_DIRECT)
				return NULL;
		}
	}

	s_path = malloc(origlen + 1);
	if (!s_path)
		return NULL;

	for (cp = s_path, scp = path; len > 0; scp++, len--) {
		if (!quote) {
			if (*scp == '"') {
				if (dquote)
					dquote = 0;
				else
					dquote = 1;
				continue;
			}

			if (!dquote) {
				/* Badness in string - go away */
				if (*scp < 32) {
					free(s_path);
					return NULL;
				}

				if (*scp == '\\') {
					quote = 1;
					continue;
				} 
			}

			/*
			 * Not really proper but we get problems with
			 * paths with multiple slashes. The kernel
			 * compresses them so when we get a query there
			 * should be only single slashes.
			 */
			if (*scp == '/') {
				if (seen_slash)
					continue;
				seen_slash = 1;
			} else
				seen_slash = 0;
		}
		quote = 0;
		*cp++ = *scp;
	}
	*cp = '\0';

	if (dquote) {
		debug(logopt, "unmatched quote in %.*s", origlen, path);
		free(s_path);
		return NULL;
	}

	/* Remove trailing / but watch out for a quoted / alone */
	if (strlen(cp) > 1 && origlen > 1 && *(cp - 1) == '/')
		*(cp - 1) = '\0';

	return s_path;
}

static char *hasopt(const char *str, const char *opt)
{
	const size_t optlen = strlen(opt);
	char *rest = (char *) str, *p;

	while ((p = strstr(rest, opt)) != NULL) {
		if ((p == rest || p[-1] == ',') &&
		    (p[optlen] == '\0' || p[optlen] == '=' ||
		     p[optlen] == ','))
			return p;

		rest = strchr (p, ',');
		if (rest == NULL)
			break;
		++rest;
	}

	return NULL;
}

char *merge_options(const char *opt1, const char *opt2)
{
	char str[MAX_OPTIONS_LEN + 1];
	char result[MAX_OPTIONS_LEN + 1];
	char neg[MAX_OPTION_LEN + 1];
	char *tok, *ptr = NULL;
	size_t resultlen, len;

	if ((!opt1 || !*opt1) && (!opt2 || !*opt2))
		return NULL;

	if (!opt2 || !*opt2) {
		if (!*opt1)
			return NULL;
		return strdup(opt1);
	}

	if (!opt1 || !*opt1) {
		if (!*opt2)
			return NULL;
		return strdup(opt2);
	}

	if (!strcmp(opt1, opt2))
		return strdup(opt1);

	if (strlen(str) > MAX_OPTIONS_LEN)
		return NULL;
	memset(result, 0, sizeof(result));
	strcpy(str, opt1);

	resultlen = 0;
	tok = strtok_r(str, ",", &ptr);
	while (tok) {
		const char *this = (const char *) tok;
		char *eq = strchr(this, '=');
		if (eq) {
			*eq = '\0';
			if (!hasopt(opt2, this)) {
				if (resultlen + strlen(this) > MAX_OPTIONS_LEN)
					return NULL;
				*eq = '=';
				if (!*result)
					strcpy(result, this);
				else
					strcat(result, this);
				strcat(result, ",");
				resultlen += strlen(this) + 1;
				goto next;
			}
		}

		if (!strcmp(this, "rw") && hasopt(opt2, "ro"))
			goto next;
		if (!strcmp(this, "ro") && hasopt(opt2, "rw"))
			goto next;
		if (!strcmp(this, "bg") && hasopt(opt2, "fg"))
			goto next;
		if (!strcmp(this, "fg") && hasopt(opt2, "bg"))
			goto next;
		if (!strcmp(this, "bg") && hasopt(opt2, "fg"))
			goto next;
		if (!strcmp(this, "soft") && hasopt(opt2, "hard"))
			goto next;
		if (!strcmp(this, "hard") && hasopt(opt2, "soft"))
			goto next;

		if (!strncmp(this, "no", 2)) {
			if (strlen(this + 2) > MAX_OPTION_LEN)
				return NULL;
			strcpy(neg, this + 2);
			if (hasopt(opt2, neg))
				goto next;
		} else {
			if ((strlen(this) + 2) > MAX_OPTION_LEN)
				return NULL;
			strcpy(neg, "no");
			strcat(neg, this);
			if (hasopt(opt2, neg))
				goto next;
		}

		if (hasopt(opt2, tok))
			goto next;

		if (resultlen + strlen(this) + 1 > MAX_OPTIONS_LEN)
			return NULL;

		if (!*result)
			strcpy(result, this);
		else
			strcat(result, this);
		strcat(result, ",");
		resultlen =+ strlen(this) + 1;
next:
		tok = strtok_r(NULL, ",", &ptr);
	}

	if (resultlen + strlen(opt2) > MAX_OPTIONS_LEN)
		return NULL;

	if (!*result)
		strcpy(result, opt2);
	else
		strcat(result, opt2);

	len = strlen(result);
	if (len && result[len - 1] == ',')
		result[len - 1] = '\0';

	return strdup(result);
}

static char *expand_slash_or_dot(char *str, unsigned int type)
{
	char *val = NULL;

	if (!str)
		return NULL;

	if (!type)
		return str;

	if (type & EXPAND_LEADING_SLASH)
		val = basename(str);
	else if (type & EXPAND_TRAILING_SLASH)
		val = dirname(str);
	else if (type & (EXPAND_LEADING_DOT | EXPAND_TRAILING_DOT)) {
		char *dot = strchr(str, '.');
		if (dot)
			*dot++ = '\0';
		if (type & EXPAND_LEADING_DOT)
			val = dot;
		else
			val = str;
	}

	return val;
}

/*
 * $-expand an amd-style map entry and return the length of the entry.
 * If "dst" is NULL, just count the length.
 */
/* TODO: how should quoting be handled? */
int expandamdent(const char *src, char *dst, const struct substvar *svc)
{
	unsigned int flags = conf_amd_get_flags(NULL);
	const struct substvar *sv;
	const char *o_src = src;
	int len, l;
	const char *p;
	char ch;

	len = 0;

	while ((ch = *src++)) {
		switch (ch) {
		case '$':
			if (*src == '{') {
				char *start, *end;
				unsigned int type = 0;
				p = strchr(++src, '}');
				if (!p) {
					/* Ignore rest of string */
					if (dst)
						*dst = '\0';
					return len;
				}
				start = (char *) src;
				if (*src == '/' || *src == '.') {
					start++;
					type = EXPAND_LEADING_SLASH;
					if (*src == '.')
						type = EXPAND_LEADING_DOT;
				}
				end = (char *) p;
				if (*(p - 1) == '/' || *(p - 1) == '.') {
					end--;
					type = EXPAND_TRAILING_SLASH;
					if (*(p - 1) == '.')
						type = EXPAND_TRAILING_DOT;
				}
				sv = macro_findvar(svc, start, end - start);
				if (sv) {
					char *val;
					char *str = strdup(sv->val);
					val = expand_slash_or_dot(str, type);
					if (!val)
						val = sv->val;
					l = strlen(val);
					if (dst) {
						if (*dst)
							strcat(dst, val);
						else
							strcpy(dst, val);
						dst += l;
					}
					len += l;
					if (str)
						free(str);
				} else {
					if (dst) {
						*dst++ = ch;
						*dst++ = '{';
						strncat(dst, src, p - src);
						dst += (p - src);
						*dst++ = '}';
					}
					len += 1 + 1 + (p - src) + 1;
				}
				src = p + 1;
			} else {
				if (dst)
					*(dst++) = ch;
				len++;
			}
			break;

		case '\\':
			if (!(flags & CONF_NORMALIZE_SLASHES)) {
				len++;
				if (dst)
					*dst++ = ch;
				break;
			}

			if (*src) {
				len++;
				if (dst)
					*dst++ = *src;
				src++;
			}
			break;

		case '/':
			len++;
			if (dst)
				*dst++ = ch;

			if (!(flags & CONF_NORMALIZE_SLASHES))
				break;

			/* Double slash at start is allowed */
			if (src == (o_src + 1) && *src == '/') {
				len++;
				if (dst)
					*dst++ = *src;
				src++;
			}
			while (*src == '/')
				src++;
			break;

		case '"':
			len++;
			if (dst)
				*dst++ = ch;

			while (*src && *src != '"') {
				len++;
				if (dst)
					*dst++ = *src;
				src++;
			}
			if (*src) {
				len++;
				if (dst)
					*dst++ = *src;
				src++;
			}
			break;

		default:
			if (dst)
				*(dst++) = ch;
			len++;
			break;
		}
	}
	if (dst)
		*dst = '\0';

	return len;
}

int expand_selectors(struct autofs_point *ap,
		     const char *mapstr, char **pmapstr,
		     struct substvar *sv)
{
	char buf[MAX_ERR_BUF];
	char *expand;
	size_t len;

	if (!mapstr)
		return 0;

	len = expandamdent(mapstr, NULL, sv);
	if (len == 0) {
		error(ap->logopt, "failed to expand map entry");
		return 0;
	}

	expand = malloc(len + 1);
	if (!expand) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "malloc: %s", estr);
		return 0;
	}
	memset(expand, 0, len + 1);

	expandamdent(mapstr, expand, sv);

	*pmapstr = expand;

	return len;
}

void free_map_type_info(struct map_type_info *info)
{
	if (info->type)
		free(info->type);
	if (info->format)
		free(info->format);
	if (info->map)
		free(info->map);
	free(info);
	return;
}

struct map_type_info *parse_map_type_info(const char *str)
{
	struct map_type_info *info;
	char *buf, *type, *fmt, *map, *tmp;
	char *pos;

	buf = strdup(str);
	if (!buf)
		return NULL;

	info = malloc(sizeof(struct map_type_info));
	if (!info) {
		free(buf);
		return NULL;
	}
	memset(info, 0, sizeof(struct map_type_info));

	type = fmt = map = NULL;

	tmp = strchr(buf, ':');
	if (!tmp) {
		pos = buf;
		while (*pos == ' ')
			*pos++ = '\0';
		map = pos;
	} else {
		int i, j;

		for (i = 0; i < map_type_count; i++) {
			char *m_type = map_type[i].type;
			unsigned int m_len = map_type[i].len;

			pos = buf;

			if (strncmp(m_type, pos, m_len))
				continue;

			type = pos;
			pos += m_len;

			if (*pos == ' ' || *pos == ':') {
				while (*pos == ' ')
					*pos++ = '\0';
				if (*pos != ':') {
					free(buf);
					free(info);
					return NULL;
				} else {
					*pos++ = '\0';
					while (*pos && *pos == ' ')
						*pos++ = '\0';
					map = pos;
					break;
				}
			}

			if (*pos == ',') {
				*pos++ = '\0';
				for (j = 0; j < format_type_count; j++) {
					char *f_type = format_type[j].type;
					unsigned int f_len = format_type[j].len;
				
					if (strncmp(f_type, pos, f_len))
						continue;

					fmt = pos;
					pos += f_len;

					if (*pos == ' ' || *pos == ':') {
						while (*pos == ' ')
							*pos++ = '\0';
						if (*pos != ':') {
							free(buf);
							free(info);
							return NULL;
						} else {
							*pos++ = '\0';
							while (*pos && *pos == ' ')
								*pos++ = '\0';
							map = pos;
							break;
						}
					}
				}
			}
		}

		if (!type) {
			pos = buf;
			while (*pos == ' ')
				*pos++ = '\0';
			map = pos;
		}
	}

	/* Look for space terminator - ignore local options */
	for (tmp = buf; *tmp; tmp++) {
		if (*tmp == ' ') {
			*tmp = '\0';
			break;
		}
		if (*tmp == '\\')
			tmp++;
	}

	if (type) {
		info->type = strdup(type);
		if (!info->type) {
			free(buf);
			free_map_type_info(info);
			return NULL;
		}
	}

	if (fmt) {
		info->format = strdup(fmt);
		if (!info->format) {
			free(buf);
			free_map_type_info(info);
			return NULL;
		}
	}

	if (map) {
		info->map = strdup(map);
		if (!info->map) {
			free(buf);
			free_map_type_info(info);
			return NULL;
		}
	}

	free(buf);

	return info;
}

