/*
 * Copyright 2011 Ian Kent <raven@themaw.net>
 * Copyright 2011 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <stdlib.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <ldap.h>
#include <sys/param.h>
#include <errno.h>
#include <endian.h>

#include "automount.h"
#include "dclist.h"

#define MAX_TTL		(60*60) /* 1 hour */

struct rr {
	unsigned int type;
	unsigned int class;
	unsigned long ttl;
	unsigned int len;
};

struct srv_rr {
	const char *name;
	unsigned int priority;
	unsigned int weight;
	unsigned int port;
	unsigned long ttl;
};

static pthread_mutex_t dclist_mutex = PTHREAD_MUTEX_INITIALIZER;

static void dclist_mutex_lock(void)
{
	int status = pthread_mutex_lock(&dclist_mutex);
	if (status)
		fatal(status);
	return;
}

static void dclist_mutex_unlock(void)
{
	int status = pthread_mutex_unlock(&dclist_mutex);
	if (status)
		fatal(status);
	return;
}

static int do_srv_query(unsigned int logopt, char *name, u_char **packet)
{
	int len = PACKETSZ;
	unsigned int last_len = len;
	char ebuf[MAX_ERR_BUF];
	u_char *buf;

	while (1) {
		buf = malloc(last_len);
		if (!buf) {
			char *estr = strerror_r(errno, ebuf, MAX_ERR_BUF);
			error(logopt, "malloc: %s", estr);
			return -1;
		}

		len = res_query(name, C_IN, T_SRV, buf, last_len);
		if (len < 0) {
			char *estr = strerror_r(errno, ebuf, MAX_ERR_BUF);
			error(logopt, "Failed to resolve %s (%s)", name, estr);
			free(buf);
			return -1;
		}

		if (len == last_len) {
			/* These shouldn't too large, bump by PACKETSZ only */
			last_len += PACKETSZ;
			free(buf);
			continue;
		}

		break;
	}

	*packet = buf;

	return len;
}

static int get_name_len(u_char *buffer, u_char *start, u_char *end)
{
	char tmp[MAXDNAME];
	return dn_expand(buffer, end, start, tmp, MAXDNAME);
}

static int get_data_offset(u_char *buffer,
			   u_char *start, u_char *end,
			   struct rr *rr)
{
	u_char *cp = start;
	int name_len;

	name_len = get_name_len(buffer, start, end);
	if (name_len < 0)
		return -1;
	cp += name_len;

	GETSHORT(rr->type, cp);
	GETSHORT(rr->class, cp);
	GETLONG(rr->ttl, cp);
	GETSHORT(rr->len, cp);

	return (cp - start);
}

static struct srv_rr *parse_srv_rr(unsigned int logopt,
				   u_char *buffer, u_char *start, u_char *end,
				   struct rr *rr, struct srv_rr *srv)
{
	u_char *cp = start;
	char ebuf[MAX_ERR_BUF];
	char tmp[MAXDNAME];
	int len;

	GETSHORT(srv->priority, cp);
	GETSHORT(srv->weight, cp);
	GETSHORT(srv->port, cp);
	srv->ttl = rr->ttl;

	len = dn_expand(buffer, end, cp, tmp, MAXDNAME);
	if (len < 0) {
		error(logopt, "failed to expand name");
		return NULL;
	}
	srv->name = strdup(tmp);
	if (!srv->name) {
		char *estr = strerror_r(errno, ebuf, MAX_ERR_BUF);
		error(logopt, "strdup: %s", estr);
		return NULL;
	}

	return srv;
}

static int cmp(struct srv_rr *a, struct srv_rr *b)
{
	if (a->priority < b->priority)
		return -1;

	if (a->priority > b->priority)
		return 1;

	if (!a->weight || a->weight == b->weight)
		return 0;

	if (a->weight > b->weight)
		return -1;

	return 1;
}

static void free_srv_rrs(struct srv_rr *dcs, unsigned int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (dcs[i].name)
			free((void *) dcs[i].name);
	}
	free(dcs);
}

int get_srv_rrs(unsigned int logopt,
		char *name, struct srv_rr **dcs, unsigned int *dcs_count)
{
	struct srv_rr *srvs;
	unsigned int srv_num;
	HEADER *header;
	u_char *packet;
	u_char *start;
	u_char *end;
	unsigned int count;
	int i, len;
	char ebuf[MAX_ERR_BUF];

	len = do_srv_query(logopt, name, &packet);
	if (len < 0)
		return 0;

	header = (HEADER *) packet;
	start = packet + sizeof(HEADER);
	end = packet + len;

	srvs = NULL;
	srv_num = 0;

	/* Skip over question */
	len = get_name_len(packet, start, end);
	if (len < 0) {
		error(logopt, "failed to get name length");
		goto error_out;
	}

	start += len + QFIXEDSZ;

	count = ntohs(header->ancount);

	debug(logopt, "%d records returned in the answer section", count);

	if (count <= 0) {
		error(logopt, "no records found in answers section");
		goto error_out;
	}

	srvs = malloc(sizeof(struct srv_rr) * count);
	if (!srvs) {
		char *estr = strerror_r(errno, ebuf, MAX_ERR_BUF);
		error(logopt, "malloc: %s", estr);
		goto error_out;
	}
	memset(srvs, 0, sizeof(struct srv_rr) * count);

	srv_num = 0;
	for (i = 0; i < count && (start < end); i++) {
		unsigned int data_offset;
		struct srv_rr srv;
		struct srv_rr *psrv;
		struct rr rr;

		memset(&rr, 0, sizeof(struct rr));

		data_offset = get_data_offset(packet, start, end, &rr);
		if (data_offset <= 0) {
			error(logopt, "failed to get start of data");
			goto error_out;
		}
		start += data_offset;

		if (rr.type != T_SRV)
			continue;

		psrv = parse_srv_rr(logopt, packet, start, end, &rr, &srv);
		if (psrv) {
			memcpy(&srvs[srv_num], psrv, sizeof(struct srv_rr));
			srv_num++;
		}

		start += rr.len;
	}
	free(packet);

	if (!srv_num) {
		error(logopt, "no srv resource records found");
		goto error_srvs;
	}

	qsort(srvs, srv_num, sizeof(struct srv_rr),
		(int (*)(const void *, const void *)) cmp);

	*dcs = srvs;
	*dcs_count = srv_num;

	return 1;

error_out:
	free(packet);
error_srvs:
	if (srvs)
		free_srv_rrs(srvs, srv_num);
	return 0;
}

static char *escape_dn_commas(const char *uri)
{
	size_t len = strlen(uri);
	char *new, *tmp, *ptr;

	ptr = (char *) uri;
	while (*ptr) {
		if (*ptr == '\\')
			ptr += 2;
		if (*ptr == ',')
			len += 2;
		ptr++;
	}

	new = malloc(len + 1);
	if (!new)
		return NULL;
	memset(new, 0, len + 1);

	ptr = (char *) uri;
	tmp = new;
	while (*ptr) {
		if (*ptr == '\\') {
			ptr++;
			*tmp++ = *ptr++;
			continue;
		}
		if (*ptr == ',') {
			strcpy(tmp, "%2c");
			ptr++;
			tmp += 3;
			continue;
		}
		*tmp++ = *ptr++;
	}

	return new;
}

void free_dclist(struct dclist *dclist)
{
	if (dclist->uri)
		free((void *) dclist->uri);
	free(dclist);
}

static char *getdnsdomainname(unsigned int logopt)
{
	struct addrinfo hints, *ni;
	char name[MAXDNAME + 1];
	char buf[MAX_ERR_BUF];
	char *dnsdomain = NULL;
	char *ptr;
	int ret;

	memset(name, 0, sizeof(name));
	if (gethostname(name, MAXDNAME) == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(logopt, "gethostname: %s", estr);
		return NULL;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(name, NULL, &hints, &ni);
	if (ret) {
		error(logopt, "hostname lookup failed: %s", gai_strerror(ret));
		return NULL;
	}

	ptr = ni->ai_canonname;
	while (*ptr && *ptr != '.')
		ptr++;

	if (*++ptr)
		dnsdomain = strdup(ptr);

	freeaddrinfo(ni);

	return dnsdomain;
}

struct dclist *get_dc_list(unsigned int logopt, const char *uri)
{
	LDAPURLDesc *ludlist = NULL;
	LDAPURLDesc **ludp;
	unsigned int min_ttl = MAX_TTL;
	struct dclist *dclist = NULL;;
	char buf[MAX_ERR_BUF];
	char *dn_uri, *esc_uri;
	char *domain;
	char *list;
	int ret;

	if (strcmp(uri, "ldap:///") && strcmp(uri, "ldaps:///")) {
		dn_uri = strdup(uri);
		if (!dn_uri) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, "strdup: %s", estr);
			return NULL;
		}
	} else {
		char *dnsdomain;
		char *hdn;

		dnsdomain = getdnsdomainname(logopt);
		if (!dnsdomain) {
			error(logopt, "failed to get dns domainname");
			return NULL;
		}

		if (ldap_domain2dn(dnsdomain, &hdn) || hdn == NULL) {
			error(logopt,
			      "Could not turn domain \"%s\" into a dn\n",
			      dnsdomain);
			free(dnsdomain);
			return NULL;
		}
		free(dnsdomain);

		dn_uri = malloc(strlen(uri) + strlen(hdn) + 1);
		if (!dn_uri) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, "malloc: %s", estr);
			ber_memfree(hdn);
			return NULL;
		}

		strcpy(dn_uri, uri);
		strcat(dn_uri, hdn);
		ber_memfree(hdn);
	}

	esc_uri = escape_dn_commas(dn_uri);
	if (!esc_uri) {
		error(logopt, "Could not escape commas in uri %s", dn_uri);
		free(dn_uri);
		return NULL;
	}

	ret = ldap_url_parse(esc_uri, &ludlist);
	if (ret != LDAP_URL_SUCCESS) {
		error(logopt, "Could not parse uri %s (%d)", dn_uri, ret);
		free(esc_uri);
		free(dn_uri);
		return NULL;
	}

	free(esc_uri);

	if (!ludlist) {
		error(logopt, "No dn found in uri %s", dn_uri);
		free(dn_uri);
		return NULL;
	}

	free(dn_uri);

	dclist = malloc(sizeof(struct dclist));
	if (!dclist) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(logopt, "malloc: %s", estr);
		ldap_free_urldesc(ludlist);
		return NULL;
	}
	memset(dclist, 0, sizeof(struct dclist));

	list = NULL;
	for (ludp = &ludlist; *ludp != NULL;) {
		LDAPURLDesc *lud = *ludp;
		struct srv_rr *dcs = NULL;
		unsigned int numdcs = 0;
		size_t req_len, len;
		char *request = NULL;
		char *tmp;
		int i;

		if (!lud->lud_dn && !lud->lud_dn[0] &&
		   (!lud->lud_host || !lud->lud_host[0])) {
			*ludp = lud->lud_next;
			continue;
		}

		domain = NULL;
		if (ldap_dn2domain(lud->lud_dn, &domain) || domain == NULL) {
			error(logopt,
			      "Could not turn dn \"%s\" into a domain",
			      lud->lud_dn);
			*ludp = lud->lud_next;
			continue;
		}

		debug(logopt, "doing lookup of SRV RRs for domain %s", domain);

		req_len = sizeof("_ldap._tcp.") + strlen(domain);
		request = malloc(req_len);
		if (!request) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, "malloc: %s", estr);
			goto out_error;
		}

		ret = snprintf(request, req_len, "_ldap._tcp.%s", domain);
		if (ret >= req_len) {
			free(request);
			goto out_error;
		}

		dclist_mutex_lock();
		ret = get_srv_rrs(logopt, request, &dcs, &numdcs);
		if (!ret | !dcs) {
			error(logopt,
			      "DNS SRV query failed for domain %s", domain);
			dclist_mutex_unlock();
			free(request);
			goto out_error;
		}
		dclist_mutex_unlock();
		free(request);

		len = strlen(lud->lud_scheme);
		len += sizeof("://");
		len *= numdcs;

		for (i = 0; i < numdcs; i++) {
			if (dcs[i].ttl > 0 && dcs[i].ttl < min_ttl)
				min_ttl = dcs[i].ttl;
			len += strlen(dcs[i].name);
			if (dcs[i].port > 0)
				len += sizeof(":65535");
		}

		tmp = realloc(list, len);
		if (!tmp) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, "realloc: %s", estr);
			free_srv_rrs(dcs, numdcs);
			goto out_error;
		}

		if (!list)
			memset(tmp, 0, len);
		else
			strcat(tmp, " ");

		list = NULL;
		for (i = 0; i < numdcs; i++) {
			if (i > 0)
				strcat(tmp, " ");
			strcat(tmp, lud->lud_scheme);
			strcat(tmp, "://");
			strcat(tmp, dcs[i].name);
			if (dcs[i].port > 0) {
				char port[7];
				ret = snprintf(port, 7, ":%d", dcs[i].port);
				if (ret > 6) {
					error(logopt,
					      "invalid port: %u", dcs[i].port);
					free_srv_rrs(dcs, numdcs);
					free(tmp);
					goto out_error;
				}
				strcat(tmp, port);
			}
		}
		list = tmp;

		*ludp = lud->lud_next;
		ber_memfree(domain);
		free_srv_rrs(dcs, numdcs);
	}

	ldap_free_urldesc(ludlist);

	if (!list)
		goto out_error;

	dclist->expire = time(NULL) + min_ttl;
	dclist->uri = list;

	return dclist;

out_error:
	if (list)
		free(list);
	if (domain)
		ber_memfree(domain);
	ldap_free_urldesc(ludlist);
	free_dclist(dclist);
	return NULL;
}
