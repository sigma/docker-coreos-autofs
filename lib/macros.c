/* ----------------------------------------------------------------------- *
 *   
 *  macros.c - module to handle macro substitution variables for map
 *		entries.
 * 
 *   Copyright 2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "automount.h"

static struct utsname un;
static char processor[65];		/* Not defined on Linux, so we make our own */
static char hostname[HOST_NAME_MAX + 1];
static char host[HOST_NAME_MAX];
static char domain[HOST_NAME_MAX];
static char hostd[HOST_NAME_MAX + 1];
static char endian[] = "unknown";

/* Predefined variables: tail of link chain */
static struct substvar
	sv_arch   = {"ARCH",   un.machine,  1, NULL },
	sv_cpu    = {"CPU",    processor,   1, &sv_arch},
	sv_host   = {"HOST",   un.nodename, 1, &sv_cpu},
	sv_osname = {"OSNAME", un.sysname,  1, &sv_host},
	sv_osrel  = {"OSREL",  un.release,  1, &sv_osname},
	sv_osvers = {"OSVERS", un.version,  1, &sv_osrel},
	sv_dollar = {"dollar", "$",         1, &sv_osvers},
	sv_true   = {"true",   "1",         1, &sv_dollar},
	sv_false  = {"false",  "0",         1, &sv_true},
	sv_byte	  = {"byte",   endian,	    1, &sv_false},
	sv_host2  = {"host",   host,        1, &sv_byte},
	sv_xhost  = {"xhost",  host,	    1, &sv_host2},
	sv_domain = {"domain", domain,      1, &sv_xhost},
	sv_hostd  = {"hostd",  hostd,       1, &sv_domain
};

static struct substvar *system_table = &sv_hostd;
static unsigned int macro_init_done = 0;

static pthread_mutex_t table_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t macro_mutex = PTHREAD_MUTEX_INITIALIZER;

void dump_table(struct substvar *table)
{
	struct substvar *lv = table;
	int status;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	while (lv) {
		logmsg("lv->def %s lv->val %s lv->next %p",
		      lv->def, lv->val, lv->next);
		lv = lv->next;
	}

	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);
}

/* Get processor information for predefined macro definitions */
void macro_init(void)
{
	char *local_domain;

	memset(hostname, 0, HOST_NAME_MAX + 1);
	memset(host, 0, HOST_NAME_MAX);
	memset(domain, 0, HOST_NAME_MAX);
	memset(hostd, 0, HOST_NAME_MAX + 1);

	macro_lock();
	if (macro_init_done) {
		macro_unlock();
		return;
	}

	uname(&un);
	/*
	 * uname -p is not defined on Linux.  Make it the same as
	 * uname -m, except make it return i386 on all x86 (x >= 3)
	 */
	strcpy(processor, un.machine);
	if (processor[0] == 'i' && processor[1] >= '3' &&
		!strcmp(processor + 2, "86"))
		processor[1] = '3';

	local_domain = conf_amd_get_sub_domain();

	if (!gethostname(hostname, HOST_NAME_MAX)) {
		char *dot;
		dot = strchr(hostname, '.');
		if (dot) {
			*dot++ = '\0';
			strcpy(domain, dot);
		}
		strcpy(host, hostname);
		strcpy(hostd, host);
		if (*domain || local_domain) {
			strcat(hostd, ".");
			if (!local_domain)
				strcat(hostd, domain);
			else {
				strcat(hostd, local_domain);
				strcpy(domain, local_domain);
			}
		}
	}

	if (sizeof(short) == 2) {
		union { short s; char c[sizeof(short)]; } order;
		order.s = 0x0102;
		if (order.c[0] == 1 && order.c[1] == 2)
			strcpy(endian, "big");
		else if (order.c[0] == 2 && order.c[1] == 1)
			strcpy(endian, "little");
		else
			strcpy(endian, "unknown");
	}

	add_std_amd_vars(system_table);

	macro_init_done = 1;
	macro_unlock();
	return;
}

int macro_is_systemvar(const char *str, int len)
{
	struct substvar *sv;
	int found = 0;
	int status;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	sv = system_table;

	while (sv) {
		if (!strncmp(str, sv->def, len) && sv->def[len] == '\0') {
			found = 1;
			break;
		}
		sv = sv->next;
	}

	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);

	return found;
}

int macro_global_addvar(const char *str, int len, const char *value)
{
	struct substvar *sv;
	int status, ret = 0;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	sv = system_table;

	while (sv) {
		if (!strncmp(str, sv->def, len) && sv->def[len] == '\0')
			break;
		sv = sv->next;
	}

	if (sv && !sv->readonly) {
		char *this = malloc(strlen(value) + 1);
		if (!this)
			goto done;
		strcpy(this, value);
		free(sv->val);
		sv->val = this;
		ret = 1;
	} else {
		struct substvar *new;
		char *def, *val;

		def = strdup(str);
		if (!def)
			goto done;
		def[len] = '\0';

		val = strdup(value);
		if (!val) {
			free(def);
			goto done;
		}

		new = malloc(sizeof(struct substvar));
		if (!new) {
			free(def);
			free(val);
			goto done;
		}
		new->def = def;
		new->val = val;
		new->readonly = 0;
		new->next = system_table;
		system_table = new;
		ret =1;
	}
done:
	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);

	return ret;
}

int macro_parse_globalvar(const char *define)
{
	char buf[MAX_MACRO_STRING];
	char *pbuf, *value;

	if (strlen(define) >= MAX_MACRO_STRING)
		return 0;

	strcpy(buf, define);

	pbuf = buf;
	while (pbuf) {
		if (*pbuf == '=') {
			*pbuf = '\0';
			value = pbuf + 1;
			break;
		}
		pbuf++;
	}

	/* Macro must have value */
	if (!pbuf)
		return 0;

	return macro_global_addvar(buf, strlen(buf), value);
}

void macro_lock(void)
{
	int status = pthread_mutex_lock(&macro_mutex);
	if (status)
		fatal(status);
}

void macro_unlock(void)
{
	int status = pthread_mutex_unlock(&macro_mutex);
	if (status)
		fatal(status);
}

struct substvar *
macro_addvar(struct substvar *table, const char *str, int len, const char *value)
{
	struct substvar *lv = table;

	while (lv) {
		if (!strncmp(str, lv->def, len) && lv->def[len] == '\0')
			break;
		lv = lv->next;
	}

	if (lv) {
		char *this = malloc(strlen(value) + 1);
		if (!this) {
			lv = table;
			goto done;
		}
		strcpy(this, value);
		free(lv->val);
		lv->val = this;
		if (lv != table)
			lv = table;
	} else {
		struct substvar *new;
		char *def, *val;

		def = strdup(str);
		if (!def) {
			lv = table;
			goto done;
		}
		def[len] = '\0';

		val = strdup(value);
		if (!val) {
			lv = table;
			free(def);
			goto done;
		}

		new = malloc(sizeof(struct substvar));
		if (!new) {
			lv = table;
			free(def);
			free(val);
			goto done;
		}
		new->def = def;
		new->val = val;
		new->readonly = 0;
		new->next = table;
		lv = new;
	}
done:

	return lv;
}

void macro_global_removevar(const char *str, int len)
{
	struct substvar *sv;
	struct substvar *last = NULL;
	int status;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	sv = system_table;

	while (sv) {
		if (!strncmp(str, sv->def, len) && sv->def[len] == '\0')
			break;
		last = sv;
		sv = sv->next;
	}

	if (sv && !sv->readonly) {
		if (last)
			last->next = sv->next;
		else
			system_table = sv->next;
		if (sv->def)
			free(sv->def);
		if (sv->val)
			free(sv->val);
		free(sv);
	}

	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);

	return;
}

struct substvar *
macro_removevar(struct substvar *table, const char *str, int len)
{
	struct substvar *list, *lv;
	struct substvar *last = NULL;

	lv = list = table;

	while (lv) {
		if (!strncmp(str, lv->def, len) && lv->def[len] == '\0')
			break;
		last = lv;
		lv = lv->next;
	}

	if (lv) {
		if (last)
			last->next = lv->next;
		else
			list = lv->next;
		if (lv->def)
			free(lv->def);
		if (lv->val)
			free(lv->val);
		free(lv);
	}

	return list;
}

void macro_free_global_table(void)
{
	struct substvar *sv;
	struct substvar *next;
	int status;

	status = pthread_mutex_lock(&table_mutex);
	if (status)
		fatal(status);

	sv = system_table;

	while (sv) {
		if (sv->readonly) {
			sv = sv->next;
			continue;
		}
		next = sv->next;
		if (sv->def)
			free(sv->def);
		if (sv->val)
			free(sv->val);
		free(sv);
		sv = next;
	}

	system_table = &sv_osvers;

	status = pthread_mutex_unlock(&table_mutex);
	if (status)
		fatal(status);

	return;
}

void macro_free_table(struct substvar *table)
{
	struct substvar *lv = table;
	struct substvar *next;

	if (!lv)
		return;

	while (lv) {
		next = lv->next;
		if (lv->def)
			free(lv->def);
		if (lv->val)
			free(lv->val);
		free(lv);
		lv = next;
	}

	return;
}

/* Find the $-variable matching a certain string fragment */
const struct substvar *
macro_findvar(const struct substvar *table, const char *str, int len)
{
	const struct substvar *sv = system_table;
	const struct substvar *lv = table;
#ifdef ENABLE_EXT_ENV
	/* holds one env var */
	static struct substvar *lv_var;
	static char *value;
	char etmp[512];
#endif

	/* First try the passed in local table */
	while (lv) {
		if (!strncmp(str, lv->def, len) && lv->def[len] == '\0')
			return lv;
		lv = lv->next;
	}

	/* Then look in the system wide table */
	while (sv) {
		if (!strncmp(str, sv->def, len) && sv->def[len] == '\0')
			return sv;
		sv = sv->next;
	}

#ifdef ENABLE_EXT_ENV
	/* builtin and local map failed, try the $ENV */
	memcpy(etmp, str, len);
	etmp[len]='\0';

	if ((value=getenv(etmp)) != NULL) {
		lv_var = macro_addvar((struct substvar *) table, str, len, value);
		return(lv_var);
	}
#endif

	return NULL;
}

/* Set environment from macro variable table */
void macro_setenv(struct substvar *table)
{
	const struct substvar *sv = system_table;
	const struct substvar *lv = table;

	/*
	 * First set environment from global table, matching local
	 * variables will overwrite these.
	 */
	while (sv) {
		if (sv->def)
			setenv(sv->def, sv->val, 1);
		sv = sv->next;
	}

	/* Next set environment from the local table */
	while (lv) {
		if (lv->def)
			setenv(lv->def, lv->val, 1);
		lv = lv->next;
	}

	return;
}
