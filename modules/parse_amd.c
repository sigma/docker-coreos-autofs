/* ----------------------------------------------------------------------- *
 *
 *  Copyright 2013 Ian Kent <raven@themaw.net>
 *  Copyright 2013 Red Hat, Inc.
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *  USA; either version 2 of the License, or (at your option) any later
 *  version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <malloc.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <sys/mount.h>
#include <linux/fs.h>

#define MODULE_PARSE
#include "automount.h"

#define MODPREFIX "parse(amd): "

int parse_version = AUTOFS_PARSE_VERSION;	/* Required by protocol */

static struct mount_mod *mount_nfs = NULL;
static int init_ctr = 0;
static pthread_mutex_t instance_mutex = PTHREAD_MUTEX_INITIALIZER;

static void instance_mutex_lock(void)
{
	int status = pthread_mutex_lock(&instance_mutex);
	if (status)
		fatal(status);
}

static void instance_mutex_unlock(void)
{
	int status = pthread_mutex_unlock(&instance_mutex);
	if (status)
		fatal(status);
}

extern const char *global_options;

struct parse_context {
	char *optstr;		/* Mount options */
	char *macros;		/* Map wide macro defines */
	struct substvar *subst;	/* $-substitutions */
};

struct multi_mnt {
	char *path;
	char *options;
	char *location;
	struct multi_mnt *next;
};

/* Default context */

static struct parse_context default_context = {
	NULL,			/* No mount options */
	NULL,			/* No map wide macros */
	NULL			/* The substvar local vars table */
};

/* Free all storage associated with this context */
static void kill_context(struct parse_context *ctxt)
{
	macro_lock();
	macro_free_table(ctxt->subst);
	macro_unlock();
	if (ctxt->optstr)
		free(ctxt->optstr);
	if (ctxt->macros)
		free(ctxt->macros);
	free(ctxt);
}

int parse_init(int argc, const char *const *argv, void **context)
{
	struct parse_context *ctxt;
	char buf[MAX_ERR_BUF];

	sel_hash_init();

	/* Set up context and escape chain */

	if (!(ctxt = (struct parse_context *) malloc(sizeof(struct parse_context)))) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		*context = NULL;
		return 1;
	}
	*context = (void *) ctxt;

	*ctxt = default_context;

	/* We only need this once.  NFS mounts are so common that we cache
	   this module. */
	instance_mutex_lock();
	if (mount_nfs)
		init_ctr++;
	else {
		if ((mount_nfs = open_mount("nfs", MODPREFIX))) {
			init_ctr++;
		} else {
			kill_context(ctxt);
			*context = NULL;
			instance_mutex_unlock();
			return 1;
		}
	}
	instance_mutex_unlock();

	return 0;
}

static struct substvar *add_lookup_vars(struct autofs_point *ap,
					const char *key, int key_len,
					struct map_source *source,
					struct substvar *sv)
{
	struct substvar *list = sv;
	struct thread_stdenv_vars *tsv;
	char lkp_key[PATH_MAX + 1];
	char path[PATH_MAX + 1];
	struct mapent *me;
	int len;

	len = strlen(ap->path) + 1 + key_len + 1;
	if (len > PATH_MAX) {
		error(ap->logopt, MODPREFIX
		      "error: lookup key is greater than PATH_MAX");
		return NULL;
	}

	if (ap->pref) {
		if (snprintf(lkp_key, sizeof(lkp_key), "%s%s",
			     ap->pref, key) >= sizeof(lkp_key)) {
			error(ap->logopt, MODPREFIX "key too long");
			return NULL;
		}
	} else {
		if (snprintf(lkp_key, sizeof(lkp_key), "%s",
			     key) >= sizeof(lkp_key)) {
			error(ap->logopt, MODPREFIX "key too long");
			return NULL;
		}
	}

	if (*key == '/')
		strcpy(path, key);
	else {
		strcpy(path, ap->path);
		strcat(path, "/");
		strcat(path, key);
	}
	list = macro_addvar(list, "path", 4, path);

	me = cache_lookup_distinct(source->mc, lkp_key);
	if (me)
		list = macro_addvar(list, "key", 3, me->key);

	while (!me) {
		char match[PATH_MAX + 1];
		char *prefix;

		strcpy(match, lkp_key);
		while ((prefix = strrchr(match, '/'))) {
			*prefix = '\0';
			me = cache_partial_match_wild(source->mc, match);
			if (me) {
				list = macro_addvar(list, "key", 3, lkp_key);
				break;
			}
		}

		if (!me) {
			me = cache_lookup_distinct(source->mc, "*");
			if (me)
				list = macro_addvar(list, "key", 3, lkp_key);
		}

		break;
	}

	if (source->name)
		list = macro_addvar(list, "map", 3, source->name);
	else if (source->argv[0][0])
		list = macro_addvar(list, "map", 3, source->argv[0]);

	tsv = pthread_getspecific(key_thread_stdenv_vars);
	if (tsv) {
		char numbuf[16];
		long num;
		int ret;

		num = (long) tsv->uid;
		ret = sprintf(numbuf, "%ld", num);
		if (ret > 0)
			list = macro_addvar(list, "uid", 3, numbuf);
		num = (long) tsv->gid;
		ret = sprintf(numbuf, "%ld", num);
		if (ret > 0)
			list = macro_addvar(list, "gid", 3, numbuf);
	}

	list = macro_addvar(list, "fs", 2, "${autodir}/${rhost}${rfs}");
	list = macro_addvar(list, "rfs", 3, path);

	return list;
}

static int match_my_name(unsigned int logopt, const char *name, struct substvar *sv)
{
	struct addrinfo hints, *cni, *ni, *haddr;
	char host[NI_MAXHOST + 1], numeric[NI_MAXHOST + 1];
	const struct substvar *v;
	int rv = 0, ret;

	v = macro_findvar(sv, "host", 4);
	if (v) {
		if (!strcmp(v->val, name))
			return 1;
	}

	if (!v || !v->val) {
		error(logopt, "error: ${host} not set");
		goto out;
	}

	/* Check if comparison value is an alias */

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	/* Get host canonical name */
	ret = getaddrinfo(v->val, NULL, &hints, &cni);
	if (ret) {
		error(logopt,
		      "hostname lookup failed: %s\n", gai_strerror(ret));
		goto out;
	}

	hints.ai_flags = 0;

	/* Resolve comparison name to its names and compare */
	ret = getaddrinfo(name, NULL, &hints, &ni);
	if (ret) {
		error(logopt,
		      "hostname lookup failed: %s\n", gai_strerror(ret));
		freeaddrinfo(cni);
		goto out;
	}

	haddr = ni;
	while (haddr) {
		/* Translate the host address into a numeric string form */
		ret = getnameinfo(haddr->ai_addr, haddr->ai_addrlen,
				  numeric, sizeof(numeric), NULL, 0,
				  NI_NUMERICHOST);
		if (ret) {
			error(logopt,
			      "host address info lookup failed: %s\n",
			      gai_strerror(ret));
			freeaddrinfo(cni);
			goto next;
		}

		/* Try to resolve back again to get the canonical name */
		ret = getnameinfo(haddr->ai_addr, haddr->ai_addrlen,
				  host, NI_MAXHOST, NULL, 0, 0);
		if (ret) {
			error(logopt,
			      "host address info lookup failed: %s\n",
			      gai_strerror(ret));
			freeaddrinfo(cni);
			goto next;
		}

		if (!strcmp(host, cni->ai_canonname)) {
			rv = 1;
			break;
		}
next:
		haddr = haddr->ai_next;
	}
	freeaddrinfo(ni);
	freeaddrinfo(cni);
out:
	return rv;
}

static int eval_selector(unsigned int logopt,
			 struct amd_entry *this, struct substvar *sv)
{
	struct selector *s = this->selector;
	const struct substvar *v;
	unsigned int s_type;
	unsigned int v_type;
	struct stat st;
	char *host;
	int res, val, ret = 0;

	s_type = s->sel->flags & SEL_FLAGS_TYPE_MASK;

	switch (s_type) {
	case SEL_FLAG_MACRO:
		v = macro_findvar(sv, s->sel->name, strlen(s->sel->name));
		if (!v) {
			error(logopt, "failed to get selector %s", s->sel->name);
			return 0;
		}

		v_type = s->sel->flags & SEL_FLAGS_VALUE_MASK;

		switch (v_type) {
		case SEL_FLAG_STR:
			res = strcmp(v->val, s->comp.value);
			if (s->compare & SEL_COMP_EQUAL && !res) {
				debug(logopt, MODPREFIX
				      "matched selector %s(%s) == %s",
				      v->def, v->val, s->comp.value);
				ret = 1;
				break;
			} else if (s->compare & SEL_COMP_NOTEQUAL && res) {
				debug(logopt, MODPREFIX
				      "matched selector %s(%s) != %s",
				      v->def, v->val, s->comp.value);
				ret = 1;
				break;
			}

			debug(logopt, MODPREFIX
				      "did not match selector %s(%s) %s %s",
				      v->def, v->val,
				      (s->compare & SEL_COMP_EQUAL ? "==" : "!="),
				      s->comp.value);
			break;

		case SEL_FLAG_NUM:
			if (!*s->comp.value) {
				res = 1;
				val = 0;
			} else {
				res = atoi(v->val);
				val = atoi(s->comp.value);
			}
			if (s->compare & SEL_COMP_EQUAL && res == val) {
				debug(logopt, MODPREFIX
				      "matched selector %s(%s) equal to %s",
				      v->def, v->val, s->comp.value);
				ret = 1;
				break;
			} else if (s->compare & SEL_COMP_NOTEQUAL && res != val) {
				debug(logopt, MODPREFIX
				      "matched selector %s(%s) not equal to %s",
				      v->def, v->val, s->comp.value);
				ret = 1;
				break;
			}

			debug(logopt, MODPREFIX
				      "did not match selector %s(%s) %s %s",
				      v->def, v->val,
				      (s->compare & SEL_COMP_EQUAL ? "==" : "!="),
				      s->comp.value);
			break;

		default:
			break;
		}
		break;

	case SEL_FLAG_FUNC1:
		if (s->sel->selector != SEL_TRUE &&
		    s->sel->selector != SEL_FALSE &&
		    !s->func.arg1) {
			error(logopt, MODPREFIX
			      "expected argument missing for selector %s",
			      s->sel->name);
			break;
		}

		switch (s->sel->selector) {
		case SEL_TRUE:
			ret = 1;
			if (s->compare == SEL_COMP_NOT)
				ret = !ret;
			if (ret)
				debug(logopt, MODPREFIX
				      "matched selector %s(%s)",
				      s->sel->name, s->func.arg1);
			else
				debug(logopt, MODPREFIX
				      "did not match selector %s(%s)",
				      s->sel->name, s->func.arg1);
			break;

		case SEL_FALSE:
			if (s->compare == SEL_COMP_NOT)
				ret = !ret;
			if (ret)
				debug(logopt, MODPREFIX
				      "matched selector %s(%s)",
				      s->sel->name, s->func.arg1);
			else
				debug(logopt, MODPREFIX
				      "did not match selector %s(%s)",
				      s->sel->name, s->func.arg1);
			break;

		case SEL_XHOST:
			ret = match_my_name(logopt, s->func.arg1, sv);
			if (s->compare == SEL_COMP_NOT)
				ret = !ret;
			if (ret)
				debug(logopt, MODPREFIX
				      "matched selector %s(%s) to host name",
				      s->sel->name, s->func.arg1);
			else
				debug(logopt, MODPREFIX
				      "did not match selector %s(%s) to host name",
				      s->sel->name, s->func.arg1);
			break;

		case SEL_EXISTS:
			/* Sould be OK to fail on any error here */
			ret = !lstat(s->func.arg1, &st);
			if (s->compare == SEL_COMP_NOT)
				ret = !ret;
			if (ret)
				debug(logopt, MODPREFIX
				      "matched selector %s(%s)",
				      s->sel->name, s->func.arg1);
			else
				debug(logopt, MODPREFIX
				      "did not match selector %s(%s)",
				      s->sel->name, s->func.arg1);
			break;

		case SEL_IN_NETWORK:
			ret = in_network(s->func.arg1);
			if (s->compare == SEL_COMP_NOT)
				ret = !ret;
			if (ret)
				debug(logopt, MODPREFIX
				      "matched selector %s(%s)",
				      s->sel->name, s->func.arg1);
			else
				debug(logopt, MODPREFIX
				      "did not match selector %s(%s)",
				      s->sel->name, s->func.arg1);
			break;

		default:
			break;
		}
		break;

	case SEL_FLAG_FUNC2:
		if (!s->func.arg1) {
			error(logopt, MODPREFIX
			      "expected argument missing for selector %s",
			      s->sel->name);
			break;
		}

		switch (s->sel->selector) {
		case SEL_NETGRP:
		case SEL_NETGRPD:
			if (s->func.arg2)
				host = s->func.arg2;
			else {
				if (s->sel->selector == SEL_NETGRP)
					v = macro_findvar(sv, "host", 4);
				else
					v = macro_findvar(sv, "hostd", 5);
				if (!v || !*v->val) {
					error(logopt,
					     "failed to get value of ${host}");
					break;
				}
				host = v->val;
			}
			ret = innetgr(s->func.arg1, host, NULL, NULL);
			if (s->compare == SEL_COMP_NOT)
				ret = !ret;
			if (ret) {
				if (!s->func.arg2)
					debug(logopt, MODPREFIX
					      "matched selector %s(%s)",
					      s->sel->name, s->func.arg1);
				else
					debug(logopt, MODPREFIX
					      "matched selector %s(%s,%s)",
					      s->sel->name, s->func.arg1,
					      s->func.arg2);
			} else {
				if (!s->func.arg2)
					debug(logopt, MODPREFIX
					      "did not match selector %s(%s)",
					      s->sel->name, s->func.arg1);
				else
					debug(logopt, MODPREFIX
					      "did not match selector %s(%s,%s)",
					      s->sel->name, s->func.arg1, s->func.arg2);
			}
			break;

		default:
			break;
		}
		break;

	default:
		break;
	}

	return ret;
}

static void update_with_defaults(struct amd_entry *defaults,
				 struct amd_entry *entry,
				 struct substvar *sv)
{
	const struct substvar *v;
	unsigned long fstype = entry->flags & AMD_MOUNT_TYPE_MASK;
	char *tmp;

	if (fstype == AMD_MOUNT_TYPE_NONE) {
		unsigned long deftype = defaults->flags & AMD_MOUNT_TYPE_MASK;
		if (deftype != AMD_MOUNT_TYPE_NONE)
			entry->flags |= (defaults->flags & AMD_MOUNT_TYPE_MASK);
		else {
			entry->flags = AMD_MOUNT_TYPE_NFS;
			tmp = strdup("nfs");
			if (tmp)
				entry->type = tmp;
		}
	}

	if (!entry->type && defaults->type) {
		tmp = strdup(defaults->type);
		if (tmp)
			entry->type = tmp;
	}

	if (!entry->map_type && defaults->map_type) {
		tmp = strdup(defaults->map_type);
		if (tmp)
			entry->map_type = tmp;
	}

	if (!entry->pref && defaults->pref) {
		tmp = strdup(defaults->pref);
		if (tmp)
			entry->pref = tmp;
	}

	if (!entry->fs) {
		if (defaults->fs) {
			tmp = strdup(defaults->fs);
			if (tmp)
				entry->fs = tmp;
		} else {
			v = macro_findvar(sv, "fs", 2);
			if (v)
				entry->fs = strdup(v->val);
		}
	}

	if (!entry->rfs) {
		if (defaults->rfs) {
			tmp = strdup(defaults->rfs);
			if (tmp)
				entry->rfs = tmp;
		} else {
			v = macro_findvar(sv, "rfs", 3);
			if (v)
				entry->rfs = strdup(v->val);
		}
	}

	if (!entry->rhost) {
		if (defaults->rhost) {
			tmp = strdup(defaults->rhost);
			if (tmp)
				entry->rhost = tmp;
		} else {
			v = macro_findvar(sv, "host", 4);
			if (v)
				entry->rhost = strdup(v->val);
		}
	}

	if (!entry->dev && defaults->dev) {
		tmp = strdup(defaults->dev);
		if (tmp)
			entry->dev = tmp;
	}

	if (!entry->opts && defaults->opts) {
		tmp = merge_options(defaults->opts, entry->opts);
		if (tmp)
			entry->opts = tmp;
	}

	if (!entry->addopts && defaults->addopts) {
		tmp = merge_options(defaults->addopts, entry->addopts);
		if (tmp)
			entry->addopts = tmp;
	}

	if (!entry->remopts) {
		if (defaults->remopts) {
			tmp = strdup(defaults->remopts);
			if (tmp)
				entry->remopts = tmp;
		} else {
			v = macro_findvar(sv, "remopts", 7);
			if (v)
				entry->remopts = strdup(v->val);
		}
	}

	return;
}

static char *normalize_hostname(unsigned int logopt, const char *host,
				unsigned int flags, struct substvar *sv)
{
	struct addrinfo hints, *ni;
	char *name;
	int ret;

	if (!(flags & CONF_NORMALIZE_HOSTNAMES))
		name = strdup(host);
	else {
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_CANONNAME;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;

		ret = getaddrinfo(host, NULL, &hints, &ni);
		if (ret) {
			error(logopt, "hostname lookup failed: %s", gai_strerror(ret));
			return NULL;
		}
		name = strdup(ni->ai_canonname);
		freeaddrinfo(ni);
	}

	if (!name)
		return NULL;

	if (flags & CONF_DOMAIN_STRIP) {
		const struct substvar *v = macro_findvar(sv, "hostd", 5);
		if (v) {
			char *d1 = strchr(name, '.');
			if (d1) {
				char *d2 = strchr(v->val, '.');
				if (d2 && !strcmp(d1, d2))
					*d1 = '\0';
			}
		}
	}

	return name;
}

static struct substvar *expand_entry(struct autofs_point *ap,
				     struct amd_entry *entry,
				     unsigned int flags,
				     struct substvar *sv)
{
	unsigned int logopt = ap->logopt;
	char *expand;

	if (entry->rhost && *entry->rhost) {
		char *host = strdup(entry->rhost);
		char *nn;
		if (!host) {
			error(ap->logopt, MODPREFIX
			      "failed to allocate storage for rhost");
			goto next;
		}
		if (expand_selectors(ap, host, &expand, sv)) {
			free(host);
			host = expand;
		}
		nn = normalize_hostname(ap->logopt, host, flags, sv);
		if (!nn)
			sv = macro_addvar(sv, "rhost", 5, host);
		else {
			sv = macro_addvar(sv, "rhost", 5, nn);
			free(host);
			host = nn;
		}
		debug(logopt, MODPREFIX
		      "rhost expand(\"%s\") -> %s", entry->rhost, host);
		free(entry->rhost);
		entry->rhost = host;
	}
next:
	if (entry->sublink) {
		if (expand_selectors(ap, entry->sublink, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "sublink expand(\"%s\") -> %s",
			      entry->sublink, expand);
			free(entry->sublink);
			entry->sublink = expand;
		}
		sv = macro_addvar(sv, "sublink", 7, entry->sublink);
	}

	if (entry->rfs && *entry->rfs) {
		if (expand_selectors(ap, entry->rfs, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "rfs expand(\"%s\") -> %s", entry->rfs, expand);
			free(entry->rfs);
			entry->rfs = expand;
		}
		sv = macro_addvar(sv, "rfs", 3, entry->rfs);
	}

	if (entry->fs && *entry->fs) {
		if (expand_selectors(ap, entry->fs, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "fs expand(\"%s\") -> %s", entry->fs, expand);
			free(entry->fs);
			entry->fs = expand;
		}
		sv = macro_addvar(sv, "fs", 2, entry->fs);
	}

	if (entry->opts && *entry->opts) {
		if (expand_selectors(ap, entry->opts, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "ops expand(\"%s\") -> %s", entry->opts, expand);
			free(entry->opts);
			entry->opts = expand;
		}
		sv = macro_addvar(sv, "opts", 4, entry->opts);
	}

	if (entry->addopts && *entry->addopts) {
		if (expand_selectors(ap, entry->addopts, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "addopts expand(\"%s\") -> %s",
			      entry->addopts, expand);
			free(entry->addopts);
			entry->addopts = expand;
		}
		sv = macro_addvar(sv, "addopts", 7, entry->addopts);
	}

	if (entry->remopts && *entry->remopts) {
		if (expand_selectors(ap, entry->remopts, &expand, sv)) {
			debug(logopt, MODPREFIX
			      "remopts expand(\"%s\") -> %s",
			      entry->remopts, expand);
			free(entry->remopts);
			entry->remopts = expand;
		}
		sv = macro_addvar(sv, "remopts", 7, entry->remopts);
	}

	return sv;
}

static void expand_merge_options(struct autofs_point *ap,
				 struct amd_entry *entry,
				 struct substvar *sv)
{
	char *tmp;

	if (entry->opts && *entry->opts) {
		if (!expand_selectors(ap, entry->opts, &tmp, sv))
			error(ap->logopt, MODPREFIX "failed to expand opts");
		else {
			free(entry->opts);
			entry->opts = tmp;
		}
	}

	if (entry->addopts && *entry->addopts) {
		if (!expand_selectors(ap, entry->addopts, &tmp, sv))
			error(ap->logopt, MODPREFIX "failed to expand addopts");
		else {
			free(entry->addopts);
			entry->addopts = tmp;
		}
	}

	if (entry->remopts && *entry->remopts) {
		if (!expand_selectors(ap, entry->remopts, &tmp, sv))
			error(ap->logopt, MODPREFIX "failed to expand remopts");
		else {
			free(entry->remopts);
			entry->remopts = tmp;
		}
	}

	return;
}

static struct substvar *merge_entry_options(struct autofs_point *ap,
					    struct amd_entry *entry,
				            struct substvar *sv)
{
	char *tmp;

	if (!entry->addopts)
		return sv;

	if (entry->opts && entry->remopts &&
	    !strcmp(entry->opts, entry->remopts)) {
		expand_merge_options(ap, entry, sv);
		tmp = merge_options(entry->opts, entry->addopts);
		if (tmp) {
			info(ap->logopt, MODPREFIX
			     "merge remopts \"%s\" addopts \"%s\" => \"%s\"",
			      entry->opts, entry->addopts, tmp);
			free(entry->opts);
			entry->opts = tmp;
			sv = macro_addvar(sv, "opts", 4, entry->opts);
		}
		if (*entry->opts) {
			tmp = strdup(entry->opts);
			if (tmp) {
				free(entry->remopts);
				entry->remopts = tmp;
				sv = macro_addvar(sv, "remopts", 7, entry->remopts);
			}
		}
		return sv;
	}

	expand_merge_options(ap, entry, sv);

	if (entry->opts && entry->addopts) {
		tmp = merge_options(entry->opts, entry->addopts);
		if (tmp) {
			info(ap->logopt, MODPREFIX
			     "merge opts \"%s\" addopts \"%s\" => \"%s\"",
			      entry->opts, entry->addopts, tmp);
			free(entry->opts);
			entry->opts = tmp;
			sv = macro_addvar(sv, "opts", 4, entry->opts);
		}
	} else if (entry->addopts && *entry->addopts) {
		tmp = strdup(entry->addopts);
		if (tmp) {
			info(ap->logopt, MODPREFIX
			     "opts add addopts \"%s\" => \"%s\"", entry->addopts, tmp);
			entry->opts = tmp;
			sv = macro_addvar(sv, "opts", 4, entry->opts);
		}
	}

	expand_merge_options(ap, entry, sv);

	if (entry->remopts && entry->addopts) {
		tmp = merge_options(entry->remopts, entry->addopts);
		if (tmp) {
			info(ap->logopt, MODPREFIX
			     "merge remopts \"%s\" addopts \"%s\" => \"%s\"",
			      entry->remopts, entry->addopts, tmp);
			free(entry->remopts);
			entry->remopts = tmp;
			sv = macro_addvar(sv, "remopts", 7, entry->remopts);
		}
	} else if (entry->addopts && *entry->addopts) {
		tmp = strdup(entry->addopts);
		if (tmp) {
			info(ap->logopt, MODPREFIX
			     "remopts add addopts \"%s\" => \"%s\"",
			     entry->addopts, tmp);
			entry->remopts = tmp;
			sv = macro_addvar(sv, "remopts", 7, entry->remopts);
		}
	}

	return sv;
}

static int do_auto_mount(struct autofs_point *ap, const char *name,
			 struct amd_entry *entry, unsigned int flags)
{
	char target[PATH_MAX + 1];

	if (!entry->map_type) {
		if (strlen(entry->fs) > PATH_MAX) {
			error(ap->logopt, MODPREFIX
			     "error: fs option length is too long");
			return 0;
		}
		strcpy(target, entry->fs);
	} else {
		if (strlen(entry->fs) +
		    strlen(entry->map_type) + 5 > PATH_MAX) {
			error(ap->logopt, MODPREFIX
			     "error: fs + maptype options length is too long");
			return 0;
		}
		strcpy(target, entry->map_type);
		strcat(target, ",amd:");
		strcat(target, entry->fs);
	}

	return do_mount(ap, ap->path,
			name, strlen(name), target, "autofs", NULL);
}

static int do_link_mount(struct autofs_point *ap, const char *name,
			 struct amd_entry *entry, unsigned int flags)
{
	char target[PATH_MAX + 1];
	const char *opts = (entry->opts && *entry->opts) ? entry->opts : NULL;
	int ret;

	if (entry->sublink) {
		if (strlen(entry->sublink) > PATH_MAX) {
			error(ap->logopt, MODPREFIX
			     "error: sublink option length is too long");
			return 0;
		}
		strcpy(target, entry->sublink);
	} else {
		if (strlen(entry->fs) > PATH_MAX) {
			error(ap->logopt, MODPREFIX
			     "error: fs option length is too long");
			return 0;
		}
		strcpy(target, entry->fs);
	}

	if (!(flags & CONF_AUTOFS_USE_LOFS))
		goto symlink;

	/* For a sublink this might cause an external mount */
	ret = do_mount(ap, ap->path,
		       name, strlen(name), target, "bind", opts);
	if (!ret)
		goto out;

	debug(ap->logopt, MODPREFIX "bind mount failed, symlinking");

symlink:
	ret = do_mount(ap, ap->path,
		       name, strlen(name), target, "bind", "symlink");
	if (!ret)
		goto out;

	error(ap->logopt, MODPREFIX
	      "failed to symlink %s to %s", entry->path, target);

	if (entry->sublink) {
		/* failed to complete sublink mount */
		if (ext_mount_remove(&entry->ext_mount, entry->fs))
			umount_ent(ap, entry->fs);
	}
out:
	return ret;
}

static int do_linkx_mount(struct autofs_point *ap, const char *name,
			  struct amd_entry *entry, unsigned int flags)
{
	struct stat st;
	char *target;

	if (entry->sublink)
		target = entry->sublink;
	else
		target = entry->fs;

	if (lstat(target, &st) < 0)
		return errno;

	return do_link_mount(ap, name, entry, flags);
}

static int do_generic_mount(struct autofs_point *ap, const char *name,
			    struct amd_entry *entry, const char *target,
			    unsigned int flags)
{
	const char *opts = (entry->opts && *entry->opts) ? entry->opts : NULL;
	unsigned int umount = 0;
	int ret = 0;

	if (!entry->fs) {
		ret = do_mount(ap, ap->path, name,
			       strlen(name), target, entry->type, opts);
	} else {
		/*
		 * Careful, external mounts may get mounted
		 * multiple times since they are outside of
		 * the automount filesystem.
		 */
		if (!is_mounted(_PATH_MOUNTED, entry->fs, MNTS_REAL)) {
			ret = do_mount(ap, entry->fs, "/", 1,
				       target, entry->type, opts);
			if (ret)
				goto out;
			umount = 1;
		}
		/* We have an external mount */
		ext_mount_add(&entry->ext_mount, entry->fs, umount);
		ret = do_link_mount(ap, name, entry, flags);
	}
out:
	return ret;
}

static int do_nfs_mount(struct autofs_point *ap, const char *name,
			struct amd_entry *entry, unsigned int flags)
{
	char target[PATH_MAX + 1];
	unsigned int proximity;
	char *opts = (entry->opts && *entry->opts) ? entry->opts : NULL;
	unsigned int umount = 0;
	int ret = 0;

	if (strlen(entry->rhost) + strlen(entry->rfs) + 1 > PATH_MAX) {
		error(ap->logopt, MODPREFIX
		     "error: rhost + rfs options length is too long");
		return 0;
	}

	strcpy(target, entry->rhost);
	strcat(target, ":");
	strcat(target, entry->rfs);

	proximity = get_network_proximity(entry->rhost);
	if (proximity == PROXIMITY_OTHER && entry->remopts && *entry->remopts)
		opts = entry->remopts;

	if (!entry->fs) {
		ret = mount_nfs->mount_mount(ap, ap->path, name, strlen(name),
					     target, entry->type, opts,
					     mount_nfs->context);
	} else {
		if (!is_mounted(_PATH_MOUNTED, entry->fs, MNTS_REAL)) {
			ret = mount_nfs->mount_mount(ap, entry->fs, "/", 1,
						target, entry->type, opts,
						mount_nfs->context);
			if (ret)
				goto out;
			umount = 1;
		}
		/* We might be using an external mount */
		ext_mount_add(&entry->ext_mount, entry->fs, umount);
		ret = do_link_mount(ap, name, entry, flags);
	}
out:
	return ret;
}

static int do_nfsl_mount(struct autofs_point *ap, const char *name,
			 struct amd_entry *entry, struct substvar *sv,
			 unsigned int flags)
{
	const struct substvar *host, *hostd;
	struct stat st;
	char *target;

	host = macro_findvar(sv, "host", 4);
	if (!host)
		return do_nfs_mount(ap, name, entry, flags);
	hostd = macro_findvar(sv, "hostd", 5);
	if (!hostd || !*hostd->val)
		return do_nfs_mount(ap, name, entry, flags);

	if (entry->sublink)
		target = entry->sublink;
	else
		target = entry->fs;

	if (strcasecmp(host->val, entry->rhost) ||
	    strcasecmp(hostd->val, entry->rhost))
		return do_nfs_mount(ap, name, entry, flags);
	else if (lstat(target, &st) < 0)
		return do_nfs_mount(ap, name, entry, flags);

	return do_link_mount(ap, name, entry, flags);
}

static int wait_for_expire(struct autofs_point *ap)
{
	int ret = 0;

	st_wait_task(ap, ST_EXPIRE, 0);

	st_mutex_lock();
	if (ap->state != ST_SHUTDOWN &&
	    ap->state != ST_SHUTDOWN_PENDING &&
	    ap->state != ST_SHUTDOWN_FORCE) {
		ret = 1;
	}
	st_mutex_unlock();

	return ret;
}

static int do_host_mount(struct autofs_point *ap, const char *name,
			 struct amd_entry *entry, struct map_source *source,
			 unsigned int flags)
{
	struct lookup_mod *lookup;
	struct map_source *instance;
	struct mapent *me;
	const char *argv[2];
	const char **pargv = NULL;
	int argc = 0;
	int ret = 1;

	/*
	 * If the mount point name isn't the same as the host name
	 * then we need to symlink to it after the mount. Attempt
	 * the allocation and set entry->path to the base location
	 * of the hosts mount tree so we can find it in
	 * lookup_nss_mount() later.
	 */
	if (strcmp(name, entry->rhost)) {
		char *target;
		size_t len = strlen(ap->path) + strlen(entry->rhost) + 2;
		target = malloc(len);
		if (!target) {
			warn(ap->logopt, MODPREFIX
			     "failed to alloc target to hosts mount base");
			goto out;
		}
		strcpy(target, ap->path);
		strcat(target, "/");
		strcat(target, entry->rhost);
		if (entry->path)
			free(entry->path);
		entry->path = target;
		/*
		 * Wait for any expire before racing to mount the
		 * export tree or bail out if we're shutting down.
		*/
		if (!wait_for_expire(ap))
			goto out;
	}

	if (entry->opts && *entry->opts) {
		argv[0] = entry->opts;
		argv[1] = NULL;
		pargv = argv;
		argc = 1;
	}

	instance_mutex_lock();
	lookup = open_lookup("hosts", MODPREFIX, NULL, argc, pargv);
	if (!lookup) {
		debug(ap->logopt, "open lookup module hosts failed");
		instance_mutex_unlock();
		goto out;
	}

	instance = master_find_source_instance(source,
					 "hosts", "sun", argc, pargv);
	if (!instance) {
		instance = master_add_source_instance(source,
				 "hosts", "sun", time(NULL), argc, pargv);
		if (!instance) {
			error(ap->logopt, MODPREFIX
			     "failed to create source instance for hosts map");
			instance_mutex_unlock();
			close_lookup(lookup);
			goto out;
		}
	}
	instance->lookup = lookup;
	instance_mutex_unlock();

	cache_writelock(source->mc);
	me = cache_lookup_distinct(source->mc, name);
	if (me)
		cache_push_mapent(me, NULL);
	cache_unlock(source->mc);

	master_source_current_wait(ap->entry);
	ap->entry->current = source;

	ret = lookup->lookup_mount(ap, entry->rhost,
				   strlen(entry->rhost), lookup->context);

	if (!strcmp(name, entry->rhost))
		goto out;

	if (do_mount(ap, ap->path,
		     name, strlen(name), entry->path, "bind", "symlink"))
		warn(ap->logopt, MODPREFIX
		     "failed to create symlink to hosts mount base");
out:
	return ret;
}

static unsigned int validate_auto_options(unsigned int logopt,
					  struct amd_entry *entry)
{
	/*
	 * The amd manual implies all the mount type auto options
	 * are optional but I don't think there's much point if
	 * no map is given. If the option has been intentionally
	 * left blank the mount must be expected to fail so don't
	 * report the error.
	 */
	if (!entry->fs) {
		error(logopt, MODPREFIX
		      "%s: file system not given", entry->type);
		return 0;
	} else if (!*entry->fs)
		return 0;
	return 1;
}

static unsigned int validate_link_options(unsigned int logopt,
					  struct amd_entry *entry)
{
	/* fs is the destimation of the link */
	return validate_auto_options(logopt, entry);
}

static unsigned int validate_nfs_options(unsigned int logopt,
					 struct amd_entry *entry)
{
	/*
	 * Required option rhost will always have a value unless
	 * it has been intentionally left blank. It is set from
	 * ${host} if it is found to be NULL earlier in the parsing
	 * process. Don't report the error if it has been left blank
	 * or if the fs option has been left blank since the mount is
	 * expected to fail.
	 */
	if (!entry->rfs || !*entry->rfs) {
		if (entry->rfs && !*entry->rfs)
			return 0;
		/* Map option fs has been intentionally left blank */
		if (entry->fs && !*entry->fs)
			return 0;
		entry->rfs = strdup(entry->fs);
		if (!entry->rfs) {
			error(logopt, MODPREFIX
			      "%s: remote file system not given", entry->type);
			return 0;
		}
	}
	if (entry->sublink && !entry->fs) {
		error(logopt, MODPREFIX
		      "%s: sublink option requires option fs");
		return 0;
	}
	return 1;
}

static unsigned int validate_generic_options(unsigned int logopt,
					     unsigned long fstype,
					     struct amd_entry *entry)
{
	/*
	 * If dev or rfs are empty in the map entry the mount is
	 * expected to fail so don't report the error.
	 */
	if (fstype != AMD_MOUNT_TYPE_LOFS) {
		if (!entry->dev) {
			error(logopt, MODPREFIX
			      "%s: mount device not given", entry->type);
			return 0;
		} else if (!*entry->dev)
			return 0;
	} else {
		if (!entry->rfs) {
			/*
			 * Can't use entry->type as the mount type to reprot
			 * the error since entry->type == "bind" not "lofs".
			 */
			error(logopt, "lofs: mount device not given");
			return 0;
		} else if (!*entry->rfs)
			return 0;
	}
	if (entry->sublink && !entry->fs) {
		error(logopt, MODPREFIX
		      "%s: sublink option requires option fs");
		return 0;
	}
	return 1;
}

static unsigned int validate_ufs_fstype(unsigned int logopt,
					struct amd_entry *entry)
{
	const char *type = (const char *) entry->type;

	if (strcmp(type, "ext") && strcmp(type, "ext2") &&
	    strcmp(type, "ext3") && strcmp(type, "ext4") &&
	    strcmp(type, "xfs") && strcmp(type, "jfs")) {
		error(logopt, MODPREFIX
		      "%s: mount type %s not valid as ufs mount type on Linux",
		      type);
		return 0;
	}
	return 1;
}

static unsigned int validate_host_options(unsigned int logopt,
					  struct amd_entry *entry)
{
	/*
	 * rhost is always non-null, unless it is intentionally left
	 * empty, because it will have the the value of the host name
	 * if it isn't given in the map entry. Don't report an error
	 * if it has been left empty since it's expected to fail.
	 */
	if (!entry->rhost) {
		error(logopt, MODPREFIX
		      "%s: remote host name not given", entry->type);
		return 0;
	} else if (!*entry->rhost)
		return 0;
	return 1;
}

static int amd_mount(struct autofs_point *ap, const char *name,
		     struct amd_entry *entry, struct map_source *source,
		     struct substvar *sv, unsigned int flags,
		     struct parse_context *ctxt)
{
	unsigned long fstype = entry->flags & AMD_MOUNT_TYPE_MASK;
	int ret = 1;

	switch (fstype) {
	case AMD_MOUNT_TYPE_AUTO:
		if (!validate_auto_options(ap->logopt, entry))
			return 1;
		ret = do_auto_mount(ap, name, entry, flags);
		break;

	case AMD_MOUNT_TYPE_LOFS:
		if (!validate_generic_options(ap->logopt, fstype, entry))
			return 1;
		ret = do_generic_mount(ap, name, entry, entry->rfs, flags);
		break;

	case AMD_MOUNT_TYPE_UFS:
		if (!validate_ufs_fstype(ap->logopt, entry))
			return 1;
		/* fall through to validate generic options */

	case AMD_MOUNT_TYPE_EXT:
	case AMD_MOUNT_TYPE_XFS:
	case AMD_MOUNT_TYPE_CDFS:
		if (!validate_generic_options(ap->logopt, fstype, entry))
			return 1;
		ret = do_generic_mount(ap, name, entry, entry->dev, flags);
		break;

	case AMD_MOUNT_TYPE_NFS:
		if (!validate_nfs_options(ap->logopt, entry))
			return 1;
		ret = do_nfs_mount(ap, name, entry, flags);
		break;

	case AMD_MOUNT_TYPE_NFSL:
		if (!validate_nfs_options(ap->logopt, entry) ||
		    !validate_link_options(ap->logopt, entry))
			return 1;
		ret = do_nfsl_mount(ap, name, entry, sv, flags);
		break;

	case AMD_MOUNT_TYPE_LINK:
		if (!validate_link_options(ap->logopt, entry))
			return 1;
		ret = do_link_mount(ap, name, entry, flags);
		break;

	case AMD_MOUNT_TYPE_LINKX:
		if (!validate_link_options(ap->logopt, entry))
			return 1;
		ret = do_linkx_mount(ap, name, entry, flags);
		break;

	case AMD_MOUNT_TYPE_HOST:
		if (!validate_host_options(ap->logopt, entry))
			return 1;
		ret = do_host_mount(ap, name, entry, source, flags);
		break;

	default:
		info(ap->logopt,
		     MODPREFIX "unknown file system type %x", fstype);
		break;
	}

	return ret;
}

void dequote_entry(struct autofs_point *ap, struct amd_entry *entry)
{
	char *res;

	if (entry->pref) {
		res = dequote(entry->pref, strlen(entry->pref), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "pref dequote(\"%.*s\") -> %s",
			      strlen(entry->pref), entry->pref, res);
			free(entry->pref);
			entry->pref = res;
		}
	}

	if (entry->sublink) {
		res = dequote(entry->sublink, strlen(entry->sublink), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "sublink dequote(\"%.*s\") -> %s",
			      strlen(entry->sublink), entry->sublink, res);
			free(entry->sublink);
			entry->sublink = res;
		}
	}

	if (entry->fs && *entry->fs) {
		res = dequote(entry->fs, strlen(entry->fs), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "fs dequote(\"%.*s\") -> %s",
			      strlen(entry->fs), entry->fs, res);
			free(entry->fs);
			entry->fs = res;
		}
	}

	if (entry->rfs && *entry->rfs) {
		res = dequote(entry->rfs, strlen(entry->rfs), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "rfs dequote(\"%.*s\") -> %s",
			      strlen(entry->rfs), entry->rfs, res);
			free(entry->rfs);
			entry->rfs = res;
		}
	}

	if (entry->opts && *entry->opts) {
		res = dequote(entry->opts, strlen(entry->opts), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "ops dequote(\"%.*s\") -> %s",
			      strlen(entry->opts), entry->opts, res);
			free(entry->opts);
			entry->opts = res;
		}
	}

	if (entry->remopts && *entry->remopts) {
		res = dequote(entry->remopts, strlen(entry->remopts), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "remopts dequote(\"%.*s\") -> %s",
			      strlen(entry->remopts), entry->remopts, res);
			free(entry->remopts);
			entry->remopts = res;
		}
	}

	if (entry->addopts && *entry->addopts) {
		res = dequote(entry->addopts, strlen(entry->addopts), ap->logopt);
		if (res) {
			debug(ap->logopt,
			      MODPREFIX "addopts dequote(\"%.*s\") -> %s",
			      strlen(entry->addopts), entry->addopts, res);
			free(entry->addopts);
			entry->addopts = res;
		}
	}

	return;
}

static void normalize_sublink(unsigned int logopt,
			      struct amd_entry *entry, struct substvar *sv)
{
	char *new;
	size_t len;

	/* Normalizing sublink requires a non-blank fs option */
	if (!*entry->fs)
		return;

	if (entry->sublink && *entry->sublink != '/') {
		len = strlen(entry->fs) + strlen(entry->sublink) + 2;
		new = malloc(len);
		if (!new) {
			error(logopt, MODPREFIX
			      "error: couldn't allocate storage for sublink");
			return;
		}
		strcpy(new, entry->fs);
		strcat(new, "/");
		strcat(new, entry->sublink);
		debug(logopt, MODPREFIX
		      "rfs dequote(\"%.*s\") -> %s",
		      strlen(entry->sublink), entry->sublink, new);
		free(entry->sublink);
		entry->sublink = new;
	}
	return;
}

/*
 * Set the prefix.
 *
 * This is done in a couple of places, here is as good a place as
 * any to describe it.
 *
 * If a prefix is present in the map entry then use it.
 *
 * A pref option with the value none is required to use no prefix,
 * otherwise the prefix of the parent map, if any, will be used.
 */
static void update_prefix(struct autofs_point *ap,
			  struct amd_entry *entry, const char *name)
{
	size_t len;
	char *new;

	if (!entry->pref && ap->pref) {
		len = strlen(ap->pref) + strlen(name) + 2;
		new = malloc(len);
		if (new) {
			strcpy(new, ap->pref);
			strcat(new, name);
			strcat(new, "/");
			entry->pref = new;
		}
	}
	return;
}

static int match_selectors(unsigned int logopt,
			   struct amd_entry *entry, struct substvar *sv)
{
	struct selector *s = entry->selector;
	int ret;

	/* No selectors, always match */
	if (!s) {
		debug(logopt, "no selectors found in location");
		return 1;
	}

	ret = 0;

	/* All selectors must match */
	while (s) {
		ret = eval_selector(logopt, entry, sv);
		if (!ret)
			break;
		s = s->next;
	}
	if (!s)
		ret = 1;

	return ret;
}

static struct amd_entry *dup_defaults_entry(struct amd_entry *defaults)
{
	struct amd_entry *entry;
	char *tmp;

	entry = malloc(sizeof(struct amd_entry));
	if (!entry)
		return NULL;
	memset(entry, 0, sizeof(struct amd_entry));

	entry->flags = defaults->flags;

	if (defaults->type) {
		tmp = strdup(defaults->type);
		if (tmp)
			entry->type = tmp;
	}

	if (defaults->map_type) {
		tmp = strdup(defaults->map_type);
		if (tmp)
			entry->map_type = tmp;
	}

	if (defaults->pref) {
		tmp = strdup(defaults->pref);
		if (tmp)
			entry->pref = tmp;
	}

	if (defaults->fs) {
		tmp = strdup(defaults->fs);
		if (tmp)
			entry->fs = tmp;
	}

	/* These shouldn't be blank in a defaults entry but ... */

	if (defaults->rfs && *defaults->rfs) {
		tmp = strdup(defaults->rfs);
		if (tmp)
			entry->rfs = tmp;
	}

	if (defaults->rhost && *defaults->rhost) {
		tmp = strdup(defaults->rhost);
		if (tmp)
			entry->rhost = tmp;
	}

	if (defaults->dev && *defaults->dev) {
		tmp = strdup(defaults->dev);
		if (tmp)
			entry->dev = tmp;
	}

	if (defaults->opts && *defaults->opts) {
		tmp = strdup(defaults->opts);
		if (tmp)
			entry->opts = tmp;
	}

	if (defaults->addopts && *defaults->addopts) {
		tmp = strdup(defaults->addopts);
		if (tmp)
			entry->addopts = tmp;
	}

	if (defaults->remopts && *defaults->remopts) {
		tmp = strdup(defaults->remopts);
		if (tmp)
			entry->remopts = tmp;
	}

	INIT_LIST_HEAD(&entry->list);

	return entry;
}

struct amd_entry *make_default_entry(struct autofs_point *ap,
				     struct substvar *sv)
{
	char *defaults = "opts:=rw,defaults";
	struct amd_entry *defaults_entry;
	struct list_head dflts;
	char *map_type;

	INIT_LIST_HEAD(&dflts);
	if (amd_parse_list(ap, defaults, &dflts, &sv))
		return NULL;
	defaults_entry = list_entry(dflts.next, struct amd_entry, list);
	list_del_init(&defaults_entry->list);
	/*
	 * If map type isn't given try to inherit from
	 * parent. A NULL map type is valid and means
	 * use configured nss sources.
	 */
	map_type = conf_amd_get_map_type(ap->path);
	if (map_type)
		defaults_entry->map_type = strdup(map_type);
	/* The list should now be empty .... */
	free_amd_entry_list(&dflts);
	return defaults_entry;
}

static struct amd_entry *select_default_entry(struct autofs_point *ap,
					      struct list_head *entries,
					      struct substvar *sv)
{
	unsigned long flags = conf_amd_get_flags(ap->path);
	struct amd_entry *defaults_entry = NULL;
	struct amd_entry *entry_default = NULL;
	struct list_head *p, *head;

	if (!(flags & CONF_SELECTORS_IN_DEFAULTS))
		goto no_sel;

	head = entries;
	p = head->next;
	while (p != head) {
		struct amd_entry *this = list_entry(p, struct amd_entry, list);

		p = p->next;

		if (this->flags & AMD_DEFAULTS_MERGE) {
			if (entry_default)
				free_amd_entry(entry_default);
			list_del_init(&this->list);
			entry_default = this;
			continue;
		} else if (this->flags & AMD_DEFAULTS_RESET) {
			struct amd_entry *new;
			new = dup_defaults_entry(defaults_entry);
			if (new) {
				free_amd_entry(entry_default);
				entry_default = new;
			}
			list_del_init(&this->list);
			free_amd_entry(this);
			continue;
		}

		/*
		 * This probably should be a fail since we expect
		 * selectors to pick the default entry.
		 */
		if (!this->selector)
			continue;

		if (match_selectors(ap->logopt, this, sv)) {
			if (entry_default) {
				/*update_with_defaults(entry_default, this, sv);*/
				free_amd_entry(entry_default);
			}
			list_del_init(&this->list);
			defaults_entry = this;
			break;
		}
	}

	/* Not strickly amd semantics but ... */
	if (!defaults_entry && entry_default) {
		defaults_entry = entry_default;
		goto done;
	}

	if (!defaults_entry) {
		debug(ap->logopt, MODPREFIX
		      "no matching selector(s) found in defaults, "
		      "using internal defaults");
		goto ret_default;
	}

	goto done;

no_sel:
	if (list_empty(entries))
		goto ret_default;

	defaults_entry = list_entry(entries->next, struct amd_entry, list);
	list_del_init(&defaults_entry->list);
	if (!list_empty(entries)) {
		free_amd_entry(defaults_entry);
		goto ret_default;
	}
done:
	/*merge_entry_options(ap, defaults_entry, sv);*/
	/*normalize_sublink(ap->logopt, defaults_entry, sv);*/
	return defaults_entry;

ret_default:
	return make_default_entry(ap, sv);
}

static struct amd_entry *get_defaults_entry(struct autofs_point *ap,
					    const char *defaults,
					    struct substvar *sv)
{
	struct amd_entry *entry;
	struct list_head dflts;

	INIT_LIST_HEAD(&dflts);

	entry = NULL;
	if (!defaults)
		goto out;
	else {
		char *expand;
		if (!expand_selectors(ap, defaults, &expand, sv))
			goto out;
		if (amd_parse_list(ap, expand, &dflts, &sv)) {
			error(ap->logopt, MODPREFIX
			     "failed to parse defaults entry, "
			     "attempting to use internal default");
			free(expand);
			goto out;
		}
		entry = select_default_entry(ap, &dflts, sv);
		if (!entry->map_type) {
			/*
			 * If map type isn't given try to inherit from
			 * parent. A NULL map type is valid and means
			 * use configured nss sources.
			 */
			char *map_type = conf_amd_get_map_type(ap->path);
			if (map_type)
				entry->map_type = strdup(map_type);
		}
		free(expand);
	}

	return entry;
out:
	return make_default_entry(ap, sv);
}

int parse_mount(struct autofs_point *ap, const char *name,
		int name_len, const char *mapent, void *context)
{
	struct parse_context *ctxt = (struct parse_context *) context;
	unsigned int flags = conf_amd_get_flags(ap->path);
	struct substvar *sv = NULL;
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *me;
	unsigned int at_least_one;
	struct list_head entries, *p, *head;
	struct amd_entry *defaults_entry;
	struct amd_entry *cur_defaults;
	char *defaults;
	char *pmapent;
	int len, rv = 1;
	int cur_state;
	int ret;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	if (!mapent) {
		warn(ap->logopt, MODPREFIX "error: empty map entry");
		return 1;
	}

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);

	sv = add_lookup_vars(ap, name, name_len, source, sv);
	if (!sv) {
		macro_free_table(sv);
		pthread_setcancelstate(cur_state, NULL);
		return 1;
	}

	len = expand_selectors(ap, mapent, &pmapent, sv);
	if (!len) {
		macro_free_table(sv);
		pthread_setcancelstate(cur_state, NULL);
		return 1;
	}

	pthread_setcancelstate(cur_state, NULL);

	debug(ap->logopt, MODPREFIX "expanded mapent: %s", pmapent);

	defaults = conf_amd_get_map_defaults(ap->path);
	if (defaults) {
		debug(ap->logopt, MODPREFIX
		      "using map_defaults %s for %s", defaults, ap->path);
	} else if ((me = cache_lookup_distinct(mc, "/defaults"))) {
		defaults = strdup(me->mapent);
		if (defaults)
			debug(ap->logopt, MODPREFIX
			      "using /defaults %s from map", defaults);
		else {
			char buf[MAX_ERR_BUF];
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, MODPREFIX "malloc: %s", estr);
		}
	}

	defaults_entry = get_defaults_entry(ap, defaults, sv);
	if (!defaults_entry) {
		error(ap->logopt, MODPREFIX "failed to get a defaults entry");
		if (defaults)
			free(defaults);
		free(pmapent);
		macro_free_table(sv);
		return 1;
	}
	if (defaults)
		free(defaults);

	INIT_LIST_HEAD(&entries);

	ret = amd_parse_list(ap, pmapent, &entries, &sv);
	if (ret) {
		error(ap->logopt,
		      MODPREFIX "failed to parse entry: %s", pmapent);
		free(pmapent);
		goto done;
	}

	free(pmapent);

	if (list_empty(&entries)) {
		error(ap->logopt, MODPREFIX "no location found after parse");
		goto done;
	}

	cur_defaults = dup_defaults_entry(defaults_entry);
	if (!cur_defaults) {
		error(ap->logopt, MODPREFIX
		      "failed to duplicate defaults entry");
		goto done;
	}

	at_least_one = 0;
	head = &entries;
	p = head->next;
	while (p != head) {
		struct amd_entry *this = list_entry(p, struct amd_entry, list);
		p = p->next;

		if (this->flags & AMD_DEFAULTS_MERGE) {
			free_amd_entry(cur_defaults);
			list_del_init(&this->list);
			cur_defaults = this;
			continue;
		} else if (this->flags & AMD_DEFAULTS_RESET) {
			struct amd_entry *new;
			new = dup_defaults_entry(defaults_entry);
			if (new) {
				free_amd_entry(cur_defaults);
				cur_defaults = new;
			}
			list_del_init(&this->list);
			free_amd_entry(this);
			continue;
		}

		if (this->flags & AMD_ENTRY_CUT && at_least_one) {
			info(ap->logopt, MODPREFIX
			     "at least one entry tried before cut selector, "
			     "not continuing");
			break;
		}

		if (!match_selectors(ap->logopt, this, sv))
			continue;

		at_least_one = 1;

		update_with_defaults(cur_defaults, this, sv);
		sv = expand_entry(ap, this, flags, sv);
		sv = merge_entry_options(ap, this, sv);
		normalize_sublink(ap->logopt, this, sv);
		update_prefix(ap, this, name);

		dequote_entry(ap, this);

		/*
		 * Type "auto" needs to set the prefix at mount time so
		 * add parsed entry to parent amd mount list and remove
		 * on mount fail.
		 */
		mounts_mutex_lock(ap);
		list_add_tail(&this->entries, &ap->amdmounts);
		mounts_mutex_unlock(ap);

		rv = amd_mount(ap, name, this, source, sv, flags, ctxt);
		mounts_mutex_lock(ap);
		if (!rv) {
			/* Mounted, remove entry from parsed list */
			list_del_init(&this->list);
			mounts_mutex_unlock(ap);
			break;
		}
		/* Not mounted, remove entry from the parent list */
		list_del_init(&this->entries);
		mounts_mutex_unlock(ap);
	}
	free_amd_entry(cur_defaults);

	if (rv)
		debug(ap->logopt, "no more locations to try, returning fail");
done:
	free_amd_entry_list(&entries);
	free_amd_entry(defaults_entry);
	macro_free_table(sv);

	return rv;
}

int parse_done(void *context)
{
	int rv = 0;
	struct parse_context *ctxt = (struct parse_context *) context;

	instance_mutex_lock();
	if (--init_ctr == 0) {
		rv = close_mount(mount_nfs);
		mount_nfs = NULL;
	}
	instance_mutex_unlock();
	if (ctxt)
		kill_context(ctxt);

	return rv;
}
