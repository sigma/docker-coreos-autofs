/* ----------------------------------------------------------------------- *
 *
 *  lookup_sss.c - module for Linux automount to query sss service
 *
 *   Copyright 2012 Ian Kent <raven@themaw.net>
 *   Copyright 2012 Red Hat, Inc.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(sss): "

#define SSS_SO_NAME "libsss_autofs"

int _sss_setautomntent(const char *, void **);
int _sss_getautomntent_r(char **, char **, void *);
int _sss_getautomntbyname_r(char *, char **, void *);
int _sss_endautomntent(void **);

typedef int (*setautomntent_t) (const char *, void **);
typedef int (*getautomntent_t) (char **, char **, void *);
typedef int (*getautomntbyname_t) (char *, char **, void *);
typedef int (*endautomntent_t) (void **);

struct lookup_context {
	const char *mapname;
    	void *dlhandle;
	setautomntent_t setautomntent;
	getautomntent_t getautomntent_r;
	getautomntbyname_t getautomntbyname_r;
	endautomntent_t endautomntent;
	struct parse_mod *parse;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];
	char dlbuf[PATH_MAX];
	char *estr;
	void *dh;
	size_t size;

	*context = NULL;

	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	if (argc < 1) {
		free(ctxt);
		logerr(MODPREFIX "No map name");
		return 1;
	}
	ctxt->mapname = argv[0];

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	size = snprintf(dlbuf, sizeof(dlbuf),
			"%s/%s.so", SSS_LIB_DIR, SSS_SO_NAME);
	if (size >= sizeof(dlbuf)) {
		free(ctxt);
		logmsg(MODPREFIX "sss library path too long");
		return 1;
	}

	dh = dlopen(dlbuf, RTLD_LAZY);
	if (!dh) {
		logerr(MODPREFIX "failed to open %s: %s", dlbuf, dlerror());
		free(ctxt);
		return 1;
	}
	ctxt->dlhandle = dh;

	ctxt->setautomntent = (setautomntent_t) dlsym(dh, "_sss_setautomntent");
	if (!ctxt->setautomntent)
		goto lib_names_fail;

	ctxt->getautomntent_r = (getautomntent_t) dlsym(dh, "_sss_getautomntent_r");
	if (!ctxt->getautomntent_r)
		goto lib_names_fail;

	ctxt->getautomntbyname_r = (getautomntbyname_t) dlsym(dh, "_sss_getautomntbyname_r");
	if (!ctxt->getautomntbyname_r)
		goto lib_names_fail;

	ctxt->endautomntent = (endautomntent_t) dlsym(dh, "_sss_endautomntent");
	if (!ctxt->setautomntent)
		goto lib_names_fail;

	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
	if (!ctxt->parse) {
		logmsg(MODPREFIX "failed to open parse context");
		dlclose(dh);
		free(ctxt);
		return 1;
	}
	*context = ctxt;

	return 0;

lib_names_fail:
	if ((estr = dlerror()) == NULL)
		logmsg(MODPREFIX "failed to locate sss library entry points");
	else
		logerr(MODPREFIX "dlsym: %s", estr);
	dlclose(dh);
	free(ctxt);
	return 1;
}

static int setautomntent(unsigned int logopt,
			 struct lookup_context *ctxt, const char *mapname,
			 void **sss_ctxt)
{
	int ret = ctxt->setautomntent(mapname, sss_ctxt);
	if (ret) {
		char buf[MAX_ERR_BUF];
		char *estr = strerror_r(ret, buf, MAX_ERR_BUF);
		error(logopt, MODPREFIX "setautomntent: %s", estr);
		if (*sss_ctxt)
			free(*sss_ctxt);
		return 0;
	}
	return 1;
}

static int endautomntent(unsigned int logopt,
			 struct lookup_context *ctxt, void **sss_ctxt)
{
	int ret = ctxt->endautomntent(sss_ctxt);
	if (ret) {
		char buf[MAX_ERR_BUF];
		char *estr = strerror_r(ret, buf, MAX_ERR_BUF);
		error(logopt, MODPREFIX "endautomntent: %s", estr);
		return 0;
	}
	return 1;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	unsigned int timeout = master->default_timeout;
	unsigned int logging = master->default_logging;
	unsigned int logopt = master->logopt;
	void *sss_ctxt = NULL;
	char buf[MAX_ERR_BUF];
	char *buffer;
	size_t buffer_len;
	char *key;
	char *value = NULL;
	int count, ret;

	if (!setautomntent(logopt, ctxt, ctxt->mapname, &sss_ctxt))
		return NSS_STATUS_UNAVAIL;

	count = 0;
	while (1) {
	        key = NULL;
	        value = NULL;
		ret = ctxt->getautomntent_r(&key, &value, sss_ctxt);
		if (ret && ret != ENOENT) {
			char *estr = strerror_r(ret, buf, MAX_ERR_BUF);
			error(logopt, MODPREFIX "getautomntent_r: %s", estr);
			endautomntent(logopt, ctxt, &sss_ctxt);
			if (key)
				free(key);
			if (value)
				free(value);
			return NSS_STATUS_UNAVAIL;
		}
		if (ret == ENOENT) {
			if (!count) {
				char *estr = strerror_r(ret, buf, MAX_ERR_BUF);
				error(logopt, MODPREFIX "getautomntent_r: %s", estr);
				endautomntent(logopt, ctxt, &sss_ctxt);
				if (key)
					free(key);
				if (value)
					free(value);
				return NSS_STATUS_NOTFOUND;
			}
			break;
		}
		count++;

		buffer_len = strlen(key) + 1 + strlen(value) + 2;
		buffer = malloc(buffer_len);
		if (!buffer) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, MODPREFIX "malloc: %s", estr);
			endautomntent(logopt, ctxt, &sss_ctxt);
			free(key);
			free(value);
			return NSS_STATUS_UNAVAIL;
		}

		/*
		 * TODO: implement sun % hack for key translation for
		 * mixed case keys in schema that are single case only.
		 */

		strcpy(buffer, key);
		strcat(buffer, " ");
		strcat(buffer, value);

		/*
		 * TODO: handle cancelation. This almost certainly isn't
		 * handled properly by other lookup modules either so it
		 * should be done when cancelation is reviewed for the
		 * other modules. Ditto for the other lookup module entry
		 * points.
		 */
		master_parse_entry(buffer, timeout, logging, age);

		free(buffer);
		free(key);
		free(value);
	}

	endautomntent(logopt, ctxt, &sss_ctxt);

	return NSS_STATUS_SUCCESS;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	void *sss_ctxt = NULL;
	char buf[MAX_ERR_BUF];
	char *key;
	char *value = NULL;
	char *s_key;
	int count, ret;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	/*
	 * If we don't need to create directories then there's no use
	 * reading the map. We always need to read the whole map for
	 * direct mounts in order to mount the triggers.
	 */
	if (!(ap->flags & MOUNT_FLAG_GHOST) && ap->type != LKP_DIRECT) {
		debug(ap->logopt, "map read not needed, so not done");
		return NSS_STATUS_SUCCESS;
	}

	if (!setautomntent(ap->logopt, ctxt, ctxt->mapname, &sss_ctxt))
		return NSS_STATUS_UNAVAIL;

	count = 0;
	while (1) {
	        key = NULL;
	        value = NULL;
		ret = ctxt->getautomntent_r(&key, &value, sss_ctxt);
		if (ret && ret != ENOENT) {
			char *estr = strerror_r(ret, buf, MAX_ERR_BUF);
			error(ap->logopt,
			      MODPREFIX "getautomntent_r: %s", estr);
			endautomntent(ap->logopt, ctxt, &sss_ctxt);
			if (key)
				free(key);
			if (value)
				free(value);
			return NSS_STATUS_UNAVAIL;
		}
		if (ret == ENOENT) {
			if (!count) {
				char *estr = strerror_r(ret, buf, MAX_ERR_BUF);
				error(ap->logopt,
				      MODPREFIX "getautomntent_r: %s", estr);
				endautomntent(ap->logopt, ctxt, &sss_ctxt);
				if (key)
					free(key);
				if (value)
					free(value);
				return NSS_STATUS_NOTFOUND;
			}
			break;
		}

		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (*key == '+') {
			warn(ap->logopt,
			     MODPREFIX "ignoring '+' map entry - not in file map");
			free(key);
			free(value);
			continue;
		}

		if (*key == '/' && strlen(key) == 1) {
			if (ap->type == LKP_DIRECT) {
				free(key);
				free(value);
				continue;
			}
			*key = '*';
		}

		/*
		 * TODO: implement sun % hack for key translation for
		 * mixed case keys in schema that are single case only.
		 */

		s_key = sanitize_path(key, strlen(key), ap->type, ap->logopt);
		if (!s_key) {
			error(ap->logopt, MODPREFIX "invalid path %s", key);
			endautomntent(ap->logopt, ctxt, &sss_ctxt);
			free(key);
			free(value);
			return NSS_STATUS_NOTFOUND;
		}

		count++;

		cache_writelock(mc);
		cache_update(mc, source, s_key, value, age);
		cache_unlock(mc);

		free(s_key);
		free(key);
		free(value);
	}

	endautomntent(ap->logopt, ctxt, &sss_ctxt);

	source->age = age;

	return NSS_STATUS_SUCCESS;
}

static int lookup_one(struct autofs_point *ap,
		char *qKey, int qKey_len, struct lookup_context *ctxt)
{
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *we;
	void *sss_ctxt = NULL;
	time_t age = time(NULL);
	char buf[MAX_ERR_BUF];
	char *value = NULL;
	char *s_key;
	int ret;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	if (!setautomntent(ap->logopt, ctxt, ctxt->mapname, &sss_ctxt))
		return NSS_STATUS_UNAVAIL;

	ret = ctxt->getautomntbyname_r(qKey, &value, sss_ctxt);
	if (ret && ret != ENOENT) {
		char *estr = strerror_r(ret, buf, MAX_ERR_BUF);
		error(ap->logopt,
		      MODPREFIX "getautomntbyname_r: %s", estr);
		endautomntent(ap->logopt, ctxt, &sss_ctxt);
		if (value)
			free(value);
		return NSS_STATUS_UNAVAIL;
	}
	if (ret != ENOENT) {
		/*
		 * TODO: implement sun % hack for key translation for
		 * mixed case keys in schema that are single case only.
		 */
		s_key = sanitize_path(qKey, qKey_len, ap->type, ap->logopt);
		if (!s_key) {
			free(value);
			value = NULL;
			goto wild;
		}
		cache_writelock(mc);
		ret = cache_update(mc, source, s_key, value, age);
		cache_unlock(mc);
		endautomntent(ap->logopt, ctxt, &sss_ctxt);
		free(s_key);
		free(value);
		return NSS_STATUS_SUCCESS;
	}

wild:
	ret = ctxt->getautomntbyname_r("/", &value, sss_ctxt);
	if (ret && ret != ENOENT) {
		char *estr = strerror_r(ret, buf, MAX_ERR_BUF);
		error(ap->logopt,
		      MODPREFIX "getautomntbyname_r: %s", estr);
		endautomntent(ap->logopt, ctxt, &sss_ctxt);
		if (value)
			free(value);
		return NSS_STATUS_UNAVAIL;
	}
	if (ret == ENOENT) {
		ret = ctxt->getautomntbyname_r("*", &value, sss_ctxt);
		if (ret && ret != ENOENT) {
			char *estr = strerror_r(ret, buf, MAX_ERR_BUF);
			error(ap->logopt,
			      MODPREFIX "getautomntbyname_r: %s", estr);
			endautomntent(ap->logopt, ctxt, &sss_ctxt);
			if (value)
				free(value);
			return NSS_STATUS_UNAVAIL;
		}
	}

	if (ret == ENOENT) {
		/* Failed to find wild entry, update cache if needed */
		cache_writelock(mc);
		we = cache_lookup_distinct(mc, "*");
		if (we) {
			/* Wildcard entry existed and is now gone */
			if (we->source == source) {
				cache_delete(mc, "*");
				source->stale = 1;
			}
		}

		/* Not found in the map but found in the cache */
		struct mapent *exists = cache_lookup_distinct(mc, qKey);
		if (exists && exists->source == source) {
			if (exists->mapent) {
				free(exists->mapent);
				exists->mapent = NULL;
				source->stale = 1;
				exists->status = 0;
			}
		}
		cache_unlock(mc);
		endautomntent(ap->logopt, ctxt, &sss_ctxt);
		return NSS_STATUS_NOTFOUND;
	}

	cache_writelock(mc);
	/* Wildcard not in map but now is */
	we = cache_lookup_distinct(mc, "*");
	if (!we)
		source->stale = 1;
	ret = cache_update(mc, source, "*", value, age);
	cache_unlock(mc);

	endautomntent(ap->logopt, ctxt, &sss_ctxt);
        free(value);

	return NSS_STATUS_SUCCESS;
}

static int check_map_indirect(struct autofs_point *ap,
			      char *key, int key_len,
			      struct lookup_context *ctxt)
{
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *me;
	time_t now = time(NULL);
	time_t t_last_read;
	int ret, cur_state;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	master_source_current_wait(ap->entry);
	ap->entry->current = source;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	ret = lookup_one(ap, key, key_len, ctxt);
	if (ret == NSS_STATUS_NOTFOUND) {
		pthread_setcancelstate(cur_state, NULL);
		return ret;
	} else if (ret == NSS_STATUS_UNAVAIL) {
		/*
		 * If the server is down and the entry exists in the cache
		 * and belongs to this map return success and use the entry.
		 */
		struct mapent *exists = cache_lookup(mc, key);
		if (exists && exists->source == source) {
			pthread_setcancelstate(cur_state, NULL);
			return NSS_STATUS_SUCCESS;
		}
		pthread_setcancelstate(cur_state, NULL);

		warn(ap->logopt,
		     MODPREFIX "lookup for %s failed: connection failed", key);

		return ret;
	}
	pthread_setcancelstate(cur_state, NULL);

	/*
	 * Check for map change and update as needed for
	 * following cache lookup.
	 */
	cache_readlock(mc);
	t_last_read = ap->exp_runfreq + 1;
	me = cache_lookup_first(mc);
	while (me) {
		if (me->source == source) {
			t_last_read = now - me->age;
			break;
		}
		me = cache_lookup_next(mc, me);
	}
	cache_unlock(mc);

	if (t_last_read > ap->exp_runfreq && ret & CHE_UPDATED)
		source->stale = 1;

	cache_readlock(mc);
	me = cache_lookup_distinct(mc, "*");
	if (ret == CHE_MISSING && (!me || me->source != source)) {
		cache_unlock(mc);
		return NSS_STATUS_NOTFOUND;
	}
	cache_unlock(mc);

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *me;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *mapent = NULL;
	char mapent_buf[MAPENT_MAX_LEN + 1];
	int ret;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	debug(ap->logopt, MODPREFIX "looking up %s", name);

	key_len = snprintf(key, KEY_MAX_LEN + 1, "%s", name);
	if (key_len > KEY_MAX_LEN)
		return NSS_STATUS_NOTFOUND;

	/* Check if we recorded a mount fail for this key anywhere */
	me = lookup_source_mapent(ap, key, LKP_DISTINCT);
	if (me) {
		if (me->status >= time(NULL)) {
			cache_unlock(me->mc);
			return NSS_STATUS_NOTFOUND;
		} else {
			struct mapent_cache *smc = me->mc;
			struct mapent *sme;

			if (me->mapent)
				cache_unlock(smc);
			else {
				cache_unlock(smc);
				cache_writelock(smc);
				sme = cache_lookup_distinct(smc, key);
				/* Negative timeout expired for non-existent entry. */
				if (sme && !sme->mapent) {
					if (cache_pop_mapent(sme) == CHE_FAIL)
						cache_delete(smc, key);
				}
				cache_unlock(smc);
			}
		}
	}

        /*
	 * We can't check the direct mount map as if it's not in
	 * the map cache already we never get a mount lookup, so
	 * we never know about it.
	 */
	if (ap->type == LKP_INDIRECT && *key != '/') {
		int status;
		char *lkp_key;

		cache_readlock(mc);
		me = cache_lookup_distinct(mc, key);
		if (me && me->multi)
			lkp_key = strdup(me->multi->key);
		else
			lkp_key = strdup(key);
		cache_unlock(mc);

		if (!lkp_key)
			return NSS_STATUS_UNKNOWN;

		master_source_current_wait(ap->entry);
		ap->entry->current = source;

		status = check_map_indirect(ap, lkp_key, strlen(lkp_key), ctxt);
		free(lkp_key);
		if (status)
			return status;
	}

	/*
	 * We can't take the writelock for direct mounts. If we're
	 * starting up or trying to re-connect to an existing direct
	 * mount we could be iterating through the map entries with
	 * the readlock held. But we don't need to update the cache
	 * when we're starting up so just take the readlock in that
	 */
	if (ap->flags & MOUNT_FLAG_REMOUNT)
		cache_writelock(mc);
	else
		cache_readlock(mc);
	me = cache_lookup(mc, key);
	/* Stale mapent => check for entry in alternate source or wildcard */
	if (me && !me->mapent) {
		while ((me = cache_lookup_key_next(me)))
			if (me->source == source)
				break;
		if (!me)
			me = cache_lookup_distinct(mc, "*");
	}
	if (me && me->mapent) {
		/*
		 * If this is a lookup add wildcard match for later validation
		 * checks and negative cache lookups.
		 */
		if (ap->type == LKP_INDIRECT && *me->key == '*' &&
		   !(ap->flags & MOUNT_FLAG_REMOUNT)) {
			ret = cache_update(mc, source, key, me->mapent, me->age);
			if (!(ret & (CHE_OK | CHE_UPDATED)))
				me = NULL;
		}
		if (me && (me->source == source || *me->key == '/')) {
			strcpy(mapent_buf, me->mapent);
			mapent = mapent_buf;
		}
	}
	cache_unlock(mc);

	if (!mapent)
		return NSS_STATUS_TRYAGAIN;

	master_source_current_wait(ap->entry);
	ap->entry->current = source;

	debug(ap->logopt, MODPREFIX "%s -> %s", key, mapent);
	ret = ctxt->parse->parse_mount(ap, key, key_len,
				       mapent, ctxt->parse->context);
	if (ret) {
		/* Don't update negative cache when re-connecting */
		if (ap->flags & MOUNT_FLAG_REMOUNT)
			return NSS_STATUS_TRYAGAIN;
		cache_writelock(mc);
		cache_update_negative(mc, source, key, ap->negative_timeout);
		cache_unlock(mc);
		return NSS_STATUS_TRYAGAIN;
	}

	return NSS_STATUS_SUCCESS;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	dlclose(ctxt->dlhandle);
	free(ctxt);
	return rv;
}
