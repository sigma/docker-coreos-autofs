/*
 * lookup_nisplus.c
 *
 * Module for Linux automountd to access a NIS+ automount map
 */

#include <stdio.h>
#include <malloc.h>
#include <sys/param.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpcsvc/nis.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(nisplus): "

struct lookup_context {
	const char *domainname;
	const char *mapname;
	struct parse_mod *parse;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];

	*context = NULL;

	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "%s", estr);
		return 1;
	}

	if (argc < 1) {
		free(ctxt);
		logmsg(MODPREFIX "No map name");
		return 1;
	}
	ctxt->mapname = argv[0];

	/* 
	 * nis_local_directory () returns a pointer to a static buffer.
	 * We don't need to copy or free it.
	 */
	ctxt->domainname = nis_local_directory();
	if (!ctxt->domainname) {
		free(ctxt);
		logmsg(MODPREFIX "NIS+ domain not set");
		return 1;
	}

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
	if (!ctxt->parse) {
		free(ctxt);
		logerr(MODPREFIX "failed to open parse context");
		return 1;
	}
	*context = ctxt;

	return 0;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	unsigned int timeout = master->default_timeout;
	unsigned int logging = master->default_logging;
	unsigned int logopt =  master->logopt;
	char *tablename;
	nis_result *result;
	nis_object *this;
	unsigned int current, result_count;
	char *path, *ent;
	char *buffer;
	char buf[MAX_ERR_BUF];
	int cur_state, len;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	tablename = malloc(strlen(ctxt->mapname) + strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_UNAVAIL;
	}
	sprintf(tablename, "%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	/* check that the table exists */
	result = nis_lookup(tablename, FOLLOW_PATH | FOLLOW_LINKS);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(logopt,
		     MODPREFIX "couldn't locate nis+ table %s", ctxt->mapname);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_NOTFOUND;
	}

	sprintf(tablename, "[],%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(logopt,
		     MODPREFIX "couldn't enumrate nis+ map %s", ctxt->mapname);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_UNAVAIL;
	}

	current = 0;
	result_count = NIS_RES_NUMOBJ(result);

	while (result_count--) {
		this = &result->objects.objects_val[current++];
		path = ENTRY_VAL(this, 0);
		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (*path == '+')
			continue;

		ent = ENTRY_VAL(this, 1);

		len = ENTRY_LEN(this, 0) + 1 + ENTRY_LEN(this, 1) + 2;
		buffer = malloc(len);
		if (!buffer) {
			logerr(MODPREFIX "could not malloc parse buffer");
			continue;
		}
		memset(buffer, 0, len);

		strcat(buffer, path);
		strcat(buffer, " ");
		strcat(buffer, ent);

		master_parse_entry(buffer, timeout, logging, age);

		free(buffer);
	}

	nis_freeresult(result);
	free(tablename);
	pthread_setcancelstate(cur_state, NULL);

	return NSS_STATUS_SUCCESS;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	char *tablename;
	nis_result *result;
	nis_object *this;
	unsigned int current, result_count;
	char *key, *mapent;
	char buf[MAX_ERR_BUF];
	int cur_state;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	/*
	 * If we don't need to create directories then there's no use
	 * reading the map. We always need to read the whole map for
	 * direct mounts in order to mount the triggers.
	 */
	if (!(ap->flags & MOUNT_FLAG_GHOST) && ap->type != LKP_DIRECT) {
		debug(ap->logopt, "map read not needed, so not done");
		return NSS_STATUS_SUCCESS;
	}

	mc = source->mc;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	tablename = malloc(strlen(ctxt->mapname) + strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_UNAVAIL;
	}
	sprintf(tablename, "%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	/* check that the table exists */
	result = nis_lookup(tablename, FOLLOW_PATH | FOLLOW_LINKS);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(ap->logopt,
		     MODPREFIX "couldn't locate nis+ table %s", ctxt->mapname);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_NOTFOUND;
	}

	sprintf(tablename, "[],%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(ap->logopt,
		     MODPREFIX "couldn't enumrate nis+ map %s", ctxt->mapname);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_UNAVAIL;
	}

	current = 0;
	result_count = NIS_RES_NUMOBJ(result);

	while (result_count--) {
		char *s_key;
		size_t len;

		this = &result->objects.objects_val[current++];
		key = ENTRY_VAL(this, 0);
		len = ENTRY_LEN(this, 0);

		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (*key == '+')
			continue;

		if (!(source->flags & MAP_FLAG_FORMAT_AMD))
			s_key = sanitize_path(key, len, ap->type, ap->logopt);
		else {
			if (!strcmp(key, "/defaults")) {
				mapent = ENTRY_VAL(this, 1);
				cache_writelock(mc);
				cache_update(mc, source, key, mapent, age);
				cache_unlock(mc);
				continue;
			}
			/* Don't fail on "/" in key => type == 0 */
			s_key = sanitize_path(key, len, 0, ap->logopt);
		}
		if (!s_key)
			continue;

		mapent = ENTRY_VAL(this, 1);

		cache_writelock(mc);
		cache_update(mc, source, s_key, mapent, age);
		cache_unlock(mc);

		free(s_key);
	}

	nis_freeresult(result);

	source->age = age;

	free(tablename);
	pthread_setcancelstate(cur_state, NULL);

	return NSS_STATUS_SUCCESS;
}

static int lookup_one(struct autofs_point *ap,
		      struct map_source *source,
		      const char *key, int key_len,
		      struct lookup_context *ctxt)
{
	struct mapent_cache *mc;
	char *tablename;
	nis_result *result;
	nis_object *this;
	char *mapent;
	time_t age = time(NULL);
	int ret, cur_state;
	char buf[MAX_ERR_BUF];

	mc = source->mc;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	tablename = malloc(strlen(key) + strlen(ctxt->mapname) +
			   strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		pthread_setcancelstate(cur_state, NULL);
		return -1;
	}
	sprintf(tablename, "[key=%s],%s.org_dir.%s", key, ctxt->mapname,
		ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_error rs = result->status;
		nis_freeresult(result);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		if (rs == NIS_NOTFOUND ||
		    rs == NIS_S_NOTFOUND ||
		    rs == NIS_PARTIAL)
			return CHE_MISSING;

		return -rs;
	}

	
	this = NIS_RES_OBJECT(result);
	mapent = ENTRY_VAL(this, 1);
	cache_writelock(mc);
	ret = cache_update(mc, source, key, mapent, age);
	cache_unlock(mc);

	nis_freeresult(result);
	free(tablename);
	pthread_setcancelstate(cur_state, NULL);

	return ret;
}

static int match_key(struct autofs_point *ap,
		     struct map_source *source,
		     const char *key, int key_len,
		     struct lookup_context *ctxt)
{
	unsigned int is_amd_format = source->flags & MAP_FLAG_FORMAT_AMD;
	char buf[MAX_ERR_BUF];
	char *lkp_key;
	char *prefix;
	int ret;

	ret = lookup_one(ap, source, key, key_len, ctxt);
	if (ret < 0)
		return ret;
	if (ret == CHE_OK || ret == CHE_UPDATED || is_amd_format)
		return ret;

	lkp_key = strdup(key);
	if (!lkp_key) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, MODPREFIX "strdup: %s", estr);
		return CHE_FAIL;
	}

	ret = CHE_MISSING;

	/*
	 * Now strip successive directory components and try a
	 * match against map entries ending with a wildcard and
	 * finally try the wilcard entry itself.
	 */
	while ((prefix = strrchr(lkp_key, '/'))) {
		char *match;
		size_t len;
		*prefix = '\0';
		len = strlen(lkp_key) + 3;
		match = malloc(len);
		if (!match) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, MODPREFIX "malloc: %s", estr);
			ret = CHE_FAIL;
			goto done;
		}
		len--;
		strcpy(match, lkp_key);
		strcat(match, "/*");
		ret = lookup_one(ap, source, match, len, ctxt);
		free(match);
		if (ret < 0)
			goto done;
		if (ret == CHE_OK || ret == CHE_UPDATED)
			goto done;
	}
done:
	free(lkp_key);
	return ret;
}

static int lookup_wild(struct autofs_point *ap,
		       struct map_source *source, struct lookup_context *ctxt)
{
	struct mapent_cache *mc;
	char *tablename;
	nis_result *result;
	nis_object *this;
	char *mapent;
	time_t age = time(NULL);
	int ret, cur_state;
	char buf[MAX_ERR_BUF];

	mc = source->mc;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	tablename = malloc(strlen(ctxt->mapname) + strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		pthread_setcancelstate(cur_state, NULL);
		return -1;
	}
	sprintf(tablename, "[key=*],%s.org_dir.%s", ctxt->mapname,
		ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_error rs = result->status;
		nis_freeresult(result);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		if (rs == NIS_NOTFOUND ||
		    rs == NIS_S_NOTFOUND ||
		    rs == NIS_PARTIAL)
			return CHE_MISSING;

		return -rs;
	}

	this = NIS_RES_OBJECT(result);
	mapent = ENTRY_VAL(this, 1);
	cache_writelock(mc);
	ret = cache_update(mc, source, "*", mapent, age);
	cache_unlock(mc);

	nis_freeresult(result);
	free(tablename);
	pthread_setcancelstate(cur_state, NULL);

	return ret;
}

static int lookup_amd_defaults(struct autofs_point *ap,
			       struct map_source *source,
			       struct lookup_context *ctxt)
{
	struct mapent_cache *mc = source->mc;
	char *tablename;
	nis_result *result;
	nis_object *this;
	char *mapent;
	char buf[MAX_ERR_BUF];
	int cur_state;
	int ret;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	tablename = malloc(9 + strlen(ctxt->mapname) +
			   strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		pthread_setcancelstate(cur_state, NULL);
		return CHE_FAIL;
	}
	sprintf(tablename, "[key=/defaults],%s.org_dir.%s",
		ctxt->mapname, ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_error rs = result->status;
		nis_freeresult(result);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		if (rs == NIS_NOTFOUND ||
		    rs == NIS_S_NOTFOUND ||
		    rs == NIS_PARTIAL)
			return CHE_MISSING;

		return -rs;
	}

	this = NIS_RES_OBJECT(result);
	mapent = ENTRY_VAL(this, 1);

	cache_writelock(mc);
	ret = cache_update(mc, source, "/defaults", mapent, time(NULL));
	cache_unlock(mc);

	nis_freeresult(result);
	free(tablename);
	pthread_setcancelstate(cur_state, NULL);

	return ret;
}

static int check_map_indirect(struct autofs_point *ap,
			      struct map_source *source,
			      char *key, int key_len,
			      struct lookup_context *ctxt)
{
	unsigned int is_amd_format = source->flags & MAP_FLAG_FORMAT_AMD;
	struct mapent_cache *mc;
	struct mapent *me, *exists;
	time_t now = time(NULL);
	time_t t_last_read;
	int ret = 0;

	mc = source->mc;

	if (is_amd_format) {
		/* Check for a /defaults entry to update the map source */
		if (lookup_amd_defaults(ap, source, ctxt) == CHE_FAIL) {
			warn(ap->logopt, MODPREFIX
			     "error getting /defaults from map %s",
			     ctxt->mapname);
		}
	}

	/* check map and if change is detected re-read map */
	ret = match_key(ap, source, key, key_len, ctxt);
	if (ret == CHE_FAIL)
		return NSS_STATUS_NOTFOUND;

	if (ret < 0) {
		/*
		 * If the server is down and the entry exists in the cache
		 * and belongs to this map return success and use the entry.
		 */
		cache_readlock(mc);
		if (source->flags & MAP_FLAG_FORMAT_AMD)
			exists = match_cached_key(ap, MODPREFIX, source, key);
		else
			exists = cache_lookup(mc, key);
		if (exists && exists->source == source) {
			cache_unlock(mc);
			return NSS_STATUS_SUCCESS;
		}
		cache_unlock(mc);

		warn(ap->logopt,
		     MODPREFIX "lookup for %s failed: %s",
		     key, nis_sperrno(-ret));

		return NSS_STATUS_UNAVAIL;
	}

	cache_writelock(mc);
	t_last_read = ap->exp_runfreq + 1;
	me = cache_lookup_first(mc);
	while (me) {
		if (me->source == source) {
			t_last_read = now - me->age;
			break;
		}
		me = cache_lookup_next(mc, me);
	}
	if (is_amd_format)
		exists = match_cached_key(ap, MODPREFIX, source, key);
	else
		exists = cache_lookup_distinct(mc, key);
	exists = cache_lookup_distinct(mc, key);
	/* Not found in the map but found in the cache */
	if (exists && exists->source == source && ret & CHE_MISSING) {
		if (exists->mapent) {
			free(exists->mapent);
			exists->mapent = NULL;
			source->stale = 1;
			exists->status = 0;
		}
	}
	cache_unlock(mc);

	if (t_last_read > ap->exp_runfreq && ret & CHE_UPDATED)
		source->stale = 1;

	if (ret == CHE_MISSING) {
		int wild = CHE_MISSING;
		struct mapent *we;

		wild = lookup_wild(ap, source, ctxt);
		/*
		 * Check for map change and update as needed for
		 * following cache lookup.
		*/
		cache_writelock(mc);
		we = cache_lookup_distinct(mc, "*");
		if (we) {
			/* Wildcard entry existed and is now gone */
			if (we->source == source && wild & CHE_MISSING) {
				cache_delete(mc, "*");
				source->stale = 1;
			}
		} else {
			/* Wildcard not in map but now is */
			if (wild & (CHE_OK | CHE_UPDATED))
				source->stale = 1;
		}
		cache_unlock(mc);

		if (wild & (CHE_UPDATED | CHE_OK))
			return NSS_STATUS_SUCCESS;
	}

	if (ret == CHE_MISSING)
		return NSS_STATUS_NOTFOUND;

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *lkp_key;
	char *mapent = NULL;
	int mapent_len;
	struct mapent *me;
	char buf[MAX_ERR_BUF];
	int status;
	int ret = 1;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	debug(ap->logopt, MODPREFIX "looking up %s", name);

	if (!(source->flags & MAP_FLAG_FORMAT_AMD)) {
		key_len = snprintf(key, KEY_MAX_LEN + 1, "%s", name);
		if (key_len > KEY_MAX_LEN)
			return NSS_STATUS_NOTFOUND;
	} else {
		key_len = expandamdent(name, NULL, NULL);
		if (key_len > KEY_MAX_LEN)
			return NSS_STATUS_NOTFOUND;
		memset(key, 0, KEY_MAX_LEN + 1);
		expandamdent(name, key, NULL);
		debug(ap->logopt, MODPREFIX "expanded key: \"%s\"", key);
	}

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
		cache_readlock(mc);
		me = cache_lookup_distinct(mc, key);
		if (me && me->multi)
			lkp_key = strdup(me->multi->key);
		else if (!ap->pref)
			lkp_key = strdup(key);
		else {
			lkp_key = malloc(strlen(ap->pref) + strlen(key) + 1);
			if (lkp_key) {
				strcpy(lkp_key, ap->pref);
				strcat(lkp_key, key);
			}
		}
		cache_unlock(mc);

		if (!lkp_key) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, MODPREFIX "malloc: %s", estr);
			return NSS_STATUS_UNKNOWN;
		}

		status = check_map_indirect(ap, source,
					    lkp_key, strlen(lkp_key), ctxt);
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
	 * case.
	 */
	if (ap->flags & MOUNT_FLAG_REMOUNT)
		cache_readlock(mc);
	else
		cache_writelock(mc);

	if (!ap->pref)
		lkp_key = strdup(key);
	else {
		lkp_key = malloc(strlen(ap->pref) + strlen(key) + 1);
		if (lkp_key) {
			strcpy(lkp_key, ap->pref);
			strcat(lkp_key, key);
		}
	}

	if (!lkp_key) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, MODPREFIX "malloc: %s", estr);
		cache_unlock(mc);
		return NSS_STATUS_UNKNOWN;
	}

	me = match_cached_key(ap, MODPREFIX, source, lkp_key);
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
		if (!(ap->flags & MOUNT_FLAG_REMOUNT) &&
		    ap->type == LKP_INDIRECT && *me->key == '*') {
			ret = cache_update(mc, source, key, me->mapent, me->age);
			if (!(ret & (CHE_OK | CHE_UPDATED)))
				me = NULL;
		}
		if (me && (me->source == source || *me->key == '/')) {
			mapent_len = strlen(me->mapent);
			mapent = malloc(mapent_len + 1);
			if (mapent)
				strcpy(mapent, me->mapent);
		}
	}
	cache_unlock(mc);
	free(lkp_key);

	if (!mapent)
		return NSS_STATUS_TRYAGAIN;

	master_source_current_wait(ap->entry);
	ap->entry->current = source;

	debug(ap->logopt, MODPREFIX "%s -> %s", key, mapent);
	ret = ctxt->parse->parse_mount(ap, key, key_len,
				       mapent, ctxt->parse->context);
	if (ret) {
		free(mapent);

		/* Don't update negative cache when re-connecting */
		if (ap->flags & MOUNT_FLAG_REMOUNT)
			return NSS_STATUS_TRYAGAIN;
		cache_writelock(mc);
		cache_update_negative(mc, source, key, ap->negative_timeout);
		cache_unlock(mc);
		return NSS_STATUS_TRYAGAIN;
	}
	free(mapent);

	return NSS_STATUS_SUCCESS;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free(ctxt);
	return rv;
}
