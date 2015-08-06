/*
 * lookup_hesiod.c
 *
 * Module for Linux automountd to access automount maps in hesiod filsys
 * entries.
 *
 */

#include <sys/types.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <hesiod.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT	   "hesiod"
#define AMD_MAP_PREFIX	   "hesiod."
#define AMD_MAP_PREFIX_LEN 7

#define MODPREFIX "lookup(hesiod): "
#define HESIOD_LEN 512

struct lookup_context {
	const char *mapname;
	struct parse_mod *parser;
	void *hesiod_context;
};

static pthread_mutex_t hesiod_mutex = PTHREAD_MUTEX_INITIALIZER;

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

/* This initializes a context (persistent non-global data) for queries to
   this module. */
int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt = NULL;
	char buf[MAX_ERR_BUF];

	*context = NULL;

	/* If we can't build a context, bail. */
	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}
	memset(ctxt, 0, sizeof(struct lookup_context));

	/* Initialize the resolver. */
	res_init();

	/* Initialize the hesiod context. */
	if (hesiod_init(&(ctxt->hesiod_context)) != 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "hesiod_init(): %s", estr);
		free(ctxt);
		return 1;
	}

	/* If a map type isn't explicitly given, parse it as hesiod entries. */
	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	if (!strcmp(mapfmt, "amd")) {
		/* amd formated hesiod maps have a map name */
		const char *mapname = argv[0];
		if (strncmp(mapname, AMD_MAP_PREFIX, AMD_MAP_PREFIX_LEN)) {
			logerr(MODPREFIX
			      "incorrect prefix for hesiod map %s", mapname);
			free(ctxt);
			return 1;
		}
		ctxt->mapname = mapname;
		argc--;
		argv++;
	}

	/* Open the parser, if we can. */
	ctxt->parser = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
	if (!ctxt->parser) {
		logerr(MODPREFIX "failed to open parse context");
		free(ctxt);
		return 1;
	}
	*context = ctxt;

	return 0;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	return NSS_STATUS_UNKNOWN;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	return NSS_STATUS_UNKNOWN;
}

/*
 * Lookup and act on a filesystem name.  In this case, lookup the "filsys"
 * record in hesiod.  If it's an AFS or NFS filesystem, parse it out.  If
 * it's an ERR filesystem, it's an error message we should log.  Otherwise,
 * assume it's something we know how to deal with already (generic).
 */
static int lookup_one(struct autofs_point *ap,
		      struct map_source *source,
		      const char *key, int key_len,
		      struct lookup_context *ctxt)
{
	struct mapent_cache *mc;
	char **hes_result;
	char **record, *best_record = NULL, *p;
	int priority, lowest_priority = INT_MAX;
	int ret, status;

	mc = source->mc;

	status = pthread_mutex_lock(&hesiod_mutex);
	if (status)
		fatal(status);

	hes_result = hesiod_resolve(ctxt->hesiod_context, key, "filsys");
	if (!hes_result || !hes_result[0]) {
		int err = errno;
		error(ap->logopt,
		      MODPREFIX "key \"%s\" not found in map", key);
		status = pthread_mutex_unlock(&hesiod_mutex);
		if (status)
			fatal(status);
		if (err == HES_ER_NOTFOUND)
			return CHE_MISSING;
		else
			return CHE_FAIL;
	}

	/* autofs doesn't support falling back to alternate records, so just
	   find the record with the lowest priority and hope it works.
	   -- Aaron Ucko <amu@alum.mit.edu> 2002-03-11 */
	for (record = hes_result; *record; ++record) {
	    p = strrchr(*record, ' ');
	    if ( p && isdigit(p[1]) ) {
		priority = atoi(p+1);
	    } else {
		priority = INT_MAX - 1;
	    }
	    if (priority < lowest_priority) {
		lowest_priority = priority;
		best_record = *record;
	    }
	}

	cache_writelock(mc);
	ret = cache_update(mc, source, key, best_record, time(NULL));
	cache_unlock(mc);
	if (ret == CHE_FAIL) {
		hesiod_free_list(ctxt->hesiod_context, hes_result);
		status = pthread_mutex_unlock(&hesiod_mutex);
		if (status)
			fatal(status);
		return ret;
	}

	debug(ap->logopt,
	      MODPREFIX "lookup for \"%s\" gave \"%s\"",
	      key, best_record);

	hesiod_free_list(ctxt->hesiod_context, hes_result);

	status = pthread_mutex_unlock(&hesiod_mutex);
	if (status)
		fatal(status);

	return ret;
}

static int lookup_one_amd(struct autofs_point *ap,
			  struct map_source *source,
			  const char *key, int key_len,
			  struct lookup_context *ctxt)
{
	struct mapent_cache *mc;
	char *hesiod_base;
	char **hes_result;
	char *lkp_key;
	int status, ret;

	mc = source->mc;

	hesiod_base = conf_amd_get_hesiod_base();
	if (!hesiod_base)
		return CHE_FAIL;

	lkp_key = malloc(key_len + strlen(ctxt->mapname) - 7 + 2);
	if (!lkp_key) {
		free(hesiod_base);
		return CHE_FAIL;
	}

	strcpy(lkp_key, key);
	strcat(lkp_key, ".");
	strcat(lkp_key, ctxt->mapname + AMD_MAP_PREFIX_LEN);

	status = pthread_mutex_lock(&hesiod_mutex);
	if (status)
		fatal(status);

	hes_result = hesiod_resolve(ctxt->hesiod_context, lkp_key, hesiod_base);
	if (!hes_result || !hes_result[0]) {
		int err = errno;
		if (err == HES_ER_NOTFOUND)
			ret = CHE_MISSING;
		else
			ret = CHE_FAIL;
		goto done;
	}

	cache_writelock(mc);
	ret = cache_update(mc, source, lkp_key, *hes_result, time(NULL));
	cache_unlock(mc);

	if (hes_result)
		hesiod_free_list(ctxt->hesiod_context, hes_result);
done:
	free(lkp_key);

	status = pthread_mutex_unlock(&hesiod_mutex);
	if (status)
		fatal(status);

	return ret;
}

static int match_amd_key(struct autofs_point *ap,
			 struct map_source *source,
			 const char *key, int key_len,
			 struct lookup_context *ctxt)
{
	char buf[MAX_ERR_BUF];
	char *lkp_key;
	char *prefix;
	int ret;

	ret = lookup_one_amd(ap, source, key, key_len, ctxt);
	if (ret == CHE_OK || ret == CHE_UPDATED)
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
		ret = lookup_one_amd(ap, source, match, len, ctxt);
		free(match);
		if (ret == CHE_OK || ret == CHE_UPDATED)
			goto done;
	}

	/* Lastly try the wildcard */
	ret = lookup_one_amd(ap, source, "*", 1, ctxt);
done:
	free(lkp_key);
	return ret;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct mapent_cache *mc;
	char buf[MAX_ERR_BUF];
	struct map_source *source;
	struct mapent *me;
	char key[KEY_MAX_LEN + 1];
	size_t key_len;
	char *lkp_key;
	size_t len;
	char *mapent;
	int rv;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	debug(ap->logopt,
	      MODPREFIX "looking up root=\"%s\", name=\"%s\"",
	      ap->path, name);

	if (!(source->flags & MAP_FLAG_FORMAT_AMD)) {
		key_len = snprintf(key, KEY_MAX_LEN + 1, "%s", name);
		if (key_len > KEY_MAX_LEN)
			return NSS_STATUS_NOTFOUND;
	} else {
		key_len = expandamdent(name, NULL, NULL);
		if (key_len > KEY_MAX_LEN)
			return NSS_STATUS_NOTFOUND;
		expandamdent(name, key, NULL);
		key[key_len] = '\0';
		debug(ap->logopt, MODPREFIX "expanded key: \"%s\"", key);
	}

	/* Check if we recorded a mount fail for this key anywhere */
	me = lookup_source_mapent(ap, name, LKP_DISTINCT);
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
				sme = cache_lookup_distinct(smc, name);
				/* Negative timeout expired for non-existent entry. */
				if (sme && !sme->mapent) {
					if (cache_pop_mapent(sme) == CHE_FAIL)
						cache_delete(smc, name);
				}
				cache_unlock(smc);
			}
		}
	}

	/* If this is not here the filesystem stays busy, for some reason... */
	if (chdir("/"))
		warn(ap->logopt,
		     MODPREFIX "failed to set working directory to \"/\"");

	len = key_len;
	if (!(source->flags & MAP_FLAG_FORMAT_AMD))
		lkp_key = strdup(key);
	else {
		rv = lookup_one_amd(ap, source, "/defaults", 9, ctxt);
		if (rv == CHE_FAIL)
			warn(ap->logopt,
			     MODPREFIX "failed to lookup \"/defaults\" entry");

		if (!ap->pref)
			lkp_key = strdup(key);
		else {
			len += strlen(ap->pref);
			lkp_key = malloc(len + 1);
			if (lkp_key) {
				strcpy(lkp_key, ap->pref);
				strcat(lkp_key, name);
			}
		}
	}

	if (!lkp_key) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "malloc: %s", estr);
		return NSS_STATUS_UNKNOWN;
	}

	if (source->flags & MAP_FLAG_FORMAT_AMD)
		rv = match_amd_key(ap, source, lkp_key, len, ctxt);
	else
		rv = lookup_one(ap, source, lkp_key, len, ctxt);

	if (rv == CHE_FAIL) {
		free(lkp_key);
		return NSS_STATUS_UNAVAIL;
	}

	me = match_cached_key(ap, MODPREFIX, source, lkp_key);
	free(lkp_key);
	if (!me)
		return NSS_STATUS_NOTFOUND;

	if (!me->mapent)
		return NSS_STATUS_UNAVAIL;

	mapent = strdup(me->mapent);

	rv = ctxt->parser->parse_mount(ap, key, key_len,
				       mapent, ctxt->parser->context);
	free(mapent);

	/*
	 * Unavailable due to error such as module load fail 
	 * or out of memory, etc.
	 */
	if (rv == 1 || rv == -1)
		return NSS_STATUS_UNAVAIL;

	return NSS_STATUS_SUCCESS;
}

/* This destroys a context for queries to this module.  It releases the parser
   structure (unloading the module) and frees the memory used by the context. */
int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parser);

	hesiod_end(ctxt->hesiod_context);
	free(ctxt);
	return rv;
}
