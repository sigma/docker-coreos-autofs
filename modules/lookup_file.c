/* ----------------------------------------------------------------------- *
 *   
 *  lookup_file.c - module for Linux automount to query a flat file map
 *
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2001-2003 Ian Kent <raven@themaw.net>
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
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(file): "

#define MAX_INCLUDE_DEPTH	16

typedef enum {
	st_begin, st_compare, st_star, st_badent, st_entspc, st_getent
} LOOKUP_STATE;

typedef enum { got_nothing, got_star, got_real, got_plus } FOUND_STATE;
typedef enum { esc_none, esc_char, esc_val, esc_all } ESCAPES;

struct lookup_context {
	const char *mapname;
	int opts_argc;
	const char **opts_argv;
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
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	if (argc < 1) {
		free(ctxt);
		logerr(MODPREFIX "No map name");
		return 1;
	}

	ctxt->mapname = argv[0];

	if (ctxt->mapname[0] != '/') {
		free(ctxt);
		logmsg(MODPREFIX
		     "file map %s is not an absolute pathname", argv[0]);
		return 1;
	}

	if (access(ctxt->mapname, R_OK)) {
		free(ctxt);
		warn(LOGOPT_NONE, MODPREFIX
		    "file map %s missing or not readable", argv[0]);
		return 1;
	}

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	argc--;
	argv++;

	ctxt->opts_argv = copy_argv(argc, (const char **) argv);
	if (ctxt->opts_argv == NULL) {
		free(ctxt);
		warn(LOGOPT_NONE, MODPREFIX "failed to duplicate options");
		return 1;
	}
	ctxt->opts_argc = argc;

	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc, argv);
	if (!ctxt->parse) {
		free_argv(ctxt->opts_argc, ctxt->opts_argv);
		free(ctxt);
		logmsg(MODPREFIX "failed to open parse context");
		return 1;
	}
	*context = ctxt;

	return 0;
}

static int read_one(unsigned logopt, FILE *f, char *key, unsigned int *k_len, char *mapent, unsigned int *m_len)
{
	char *kptr, *p;
	int mapent_len, key_len;
	int ch, nch;
	LOOKUP_STATE state;
	FOUND_STATE getting, gotten;
	ESCAPES escape;

	kptr = key;
	p = NULL;
	mapent_len = key_len = 0;
	state = st_begin;
	memset(key, 0, KEY_MAX_LEN + 1);
	memset(mapent, 0, MAPENT_MAX_LEN + 1);
	getting = gotten = got_nothing;
	escape = esc_none;

	/* This is ugly.  We can't just remove \ escape sequences in the value
	   portion of an entry, because the parsing routine may need it. */

	while ((ch = getc(f)) != EOF) {
		switch (escape) {
		case esc_none:
			if (ch == '\\') {
				/* Handle continuation lines */
				if ((nch = getc(f)) == '\n')
					continue;
				ungetc(nch, f);
				escape = esc_char;
			}
			if (ch == '"')
				escape = esc_all;
			break;

		case esc_char:
			escape = esc_val;
			break;

		case esc_val:
			escape = esc_none;
			break;

		case esc_all:
			if (ch == '"')
				escape = esc_none;
			break;
		}

		switch (state) {
		case st_begin:
			if (!escape) {
				if (isspace(ch));
				else if (ch == '#')
					state = st_badent;
				else if (ch == '*') {
					state = st_star;
					*(kptr++) = ch;
					key_len++;
				} else {
					if (ch == '+')
						gotten = got_plus;
					state = st_compare;
					*(kptr++) = ch;
					key_len++;
				}
			} else if (escape == esc_all) {
				state = st_compare;
				*(kptr++) = ch;
				key_len++;
			} else if (escape == esc_char);
			else
				state = st_badent;
			break;

		case st_compare:
			if (ch == '\n') {
				state = st_begin;
				if (gotten == got_plus)
					goto got_it;
				else if (escape == esc_all) {
					warn(logopt, MODPREFIX
					    "unmatched \" in map key %s", key);
					goto next;
				} else if (escape != esc_val)
					goto got_it;
			} else if (isspace(ch) && !escape) {
				getting = got_real;
				state = st_entspc;
				if (gotten == got_plus)
					goto got_it;
			} else if (escape == esc_char);
			else {
				if (key_len == KEY_MAX_LEN) {
					state = st_badent;
					gotten = got_nothing;
					warn(logopt,
					      MODPREFIX "map key \"%s...\" "
					      "is too long.  The maximum key "
					      "length is %d", key,
					      KEY_MAX_LEN);
				} else {
					if (escape == esc_val) {
						*(kptr++) = '\\';
						key_len++;
					}
					*(kptr++) = ch;
					key_len++;
				}
			}
			break;

		case st_star:
			if (ch == '\n')
				state = st_begin;
			else if (isspace(ch) && gotten < got_star && !escape) {
				getting = got_star;
				state = st_entspc;
			} else if (escape != esc_char)
				state = st_badent;
			break;

		case st_badent:
			if (ch == '\n') {
				nch = getc(f);
				if (nch != EOF && isblank(nch)) {
					ungetc(nch, f);
					break;
				}
				ungetc(nch, f);
				state = st_begin;
				if (gotten == got_real || gotten == getting)
					goto got_it;
				warn(logopt, MODPREFIX 
				      "bad map entry \"%s...\" for key "
				      "\"%s\"", mapent, key);
				goto next;
			} else if (!isblank(ch))
				gotten = got_nothing;
			break;

		case st_entspc:
			if (ch == '\n')
				state = st_begin;
			else if (!isspace(ch) || escape) {
				if (escape) {
					if (escape == esc_char)
						break;
					if (ch <= 32) {
						getting = got_nothing;
						state = st_badent;
						break;
					}
					p = mapent;
					if (escape == esc_val) {
						*(p++) = '\\';
						mapent_len++;
					}
					*(p++) = ch;
					mapent_len++;
				} else {
					p = mapent;
					*(p++) = ch;
					mapent_len = 1;
				}
				state = st_getent;
				gotten = getting;
			}
			break;

		case st_getent:
			if (ch == '\n') {
				if (escape == esc_all) {
					state = st_begin;
					warn(logopt, MODPREFIX
					     "unmatched \" in %s for key %s",
					     mapent, key);
					goto next;
				}
				nch = getc(f);
				if (nch != EOF && isblank(nch)) {
					ungetc(nch, f);
					state = st_badent;
					break;
				}
				ungetc(nch, f);
				state = st_begin;
				if (gotten == got_real || gotten == getting)
					goto got_it;
			} else if (mapent_len < MAPENT_MAX_LEN) {
				if (p) {
					mapent_len++;
					*(p++) = ch;
				}
				nch = getc(f);
				if (nch == EOF &&
				   (gotten == got_real || gotten == getting))
				   	goto got_it;
				ungetc(nch, f);
			} else {
				warn(logopt,
				      MODPREFIX "map entry \"%s...\" for key "
				      "\"%s\" is too long.  The maximum entry"
				      " size is %d", mapent, key,
				      MAPENT_MAX_LEN);
				state = st_badent;
			}
			break;
		}
		continue;

	      got_it:
		if (gotten == got_nothing)
			goto next;

		*k_len = key_len;
		*m_len = mapent_len;

		return 1;

	      next:
		kptr = key;
		p = NULL;
		mapent_len = key_len = 0;
		memset(key, 0, KEY_MAX_LEN + 1);
		memset(mapent, 0, MAPENT_MAX_LEN + 1);
		getting = gotten = got_nothing;
		escape = esc_none;
	}

	return 0;
}

static int check_master_self_include(struct master *master, struct lookup_context *ctxt)
{
	char *m_path, *m_base, *i_path, *i_base;

	/*
	 * If we are including a file map then check the
	 * full path of the map.
	 */
	if (*master->name == '/') {
		if (!strcmp(master->name, ctxt->mapname))
			return 1;
		else
			return 0;
	}

	/* Otherwise only check the map name itself. */

	i_path = strdup(ctxt->mapname);
	if (!i_path)
		return 0;
	i_base = basename(i_path);

	m_path = strdup(master->name);
	if (!m_path) {
		free(i_path);
		return 0;
	}
	m_base = basename(m_path);

	if (!strcmp(m_base, i_base)) {
		free(i_path);
		free(m_path);
		return  1;
	}
	free(i_path);
	free(m_path);

	return 0;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	unsigned int timeout = master->default_timeout;
	unsigned int logging = master->default_logging;
	unsigned int logopt = master->logopt;
	char *buffer;
	int blen;
	char path[KEY_MAX_LEN + 1];
	char ent[MAPENT_MAX_LEN + 1];
	FILE *f;
	unsigned int path_len, ent_len;
	int entry, cur_state;

	/* Don't return fail on self include, skip source */
	if (master->recurse)
		return NSS_STATUS_TRYAGAIN;

	if (master->depth > MAX_INCLUDE_DEPTH) {
		error(logopt, MODPREFIX
		      "maximum include depth exceeded %s", master->name);
		return NSS_STATUS_UNAVAIL;
	}

	f = open_fopen_r(ctxt->mapname);
	if (!f) {
		error(logopt,
		      MODPREFIX "could not open master map file %s",
		      ctxt->mapname);
		return NSS_STATUS_UNAVAIL;
	}

	while(1) {
		entry = read_one(logopt, f, path, &path_len, ent, &ent_len);
		if (!entry) {
			if (feof(f))
				break;
			if (ferror(f)) {
				warn(logopt, MODPREFIX
				     "error reading map %s", ctxt->mapname);
				break;
			}
			continue;
		}

		debug(logopt, MODPREFIX "read entry %s", path);

		/*
		 * If key starts with '+' it has to be an
		 * included map.
		 */
		if (*path == '+') {
			char *save_name;
			unsigned int inc;
			int status;

			save_name = master->name;
			master->name = path + 1;

			inc = check_master_self_include(master, ctxt);
			if (inc) 
				master->recurse = 1;
			master->depth++;
			status = lookup_nss_read_master(master, age);
			if (!status) {
				warn(logopt,
				     MODPREFIX
				     "failed to read included master map %s",
				     master->name);
			}
			master->depth--;
			master->recurse = 0;

			master->name = save_name;
		} else {
			blen = path_len + 1 + ent_len + 2;
			buffer = malloc(blen);
			if (!buffer) {
				error(logopt,
				      MODPREFIX "could not malloc parse buffer");
				fclose(f);
				return NSS_STATUS_UNAVAIL;
			}
			memset(buffer, 0, blen);

			strcpy(buffer, path);
			strcat(buffer, " ");
			strcat(buffer, ent);

			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
			master_parse_entry(buffer, timeout, logging, age);
			free(buffer);
			pthread_setcancelstate(cur_state, NULL);
		}

		if (feof(f))
			break;
	}

	fclose(f);

	return NSS_STATUS_SUCCESS;
}

static int check_self_include(const char *key, struct lookup_context *ctxt)
{
	char *m_key, *m_base, *i_key, *i_base;

	/*
	 * If we are including a file map then check the
	 * full path of the map.
	 */
	if (*(key + 1) == '/') {
		if (!strcmp(key + 1, ctxt->mapname))
			return 1;
		else
			return 0;
	}

	i_key = strdup(key + 1);
	if (!i_key)
		return 0;
	i_base = basename(i_key);

	m_key = strdup(ctxt->mapname);
	if (!m_key) {
		free(i_key);
		return 0;
	}
	m_base = basename(m_key);

	if (!strcmp(m_base, i_base)) {
		free(i_key);
		free(m_key);
		return 1;
	}
	free(i_key);
	free(m_key);

	return 0;
}

static struct map_source *
prepare_plus_include(struct autofs_point *ap,
		     struct map_source *source,
		     time_t age, char *key, unsigned int inc,
		     struct lookup_context *ctxt)
{
	struct map_source *new;
	struct map_type_info *info;
	const char *argv[2];
	char **tmp_argv, **tmp_opts;
	int argc;
	char *buf;

	/*
	 * TODO:
	 * Initially just consider the passed in key to be a simple map
	 * name (and possible source) and use the global map options in
	 * the given autofs_point. ie. global options override.
	 *
	 * Later we might want to parse this and fill in the autofs_point
	 * options fields.
	 */
	/* skip plus */
	buf = strdup(key + 1);
	if (!buf) {
		error(ap->logopt, MODPREFIX "failed to strdup key");
		return NULL;
	}

	if (!(info = parse_map_type_info(buf))) {
		error(ap->logopt, MODPREFIX "failed to parse map info");
		free(buf);
		return NULL;
	}

	argc = 1;
	argv[0] = info->map;
	argv[1] = NULL;

	tmp_argv = (char **) copy_argv(argc, argv);
	if (!tmp_argv) {
		error(ap->logopt, MODPREFIX "failed to allocate args vector");
		free_map_type_info(info);
		free(buf);
		return NULL;
	}

	tmp_opts = (char **) copy_argv(ctxt->opts_argc, ctxt->opts_argv);
	if (!tmp_opts) {
		error(ap->logopt, MODPREFIX "failed to allocate options args vector");
		free_argv(argc, (const char **) tmp_argv);
		free_map_type_info(info);
		free(buf);
		return NULL;
	}

	tmp_argv = append_argv(argc, tmp_argv, ctxt->opts_argc, tmp_opts);
	if (!tmp_argv) {
		error(ap->logopt, MODPREFIX "failed to append options vector");
		free_map_type_info(info);
		free(buf);
		return NULL;
	}
	argc += ctxt->opts_argc;

	new = master_find_source_instance(source,
					  info->type, info->format,
					  argc, (const char **) tmp_argv);
	if (new) {
		/*
		 * Make sure included map age is in sync with its owner
		 * or we could incorrectly wipe out its entries.
		 */
		new->age = age;
		new->stale = 1;
	} else {
		new = master_add_source_instance(source,
						 info->type, info->format, age,
						 argc, (const char **) tmp_argv);
		if (!new) {
			free_argv(argc, (const char **) tmp_argv);
			free_map_type_info(info);
			free(buf);
			error(ap->logopt, "failed to add included map instance");
			return NULL;
		}
	}
	free_argv(argc, (const char **) tmp_argv);

	new->depth = source->depth + 1;
	if (inc)
		new->recurse = 1;

	free_map_type_info(info);
	free(buf);

	return new;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	char key[KEY_MAX_LEN + 1];
	char mapent[MAPENT_MAX_LEN + 1];
	FILE *f;
	unsigned int k_len, m_len;
	int entry;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	if (source->recurse)
		return NSS_STATUS_TRYAGAIN;

	if (source->depth > MAX_INCLUDE_DEPTH) {
		error(ap->logopt,
		      "maximum include depth exceeded %s", ctxt->mapname);
		return NSS_STATUS_UNAVAIL;
	}

	f = open_fopen_r(ctxt->mapname);
	if (!f) {
		error(ap->logopt,
		      MODPREFIX "could not open map file %s", ctxt->mapname);
		return NSS_STATUS_UNAVAIL;
	}

	while(1) {
		entry = read_one(ap->logopt, f, key, &k_len, mapent, &m_len);
		if (!entry) {
			if (feof(f))
				break;
			if (ferror(f)) {
				warn(ap->logopt, MODPREFIX
				      "error reading map %s", ctxt->mapname);
				break;
			}
			continue;
		}
			
		/*
		 * If key starts with '+' it has to be an
		 * included map.
		 */
		if (*key == '+') {
			struct map_source *inc_source;
			unsigned int inc;
			int status;

			debug(ap->logopt, "read included map %s", key);

			inc = check_self_include(key, ctxt);

			inc_source = prepare_plus_include(ap, source,
							  age, key, inc, ctxt);
			if (!inc_source) {
				debug(ap->logopt,
				      "failed to select included map %s", key);
				continue;
			}

			/* Gim'ee some o' that 16k stack baby !! */
			status = lookup_nss_read_map(ap, inc_source, age);
			if (!status) {
				warn(ap->logopt,
				     "failed to read included map %s", key);
			}
		} else {
			char *s_key; 

			if (source->flags & MAP_FLAG_FORMAT_AMD) {
				if (!strcmp(key, "/defaults")) {
					cache_writelock(mc);
					cache_update(mc, source, key, mapent, age);
					cache_unlock(mc);
					continue;
				}
				/* Don't fail on "/" in key => type == 0 */
				s_key = sanitize_path(key, k_len, 0, ap->logopt);
				if (!s_key)
					continue;
			} else {
				s_key = sanitize_path(key, k_len, ap->type, ap->logopt);
				if (!s_key)
					continue;
			}

			cache_writelock(mc);
			cache_update(mc, source, s_key, mapent, age);
			cache_unlock(mc);

			free(s_key);
		}

		if (feof(f))
			break;
	}

	source->age = age;

	fclose(f);

	return NSS_STATUS_SUCCESS;
}

static int match_key(struct autofs_point *ap,
		     struct map_source *source, char *map_key,
		     const char *key, size_t key_len, const char *mapent)
{
	char buf[MAX_ERR_BUF];
	struct mapent_cache *mc;
	time_t age = time(NULL);
	char *lkp_key;
	char *prefix;
	size_t map_key_len;
	int ret, eq;

	mc = source->mc;

	/* exact match is a match for both autofs and amd */
	eq = strcmp(map_key, key);
	if (eq == 0) {
		cache_writelock(mc);
		ret = cache_update(mc, source, key, mapent, age);
		cache_unlock(mc);
		return ret;
	}

	if (!(source->flags & MAP_FLAG_FORMAT_AMD))
		return CHE_FAIL;

	map_key_len = strlen(map_key);

	lkp_key = strdup(key);
	if (!lkp_key) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, MODPREFIX "strdup: %s", estr);
		return CHE_FAIL;
	}

	ret = CHE_FAIL;

	if (map_key_len > (strlen(lkp_key) + 2))
		goto done;

	/*
	 * Now strip successive directory components and try a
	 * match against map entries ending with a wildcard and
	 * finally try the wilcard entry itself. If we get a match
	 * then update the cache with the read key and its mapent.
	*/
	while ((prefix = strrchr(lkp_key, '/'))) {
		size_t len;
		*prefix = '\0';
		len = strlen(lkp_key);
		eq = strncmp(map_key, lkp_key, len);
		if (!eq && map_key[len + 1] == '*') {
			cache_writelock(mc);
			ret = cache_update(mc, source, map_key, mapent, age);
			cache_unlock(mc);
			goto done;
		}
	}
done:
	free(lkp_key);
	return ret;
}

static int lookup_one(struct autofs_point *ap,
		      struct map_source *source,
		      const char *key, int key_len,
		      struct lookup_context *ctxt)
{
	struct mapent_cache *mc = source->mc;
	char mkey[KEY_MAX_LEN + 1];
	char mapent[MAPENT_MAX_LEN + 1];
	time_t age = time(NULL);
	FILE *f;
	unsigned int k_len, m_len;
	int entry, ret;

	f = open_fopen_r(ctxt->mapname);
	if (!f) {
		error(ap->logopt,
		      MODPREFIX "could not open map file %s", ctxt->mapname);
		return CHE_FAIL;
	}

	while(1) {
		entry = read_one(ap->logopt, f, mkey, &k_len, mapent, &m_len);
		if (entry) {
			/*
			 * If key starts with '+' it has to be an
			 * included map.
			 */
			if (*mkey == '+') {
				struct map_source *inc_source;
				unsigned int inc;
				int status;

				debug(ap->logopt,
				      MODPREFIX "lookup included map %s", mkey);

				inc = check_self_include(mkey, ctxt);

				inc_source = prepare_plus_include(ap, source,
								  age, mkey, inc, ctxt);
				if (!inc_source) {
					debug(ap->logopt,
					      MODPREFIX
					      "failed to select included map %s",
					      key);
					continue;
				}

				/* Gim'ee some o' that 16k stack baby !! */
				status = lookup_nss_mount(ap, inc_source, key, key_len);
				if (status) {
					fclose(f);
					return CHE_COMPLETED;
				}
			} else {
				char *s_key; 

				if (source->flags & MAP_FLAG_FORMAT_AMD) {
					if (!strcmp(mkey, "/defaults")) {
						cache_writelock(mc);
						cache_update(mc, source, mkey, mapent, age);
						cache_unlock(mc);
						continue;
					}
					/* Don't fail on "/" in key => type == 0 */
					s_key = sanitize_path(mkey, k_len, 0, ap->logopt);
					if (!s_key)
						continue;
				} else {
					s_key = sanitize_path(mkey, k_len, ap->type, ap->logopt);
					if (!s_key)
						continue;

					if (key_len != strlen(s_key)) {
						free(s_key);
						continue;
					}
				}

				ret = match_key(ap, source,
						s_key, key, key_len, mapent);
				if (ret == CHE_FAIL) {
					free(s_key);
					continue;
				}

				free(s_key);

				fclose(f);

				return ret;
			}
		}

		if (feof(f))
			break;

		if (ferror(f)) {
			warn(ap->logopt, MODPREFIX
			      "error reading map %s", ctxt->mapname);
			break;
		}		
	}

	fclose(f);

	return CHE_MISSING;
}

static int lookup_wild(struct autofs_point *ap,
		       struct map_source *source, struct lookup_context *ctxt)
{
	struct mapent_cache *mc;
	char mkey[KEY_MAX_LEN + 1];
	char mapent[MAPENT_MAX_LEN + 1];
	time_t age = time(NULL);
	FILE *f;
	unsigned int k_len, m_len;
	int entry, ret;

	mc = source->mc;

	f = open_fopen_r(ctxt->mapname);
	if (!f) {
		error(ap->logopt,
		      MODPREFIX "could not open map file %s", ctxt->mapname);
		return CHE_FAIL;
	}

	while(1) {
		entry = read_one(ap->logopt, f, mkey, &k_len, mapent, &m_len);
		if (entry) {
			int eq;

			eq = (*mkey == '*' && k_len == 1);
			if (eq == 0)
				continue;

			cache_writelock(mc);
			ret = cache_update(mc, source, "*", mapent, age);
			cache_unlock(mc);

			fclose(f);

			return ret;
		}

		if (feof(f))
			break;

		if (ferror(f)) {
			warn(ap->logopt, MODPREFIX
			      "error reading map %s", ctxt->mapname);
			break;
		}		
	}

	fclose(f);

	return CHE_MISSING;
}

static int check_map_indirect(struct autofs_point *ap,
			      struct map_source *source,
			      char *key, int key_len,
			      struct lookup_context *ctxt)
{
	struct mapent_cache *mc;
	struct mapent *exists;
	int ret = CHE_OK;

	mc = source->mc;

	ret = lookup_one(ap, source, key, key_len, ctxt);
	if (ret == CHE_COMPLETED)
		return NSS_STATUS_COMPLETED;

	if (ret == CHE_FAIL)
		return NSS_STATUS_NOTFOUND;

	cache_writelock(mc);
	if (source->flags & MAP_FLAG_FORMAT_AMD)
		exists = match_cached_key(ap, MODPREFIX, source, key);
	else
		exists = cache_lookup_distinct(mc, key);
	/* Not found in the map but found in the cache */
	if (exists && exists->source == source && ret & CHE_MISSING) {
		if (exists->mapent) {
			free(exists->mapent);
			exists->mapent = NULL;
			exists->status = 0;
		}
	}
	cache_unlock(mc);

	if (ret == CHE_MISSING) {
		struct mapent *we;
		int wild = CHE_MISSING;

		wild = lookup_wild(ap, source, ctxt);
		/*
		 * Check for map change and update as needed for
		 * following cache lookup.
		 */
		cache_writelock(mc);
		we = cache_lookup_distinct(mc, "*");
		if (we) {
			/* Wildcard entry existed and is now gone */
			if (we->source == source && (wild & CHE_MISSING))
				cache_delete(mc, "*");
		}
		cache_unlock(mc);

		if (wild & (CHE_OK | CHE_UPDATED))
			return NSS_STATUS_SUCCESS;
	}

	if (ret == CHE_MISSING)
		return NSS_STATUS_NOTFOUND;

	return NSS_STATUS_SUCCESS;
}

static int map_update_needed(struct autofs_point *ap,
			     struct map_source *source,
			     struct lookup_context * ctxt)
{
	struct mapent_cache *mc;
	struct mapent *me;
	struct stat st;
	int ret = 1;

	mc = source->mc;

	/*
	 * We can skip the map lookup and cache update altogether
	 * if we know the map hasn't been modified since it was
	 * last read. If it has then we can mark the map stale
	 * so a re-read is triggered following the lookup.
	 */
	if (stat(ctxt->mapname, &st)) {
		error(ap->logopt, MODPREFIX
		      "file map %s, could not stat", ctxt->mapname);
		return -1;
	}

	cache_readlock(mc);
	me = cache_lookup_first(mc);
	if (me && st.st_mtime <= me->age) {
		/*
		 * If any map instances are present for this source
		 * then either we have plus included entries or we
		 * are looking through the list of nsswitch sources.
		 * In either case, or if it's a "multi" source, we
		 * cannot avoid reading through the map because we
		 * must preserve the key order over multiple sources
		 * or maps. But also, we can't know, at this point,
		 * if a source instance has been changed since the
		 * last time we checked it.
		 */
		if (!source->instance &&
		    source->type && strcmp(source->type, "multi"))
			ret = 0;
	} else
		source->stale = 1;
	cache_unlock(mc);

	return ret;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *me;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *lkp_key;
	char *mapent = NULL;
	char mapent_buf[MAPENT_MAX_LEN + 1];
	char buf[MAX_ERR_BUF];
	int status = 0;
	int ret = 1;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	if (source->recurse)
		return NSS_STATUS_UNAVAIL;

	if (source->depth > MAX_INCLUDE_DEPTH) {
		error(ap->logopt,
		      MODPREFIX
		      "maximum include depth exceeded %s", ctxt->mapname);
		return NSS_STATUS_SUCCESS;
	}

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
		int ret;

		ret = map_update_needed(ap, source, ctxt);
		if (!ret)
			goto do_cache_lookup;
		/* Map isn't accessable, just try the cache */
		if (ret < 0)
			goto do_cache_lookup;

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
		if (status) {
			if (status == NSS_STATUS_COMPLETED)
				return NSS_STATUS_SUCCESS;
			return NSS_STATUS_NOTFOUND;
		}
	}

	/*
	 * We can't take the writelock for direct mounts. If we're
	 * starting up or trying to re-connect to an existing direct
	 * mount we could be iterating through the map entries with
	 * the readlock held. But we don't need to update the cache
	 * when we're starting up so just take the readlock in that
	 * case.
	 */
do_cache_lookup:
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
	if (me && me->mapent) {
		if (me && (me->source == source || *me->key == '/')) {
			strcpy(mapent_buf, me->mapent);
			mapent = mapent_buf;
		}
	}
	cache_unlock(mc);
	free(lkp_key);

	if (!me)
		return NSS_STATUS_NOTFOUND;

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
	free_argv(ctxt->opts_argc, ctxt->opts_argv);
	free(ctxt);
	return rv;
}
