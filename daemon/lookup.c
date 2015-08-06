/* ----------------------------------------------------------------------- *
 *   
 *  lookup.c - API layer to implement nsswitch semantics for map reading
 *		and mount lookups.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version.
 *   
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "automount.h"
#include "nsswitch.h"

static int check_nss_result(struct nss_source *this, enum nsswitch_status result)
{
	enum nsswitch_status status;
	struct nss_action a;

	/* Check if we have negated actions */
	for (status = 0; status < NSS_STATUS_MAX; status++) {
		a = this->action[status];
		if (a.action == NSS_ACTION_UNKNOWN)
			continue;

		if (a.negated && result != status) {
			if (a.action == NSS_ACTION_RETURN) {
				if (result == NSS_STATUS_SUCCESS)
					return 1;
				else
					return 0;
			}
		}
	}

	a = this->action[result];

	/* Check if we have other actions for this status */
	switch (result) {
	case NSS_STATUS_SUCCESS:
		if (a.action == NSS_ACTION_CONTINUE)
			break;
		return 1;

	case NSS_STATUS_NOTFOUND:
	case NSS_STATUS_UNAVAIL:
	case NSS_STATUS_TRYAGAIN:
		if (a.action == NSS_ACTION_RETURN) {
			return 0;
		}
		break;

	default:
		break;
	}

	return -1;
}

static void nsslist_cleanup(void *arg)
{
	struct list_head *nsslist = (struct list_head *) arg;
	if (!list_empty(nsslist))
		free_sources(nsslist);
	return;
}

static int do_read_master(struct master *master, char *type, time_t age)
{
	struct lookup_mod *lookup;
	const char *argv[2];
	int argc;
	int status;

	argc = 1;
	argv[0] = master->name;
	argv[1] = NULL;

	lookup = open_lookup(type, "", NULL, argc, argv);
	if (!lookup)
		return NSS_STATUS_UNAVAIL;

	status = lookup->lookup_read_master(master, age, lookup->context);

	close_lookup(lookup);

	return status;
}

static char *find_map_path(struct autofs_point *ap, struct map_source *map)
{
	const char *mname = map->argv[0];
	unsigned int mlen = strlen(mname);
	char *tok, *ptr = NULL;
	char *path = NULL;
	char *search_path;
	struct stat st;

	/*
	 * This is different to the way it is in amd.
	 * autofs will always try to locate maps in AUTOFS_MAP_DIR
	 * but amd has no default and will not find a file map that
	 * isn't a full path when no search_path is configured, either
	 * in the mount point or global configuration.
	 */
	search_path = strdup(AUTOFS_MAP_DIR);
	if (map->flags & MAP_FLAG_FORMAT_AMD) {
		struct autofs_point *pap = ap;
		char *tmp;
		/*
		 * Make sure we get search_path from the root of the
		 * mount tree, if one is present in the configuration.
		 * Again different from amd, which ignores the submount
		 * case.
		 */
		while (pap->parent)
			pap = pap->parent;
		tmp = conf_amd_get_search_path(pap->path);
		if (tmp) {
			if (search_path)
				free(search_path);
			search_path = tmp;
		}
	}
	if (!search_path)
		return NULL;

	tok = strtok_r(search_path, ":", &ptr);
	while (tok) {
		char *this = malloc(strlen(tok) + mlen + 2);
		if (!this) {
			free(search_path);
			return NULL;
		}
		strcpy(this, tok);
		strcat(this, "/");
		strcat(this, mname);
		if (!stat(this, &st)) {
			path = this;
			break;
		}
		free(this);
		tok = strtok_r(NULL, ":", &ptr);
	}

	free(search_path);
	return path;
}

static int read_master_map(struct master *master, char *type, time_t age)
{
	unsigned int logopt = master->logopt;
	char *path, *save_name;
	int result;

	if (strcasecmp(type, "files")) {
		return do_read_master(master, type, age);
	}

	/* 
	 * This is a special case as we need to append the
	 * normal location to the map name.
	 * note: It's invalid to specify a relative path.
	 */

	if (strchr(master->name, '/')) {
		error(logopt, "relative path invalid in files map name");
		return NSS_STATUS_NOTFOUND;
	}

	path = malloc(strlen(AUTOFS_MAP_DIR) + strlen(master->name) + 2);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	strcpy(path, AUTOFS_MAP_DIR);
	strcat(path, "/");
	strcat(path, master->name);

	save_name = master->name;
	master->name = path;

	result = do_read_master(master, type, age);

	master->name = save_name;
	free(path);

	return result;
}

int lookup_nss_read_master(struct master *master, time_t age)
{
	unsigned int logopt = master->logopt;
	struct list_head nsslist;
	struct list_head *head, *p;
	int result = NSS_STATUS_UNKNOWN;

	/* If it starts with a '/' it has to be a file or LDAP map */
	if (*master->name == '/') {
		if (*(master->name + 1) == '/') {
			debug(logopt, "reading master ldap %s", master->name);
			result = do_read_master(master, "ldap", age);
		} else {
			debug(logopt, "reading master file %s", master->name);
			result = do_read_master(master, "file", age);
		}

		if (result == NSS_STATUS_UNAVAIL)
			master->read_fail = 1;

		return !result;
	} else {
		char *name = master->name;
		char *tmp;

		/* Old style name specification will remain I think. */
		tmp = strchr(name, ':');
		if (tmp) {
			char source[10];

			memset(source, 0, 10);
			if ((!strncmp(name, "file", 4) &&
				 (name[4] == ',' || name[4] == ':')) ||
			    (!strncmp(name, "yp", 2) &&
				 (name[2] == ',' || name[2] == ':')) ||
			    (!strncmp(name, "nis", 3) &&
				 (name[3] == ',' || name[3] == ':')) ||
			    (!strncmp(name, "nisplus", 7) &&
				 (name[7] == ',' || name[7] == ':')) ||
			    (!strncmp(name, "ldap", 4) &&
				 (name[4] == ',' || name[4] == ':')) ||
			    (!strncmp(name, "ldaps", 5) &&
				 (name[5] == ',' || name[5] == ':')) ||
			    (!strncmp(name, "sss", 3) ||
				 (name[3] == ',' || name[3] == ':')) ||
			    (!strncmp(name, "dir", 3) &&
				 (name[3] == ',' || name[3] == ':'))) {
				strncpy(source, name, tmp - name);

				/*
				 * If it's an ldap map leave the source in the
				 * name so the lookup module can work out if
				 * ldaps has been requested.
				 */
				if (strncmp(name, "ldap", 4)) {
					master->name = tmp + 1;
					debug(logopt, "reading master %s %s",
					      source, master->name);
				} else {
					master->name = name;
					debug(logopt, "reading master %s %s",
					      source, tmp + 1);
				}

				result = do_read_master(master, source, age);
				master->name = name;

				if (result == NSS_STATUS_UNAVAIL)
					master->read_fail = 1;

				return !result;
			}
		}
	}

	INIT_LIST_HEAD(&nsslist);

	result = nsswitch_parse(&nsslist);
	if (result) {
		if (!list_empty(&nsslist))
			free_sources(&nsslist);
		error(logopt, "can't to read name service switch config.");
		return 0;
	}

	/* First one gets it */
	head = &nsslist;
	list_for_each(p, head) {
		struct nss_source *this;
		int status;

		this = list_entry(p, struct nss_source, list);

		debug(logopt,
		      "reading master %s %s", this->source, master->name);

		result = read_master_map(master, this->source, age);

		/*
		 * If the name of the master map hasn't been explicitly
		 * configured and we're not reading an included master map
		 * then we're using auto.master as the default. Many setups
		 * also use auto_master as the default master map so we
		 * check for this map when auto.master isn't found.
		 */
		if (result != NSS_STATUS_SUCCESS &&
		    !master->depth && !defaults_master_set()) {
			char *tmp = strchr(master->name, '.');
			if (tmp) {
				debug(logopt,
				      "%s not found, replacing '.' with '_'",
				       master->name);
				*tmp = '_';
				result = read_master_map(master, this->source, age);
				if (result != NSS_STATUS_SUCCESS)
					*tmp = '.';
			}
		}

		if (result == NSS_STATUS_UNKNOWN) {
			debug(logopt, "no map - continuing to next source");
			continue;
		}

		if (result == NSS_STATUS_UNAVAIL)
			master->read_fail = 1;

		status = check_nss_result(this, result);
		if (status >= 0) {
			free_sources(&nsslist);
			return status;
		}
	}

	if (!list_empty(&nsslist))
		free_sources(&nsslist);

	return !result;
}

static int do_read_map(struct autofs_point *ap, struct map_source *map, time_t age)
{
	struct lookup_mod *lookup;
	int status;

	lookup = open_lookup(map->type, "", map->format, map->argc, map->argv);
	if (!lookup) {
		debug(ap->logopt, "lookup module %s failed", map->type);
		return NSS_STATUS_UNAVAIL;
	}

	master_source_writelock(ap->entry);
	if (map->lookup)
		close_lookup(map->lookup);
	map->lookup = lookup;
	master_source_unlock(ap->entry);

	if (!map->stale)
		return NSS_STATUS_SUCCESS;

	master_source_current_wait(ap->entry);
	ap->entry->current = map;

	status = lookup->lookup_read_map(ap, age, lookup->context);

	if (status != NSS_STATUS_SUCCESS)
		map->stale = 0;

	/*
	 * For maps that don't support enumeration return success
	 * and do whatever we must to have autofs function with an
	 * empty map entry cache.
	 *
	 * For indirect maps that use the browse option, when the
	 * server is unavailable continue as best we can with
	 * whatever we have in the cache, if anything.
	 */
	if (status == NSS_STATUS_UNKNOWN ||
	   (ap->type == LKP_INDIRECT && status == NSS_STATUS_UNAVAIL))
		return NSS_STATUS_SUCCESS;

	return status;
}

static int read_file_source_instance(struct autofs_point *ap, struct map_source *map, time_t age)
{
	struct map_source *instance;
	char src_file[] = "file";
	char src_prog[] = "program";
	struct stat st;
	char *type, *format;

	if (stat(map->argv[0], &st) == -1) {
		warn(ap->logopt, "file map %s not found", map->argv[0]);
		return NSS_STATUS_NOTFOUND;
	}

	if (!S_ISREG(st.st_mode))
		return NSS_STATUS_NOTFOUND;

	if (st.st_mode & __S_IEXEC)
		type = src_prog;
	else
		type = src_file;

	format = map->format;

	instance = master_find_source_instance(map, type, format, 0, NULL);
	if (!instance) {
		int argc = map->argc;
		const char **argv = map->argv;
		instance = master_add_source_instance(map, type, format, age, argc, argv);
		if (!instance)
			return NSS_STATUS_UNAVAIL;
		instance->recurse = map->recurse;
		instance->depth = map->depth;
	}
	instance->stale = map->stale;

	return do_read_map(ap, instance, age);
}

static int read_source_instance(struct autofs_point *ap, struct map_source *map, const char *type, time_t age)
{
	struct map_source *instance;
	const char *format;

	format = map->format;

	instance = master_find_source_instance(map, type, format, 0, NULL);
	if (!instance) {
		int argc = map->argc;
		const char **argv = map->argv;
		instance = master_add_source_instance(map, type, format, age, argc, argv);
		if (!instance)
			return NSS_STATUS_UNAVAIL;
		instance->recurse = map->recurse;
		instance->depth = map->depth;
	}
	instance->stale = map->stale;

	return do_read_map(ap, instance, age);
}

static void argv_cleanup(void *arg)
{
	struct map_source *tmap = (struct map_source *) arg;
	/* path is freed in free_argv */
	free_argv(tmap->argc, tmap->argv);
	return;
}

static int lookup_map_read_map(struct autofs_point *ap,
			       struct map_source *map, time_t age)
{
	char *path;

	if (!map->argv[0]) {
		if (!strcmp(map->type, "hosts"))
			return do_read_map(ap, map, age);
		return NSS_STATUS_UNKNOWN;
	}

	/*
	 * This is only called when map->type != NULL.
	 * We only need to look for a map if source type is
	 * file and the map name doesn't begin with a "/".
	 */
	if (strncmp(map->type, "file", 4))
		return do_read_map(ap, map, age);

	if (map->argv[0][0] == '/')
		return do_read_map(ap, map, age);

	path = find_map_path(ap, map);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	if (map->argc >= 1) {
		if (map->argv[0])
			free((char *) map->argv[0]);
		map->argv[0] = path;
	} else {
		error(ap->logopt, "invalid arguments for autofs_point");
		free(path);
		return NSS_STATUS_UNKNOWN;
	}

	return do_read_map(ap, map, age);
}

static enum nsswitch_status read_map_source(struct nss_source *this,
		struct autofs_point *ap, struct map_source *map, time_t age)
{
	enum nsswitch_status result;
	struct map_source tmap;
	char *path;

	if (strcasecmp(this->source, "files")) {
		return read_source_instance(ap, map, this->source, age);
	}

	/* 
	 * autofs built-in map for nsswitch "files" is "file".
	 * This is a special case as we need to append the
	 * normal location to the map name.
	 * note: It's invalid to specify a relative path.
	 */

	if (strchr(map->argv[0], '/')) {
		error(ap->logopt, "relative path invalid in files map name");
		return NSS_STATUS_NOTFOUND;
	}

	this->source[4] = '\0';
	tmap.flags = map->flags;
	tmap.type = this->source;
	tmap.format = map->format;
	tmap.name = map->name;
	tmap.lookup = map->lookup;
	tmap.mc = map->mc;
	tmap.instance = map->instance;
	tmap.exp_timeout = map->exp_timeout;
	tmap.recurse = map->recurse;
	tmap.depth = map->depth;
	tmap.stale = map->stale;
	tmap.argc = 0;
	tmap.argv = NULL;

	path = find_map_path(ap, map);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	if (map->argc >= 1) {
		tmap.argc = map->argc;
		tmap.argv = copy_argv(map->argc, map->argv);
		if (!tmap.argv) {
			error(ap->logopt, "failed to copy args");
			free(path);
			return NSS_STATUS_UNKNOWN;
		}
		if (tmap.argv[0])
			free((char *) tmap.argv[0]);
		tmap.argv[0] = path;
	} else {
		error(ap->logopt, "invalid arguments for autofs_point");
		free(path);
		return NSS_STATUS_UNKNOWN;
	}

	pthread_cleanup_push(argv_cleanup, &tmap);
	result = read_file_source_instance(ap, &tmap, age);
	pthread_cleanup_pop(1);

	map->instance = tmap.instance;

	return result;
}

int lookup_nss_read_map(struct autofs_point *ap, struct map_source *source, time_t age)
{
	struct master_mapent *entry = ap->entry;
	struct list_head nsslist;
	struct list_head *head, *p;
	struct nss_source *this;
	struct map_source *map;
	enum nsswitch_status status;
	unsigned int at_least_one = 0;
	int result = 0;

	/*
	 * For each map source (ie. each entry for the mount
	 * point in the master map) do the nss lookup to
	 * locate the map and read it.
	 */
	if (source)
		map = source;
	else
		map = entry->maps;
	while (map) {
		/* Is map source up to date or no longer valid */
		if (!map->stale || entry->age > map->age) {
			map = map->next;
			continue;
		}

		if (map->type) {
			if (!strncmp(map->type, "multi", 5))
				debug(ap->logopt, "reading multi map");
			else
				debug(ap->logopt,
				      "reading map %s %s",
				       map->type, map->argv[0]);
			result = lookup_map_read_map(ap, map, age);
			map = map->next;
			continue;
		}

		/* If it starts with a '/' it has to be a file or LDAP map */
		if (map->argv && *map->argv[0] == '/') {
			if (*(map->argv[0] + 1) == '/') {
				char *tmp = strdup("ldap");
				if (!tmp) {
					map = map->next;
					continue;
				}
				map->type = tmp;
				debug(ap->logopt,
				      "reading map %s %s", tmp, map->argv[0]);
				result = do_read_map(ap, map, age);
			} else {
				debug(ap->logopt,
				      "reading map file %s", map->argv[0]);
				result = read_file_source_instance(ap, map, age);
			}
			map = map->next;
			continue;
		}

		INIT_LIST_HEAD(&nsslist);

		pthread_cleanup_push(nsslist_cleanup, &nsslist);
		status = nsswitch_parse(&nsslist);
		pthread_cleanup_pop(0);
		if (status) {
			error(ap->logopt,
			      "can't to read name service switch config.");
			result = 1;
			break;
		}

		pthread_cleanup_push(nsslist_cleanup, &nsslist);
		head = &nsslist;
		list_for_each(p, head) {
			this = list_entry(p, struct nss_source, list);

			if (map->flags & MAP_FLAG_FORMAT_AMD &&
			    !strcmp(this->source, "sss")) {
				warn(ap->logopt,
				     "source sss is not available for amd maps.");
				continue;
			}

			debug(ap->logopt,
			      "reading map %s %s", this->source, map->argv[0]);

			result = read_map_source(this, ap, map, age);
			if (result == NSS_STATUS_UNKNOWN)
				continue;

			/* Don't try to update the map cache if it's unavailable */
			if (result == NSS_STATUS_UNAVAIL)
				map->stale = 0;

			if (result == NSS_STATUS_SUCCESS) {
				at_least_one = 1;
				result = NSS_STATUS_TRYAGAIN;
			}

			status = check_nss_result(this, result);
			if (status >= 0) {
				map = NULL;
				break;
			}

			result = NSS_STATUS_SUCCESS;
		}
		pthread_cleanup_pop(1);

		if (!map)
			break;

		map = map->next;
	}

	if (!result || at_least_one)
		return 1;

	return 0;
}

int lookup_ghost(struct autofs_point *ap, const char *root)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me;
	char buf[MAX_ERR_BUF];
	struct stat st;
	char *fullpath;
	int ret;

	if (!strcmp(ap->path, "/-"))
		return LKP_FAIL | LKP_DIRECT;

	if (!(ap->flags & MOUNT_FLAG_GHOST))
		return LKP_INDIRECT;

	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);
	map = entry->maps;
	while (map) {
		/*
		 * Only consider map sources that have been read since 
		 * the map entry was last updated.
		 */
		if (entry->age > map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_readlock(mc);
		me = cache_enumerate(mc, NULL);
		while (me) {
			/*
			 * Map entries that have been created in the cache
			 * due to a negative lookup shouldn't have directories
			 * created if they haven't already been created.
			 */
			if (!me->mapent)
				goto next;

			if (!strcmp(me->key, "*"))
				goto next;

			if (*me->key == '/') {
				/* It's a busy multi-mount - leave till next time */
				if (list_empty(&me->multi_list))
					error(ap->logopt,
					      "invalid key %s", me->key);
				goto next;
			}

			fullpath = malloc(strlen(me->key) + strlen(root) + 3);
			if (!fullpath) {
				warn(ap->logopt, "failed to allocate full path");
				goto next;
			}
			sprintf(fullpath, "%s/%s", root, me->key);

			ret = stat(fullpath, &st);
			if (ret == -1 && errno != ENOENT) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				warn(ap->logopt, "stat error %s", estr);
				free(fullpath);
				goto next;
			}

			ret = mkdir_path(fullpath, 0555);
			if (ret < 0 && errno != EEXIST) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				warn(ap->logopt,
				     "mkdir_path %s failed: %s", fullpath, estr);
				free(fullpath);
				goto next;
			}

			if (stat(fullpath, &st) != -1) {
				me->dev = st.st_dev;
				me->ino = st.st_ino;
			}

			free(fullpath);
next:
			me = cache_enumerate(mc, me);
		}
		pthread_cleanup_pop(1);
		map = map->next;
	}
	pthread_cleanup_pop(1);

	return LKP_INDIRECT;
}

int do_lookup_mount(struct autofs_point *ap, struct map_source *map, const char *name, int name_len)
{
	struct lookup_mod *lookup;
	int status;

	if (!map->lookup) {
		lookup = open_lookup(map->type, "",
				     map->format, map->argc, map->argv);
		if (!lookup) {
			debug(ap->logopt,
			      "lookup module %s failed", map->type);
			return NSS_STATUS_UNAVAIL;
		}
		map->lookup = lookup;
	}

	lookup = map->lookup;

	master_source_current_wait(ap->entry);
	ap->entry->current = map;

	status = lookup->lookup_mount(ap, name, name_len, lookup->context);

	return status;
}

static int lookup_amd_instance(struct autofs_point *ap,
			       struct map_source *map,
			       const char *name, int name_len)
{
	struct map_source *instance;
	struct amd_entry *entry;
	const char *argv[2];
	const char **pargv = NULL;
	int argc = 0;
	struct mapent *me;
	char *m_key;

	me = cache_lookup_distinct(map->mc, name);
	if (!me || !me->multi) {
		error(ap->logopt, "expected multi mount entry not found");
		return NSS_STATUS_UNKNOWN;
	}

	m_key = malloc(strlen(ap->path) + strlen(me->multi->key) + 1);
	if (!m_key) {
		error(ap->logopt,
		     "failed to allocate storage for search key");
		return NSS_STATUS_UNKNOWN;
	}

	strcpy(m_key, ap->path);
	strcat(m_key, "/");
	strcat(m_key, me->multi->key);
	entry = master_find_amdmount(ap, m_key);
	free(m_key);

	if (!entry) {
		error(ap->logopt, "expected amd mount entry not found");
		return NSS_STATUS_UNKNOWN;
	}

	if (strcmp(entry->type, "host")) {
		error(ap->logopt, "unexpected map type %s", entry->type);
		return NSS_STATUS_UNKNOWN;
	}

	if (entry->opts && *entry->opts) {
		argv[0] = entry->opts;
		argv[1] = NULL;
		pargv = argv;
		argc = 1;
	}

	instance = master_find_source_instance(map, "hosts", "sun", argc, pargv);
	/* If this is an nss map instance it may have an amd host map sub instance */
	if (!instance && map->instance) {
		struct map_source *next = map->instance;
		while (next) {
			instance = master_find_source_instance(next,
						"hosts", "sun", argc, pargv);
			if (instance)
				break;
			next = next->next;
		}
	}
	if (!instance) {
		error(ap->logopt, "expected hosts map instance not found");
		return NSS_STATUS_UNKNOWN;
	}

	return do_lookup_mount(ap, instance, name, name_len);
}

static int lookup_name_file_source_instance(struct autofs_point *ap, struct map_source *map, const char *name, int name_len)
{
	struct map_source *instance;
	char src_file[] = "file";
	char src_prog[] = "program";
	time_t age = time(NULL);
	struct stat st;
	char *type, *format;

	if (*name == '/' && map->flags & MAP_FLAG_FORMAT_AMD)
		return lookup_amd_instance(ap, map, name, name_len);

	if (stat(map->argv[0], &st) == -1) {
		debug(ap->logopt, "file map not found");
		return NSS_STATUS_NOTFOUND;
	}

	if (!S_ISREG(st.st_mode))
		return NSS_STATUS_NOTFOUND;

	if (st.st_mode & __S_IEXEC)
		type = src_prog;
	else
		type = src_file;

	format = map->format;

	instance = master_find_source_instance(map, type, format, 0, NULL);
	if (!instance) {
		int argc = map->argc;
		const char **argv = map->argv;
		instance = master_add_source_instance(map, type, format, age, argc, argv);
		if (!instance)
			return NSS_STATUS_NOTFOUND;
		instance->recurse = map->recurse;
		instance->depth = map->depth;
	}

	return do_lookup_mount(ap, instance, name, name_len);
}

static int lookup_name_source_instance(struct autofs_point *ap, struct map_source *map, const char *type, const char *name, int name_len)
{
	struct map_source *instance;
	const char *format;
	time_t age = time(NULL);

	if (*name == '/' && map->flags & MAP_FLAG_FORMAT_AMD)
		return lookup_amd_instance(ap, map, name, name_len);

	format = map->format;

	instance = master_find_source_instance(map, type, format, 0, NULL);
	if (!instance) {
		int argc = map->argc;
		const char **argv = map->argv;
		instance = master_add_source_instance(map, type, format, age, argc, argv);
		if (!instance)
			return NSS_STATUS_NOTFOUND;
		instance->recurse = map->recurse;
		instance->depth = map->depth;
	}

	return do_lookup_mount(ap, instance, name, name_len);
}

static int do_name_lookup_mount(struct autofs_point *ap,
				struct map_source *map,
				const char *name, int name_len)
{
	char *path;

	if (!map->argv[0]) {
		if (!strcmp(map->type, "hosts"))
			return do_lookup_mount(ap, map, name, name_len);
		return NSS_STATUS_UNKNOWN;
	}

	if (*name == '/' && map->flags & MAP_FLAG_FORMAT_AMD)
		return lookup_amd_instance(ap, map, name, name_len);

	/*
	 * This is only called when map->type != NULL.
	 * We only need to look for a map if source type is
	 * file and the map name doesn't begin with a "/".
	 */
	if (strncmp(map->type, "file", 4))
		return do_lookup_mount(ap, map, name, name_len);

	if (map->argv[0][0] == '/')
		return do_lookup_mount(ap, map, name, name_len);

	path = find_map_path(ap, map);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	if (map->argc >= 1) {
		if (map->argv[0])
			free((char *) map->argv[0]);
		map->argv[0] = path;
	} else {
		error(ap->logopt, "invalid arguments for autofs_point");
		free(path);
		return NSS_STATUS_UNKNOWN;
	}

	return do_lookup_mount(ap, map, name, name_len);
}

static enum nsswitch_status lookup_map_name(struct nss_source *this,
			struct autofs_point *ap, struct map_source *map,
			const char *name, int name_len)
{
	enum nsswitch_status result;
	struct map_source tmap;
	char *path;

	if (strcasecmp(this->source, "files"))
		return lookup_name_source_instance(ap, map,
					this->source, name, name_len);

	/* 
	 * autofs build-in map for nsswitch "files" is "file".
	 * This is a special case as we need to append the
	 * normal location to the map name.
	 * note: we consider it invalid to specify a relative
	 *       path.
	 */
	if (strchr(map->argv[0], '/')) {
		error(ap->logopt, "relative path invalid in files map name");
		return NSS_STATUS_NOTFOUND;
	}

	this->source[4] = '\0';
	tmap.flags = map->flags;
	tmap.type = this->source;
	tmap.format = map->format;
	tmap.name = map->name;
	tmap.mc = map->mc;
	tmap.instance = map->instance;
	tmap.exp_timeout = map->exp_timeout;
	tmap.recurse = map->recurse;
	tmap.depth = map->depth;
	tmap.argc = 0;
	tmap.argv = NULL;

	path = find_map_path(ap, map);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	if (map->argc >= 1) {
		tmap.argc = map->argc;
		tmap.argv = copy_argv(map->argc, map->argv);
		if (!tmap.argv) {
			error(ap->logopt, "failed to copy args");
			free(path);
			return NSS_STATUS_UNKNOWN;
		}
		if (tmap.argv[0])
			free((char *) tmap.argv[0]);
		tmap.argv[0] = path;
	} else {
		error(ap->logopt, "invalid arguments for autofs_point");
		free(path);
		return NSS_STATUS_UNKNOWN;
	}

	result = lookup_name_file_source_instance(ap, &tmap, name, name_len);

	map->instance = tmap.instance;

	/* path is freed in free_argv */
	free_argv(tmap.argc, tmap.argv);

	return result;
}

static void update_negative_cache(struct autofs_point *ap, struct map_source *source, const char *name)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent *me;

	/* Don't update negative cache for included maps */ 
	if (source && source->depth)
		return;

	/* Don't update the wildcard */
	if (strlen(name) == 1 && *name == '*')
		return;

	/* Have we recorded the lookup fail for negative caching? */
	me = lookup_source_mapent(ap, name, LKP_DISTINCT);
	if (me)
		/*
		 *  Already exists in the cache, the mount fail updates
		 *  will update negative timeout status.
		 */
		cache_unlock(me->mc);
	else {
		/* Notify only once after fail */
		logmsg("key \"%s\" not found in map source(s).", name);

		/* Doesn't exist in any source, just add it somewhere */
		if (source)
			map = source;
		else
			map = entry->maps;
		if (map) {
			time_t now = time(NULL);
			int rv = CHE_FAIL;

			cache_writelock(map->mc);
			me = cache_lookup_distinct(map->mc, name);
			if (me)
				rv = cache_push_mapent(me, NULL);
			else
				rv = cache_update(map->mc, map, name, NULL, now);
			if (rv != CHE_FAIL) {
				me = cache_lookup_distinct(map->mc, name);
				if (me)
					me->status = now + ap->negative_timeout;
			}
			cache_unlock(map->mc);
		}
	}
	return;
}

int lookup_nss_mount(struct autofs_point *ap, struct map_source *source, const char *name, int name_len)
{
	struct master_mapent *entry = ap->entry;
	struct list_head nsslist;
	struct list_head *head, *p;
	struct nss_source *this;
	struct map_source *map;
	enum nsswitch_status status;
	int result = 0;

	/*
	 * For each map source (ie. each entry for the mount
	 * point in the master map) do the nss lookup to
	 * locate the map and lookup the name.
	 */
	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);
	if (source)
		map = source;
	else
		map = entry->maps;
	while (map) {
		/*
		 * Only consider map sources that have been read since 
		 * the map entry was last updated.
		 */
		if (entry->age > map->age) {
			map = map->next;
			continue;
		}

		sched_yield();

		if (map->type) {
			result = do_name_lookup_mount(ap, map, name, name_len);
			if (result == NSS_STATUS_SUCCESS)
				break;

			map = map->next;
			continue;
		}

		/* If it starts with a '/' it has to be a file or LDAP map */
		if (*map->argv[0] == '/') {
			if (*(map->argv[0] + 1) == '/') {
				char *tmp = strdup("ldap");
				if (!tmp) {
					map = map->next;
					continue;
				}
				map->type = tmp;
				result = do_lookup_mount(ap, map, name, name_len);
			} else
				result = lookup_name_file_source_instance(ap, map, name, name_len);

			if (result == NSS_STATUS_SUCCESS)
				break;

			map = map->next;
			continue;
		}

		INIT_LIST_HEAD(&nsslist);

		status = nsswitch_parse(&nsslist);
		if (status) {
			error(ap->logopt,
			      "can't to read name service switch config.");
			result = 1;
			break;
		}

		head = &nsslist;
		list_for_each(p, head) {
			this = list_entry(p, struct nss_source, list);

			if (map->flags & MAP_FLAG_FORMAT_AMD &&
			    !strcmp(this->source, "sss")) {
				warn(ap->logopt,
				     "source sss is not available for amd maps.");
				continue;
			}

			result = lookup_map_name(this, ap, map, name, name_len);

			if (result == NSS_STATUS_UNKNOWN)
				continue;

			status = check_nss_result(this, result);
			if (status >= 0) {
				map = NULL;
				break;
			}
		}

		if (!list_empty(&nsslist))
			free_sources(&nsslist);

		if (!map)
			break;

		map = map->next;
	}
	if (ap->state != ST_INIT)
		send_map_update_request(ap);

	/*
	 * The last source lookup will return NSS_STATUS_NOTFOUND if the
	 * map exits and the key has not been found but the map may also
	 * not exist in which case the key is also not found.
	 */
	if (result == NSS_STATUS_NOTFOUND || result == NSS_STATUS_UNAVAIL)
		update_negative_cache(ap, source, name);
	pthread_cleanup_pop(1);

	return !result;
}

static void lookup_close_lookup_instances(struct map_source *map)
{
	struct map_source *instance;

	instance = map->instance;
	while (instance) {
		lookup_close_lookup_instances(instance);
		instance = instance->next;
	}

	if (map->lookup) {
		close_lookup(map->lookup);
		map->lookup = NULL;
	}
}

void lookup_close_lookup(struct autofs_point *ap)
{
	struct map_source *map;

	map = ap->entry->maps;
	if (!map)
		return;

	while (map) {
		lookup_close_lookup_instances(map);
		map = map->next;
	}

	return;
}

static char *make_fullpath(const char *root, const char *key)
{
	int l;
	char *path;

	if (*key == '/') {
		l = strlen(key) + 1;
		if (l > KEY_MAX_LEN)
			return NULL;
		path = malloc(l);
		if (!path)
			return NULL;
		strcpy(path, key);
	} else {
		l = strlen(key) + 1 + strlen(root) + 1;
		if (l > KEY_MAX_LEN)
			return NULL;
		path = malloc(l);
		if (!path)
			return NULL;
		sprintf(path, "%s/%s", root, key);
	}
	return path;
}

void lookup_prune_one_cache(struct autofs_point *ap, struct mapent_cache *mc, time_t age)
{
	struct mapent *me, *this;
	char *path;
	int status = CHE_FAIL;

	me = cache_enumerate(mc, NULL);
	while (me) {
		struct mapent *valid;
		char *key = NULL, *next_key = NULL;

		if (me->age >= age) {
			/*
			 * Reset time of last fail for valid map entries to
			 * force entry update and subsequent mount retry.
			 * A map entry that's still invalid after a read
			 * may have been created by a failed wildcard lookup
			 * so reset the status on those too.
			 */
			if (me->mapent || cache_lookup(mc, "*"))
				me->status = 0;
			me = cache_enumerate(mc, me);
			continue;
		}

		key = strdup(me->key);
		me = cache_enumerate(mc, me);
		if (!key || !strcmp(key, "*")) {
			if (key)
				free(key);
			continue;
		}

		path = make_fullpath(ap->path, key);
		if (!path) {
			warn(ap->logopt, "can't malloc storage for path");
			free(key);
			continue;
		}

		/*
		 * If this key has another valid entry we want to prune it,
		 * even if it's a mount, as the valid entry will take the
		 * mount if it is a direct mount or it's just a stale indirect
		 * cache entry.
		 */
		valid = lookup_source_valid_mapent(ap, key, LKP_DISTINCT);
		if (valid && valid->mc == mc) {
			 /*
			  * We've found a map entry that has been removed from
			  * the current cache so it isn't really valid.
			  */
			cache_unlock(valid->mc);
			valid = NULL;
		}
		if (!valid &&
		    is_mounted(_PATH_MOUNTED, path, MNTS_REAL)) {
			debug(ap->logopt,
			      "prune check posponed, %s mounted", path);
			free(key);
			free(path);
			continue;
		}
		if (valid)
			cache_unlock(valid->mc);

		if (me)
			next_key = strdup(me->key);

		cache_unlock(mc);

		cache_writelock(mc);
		this = cache_lookup_distinct(mc, key);
		if (!this) {
			cache_unlock(mc);
			goto next;
		}

		if (valid)
			cache_delete(mc, key);
		else if (!is_mounted(_PROC_MOUNTS, path, MNTS_AUTOFS)) {
			dev_t devid = ap->dev;
			status = CHE_FAIL;
			if (ap->type == LKP_DIRECT)
				devid = this->dev;
			if (this->ioctlfd == -1)
				status = cache_delete(mc, key);
			if (status != CHE_FAIL) {
				if (ap->type == LKP_INDIRECT) {
					if (ap->flags & MOUNT_FLAG_GHOST)
						rmdir_path(ap, path, devid);
				} else
					rmdir_path(ap, path, devid);
			}
		}
		cache_unlock(mc);

next:
		cache_readlock(mc);
		if (next_key) {
			me = cache_lookup_distinct(mc, next_key);
			free(next_key);
		}
		free(key);
		free(path);
	}

	return;
}

int lookup_prune_cache(struct autofs_point *ap, time_t age)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;

	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);

	map = entry->maps;
	while (map) {
		/* Is the map stale */
		if (!map->stale) {
			map = map->next;
			continue;
		}
		pthread_cleanup_push(cache_lock_cleanup, map->mc);
		cache_readlock(map->mc);
		lookup_prune_one_cache(ap, map->mc, age);
		pthread_cleanup_pop(1);
		clear_stale_instances(map);
		map->stale = 0;
		map = map->next;
	}

	pthread_cleanup_pop(1);

	return 1;
}

/* Return with cache readlock held */
struct mapent *lookup_source_valid_mapent(struct autofs_point *ap, const char *key, unsigned int type)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me = NULL;

	map = entry->maps;
	while (map) {
		/*
		 * Only consider map sources that have been read since
		 * the map entry was last updated.
		 */
		if (ap->entry->age > map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		cache_readlock(mc);
		if (type == LKP_DISTINCT)
			me = cache_lookup_distinct(mc, key);
		else
			me = cache_lookup(mc, key);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}

	return me;
}

/* Return with cache readlock held */
struct mapent *lookup_source_mapent(struct autofs_point *ap, const char *key, unsigned int type)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me = NULL;

	map = entry->maps;
	while (map) {
		mc = map->mc;
		cache_readlock(mc);
		if (type == LKP_DISTINCT)
			me = cache_lookup_distinct(mc, key);
		else
			me = cache_lookup(mc, key);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}

	if (me && me->mc != mc)
		error(LOGOPT_ANY, "mismatching mc in cache", me->key);

	return me;
}

int lookup_source_close_ioctlfd(struct autofs_point *ap, const char *key)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me;
	int ret = 0;

	map = entry->maps;
	while (map) {
		mc = map->mc;
		cache_readlock(mc);
		me = cache_lookup_distinct(mc, key);
		if (me) {
			if (me->ioctlfd != -1) {
				struct ioctl_ops *ops = get_ioctl_ops();
				ops->close(ap->logopt, me->ioctlfd);
				me->ioctlfd = -1;
			}
			cache_unlock(mc);
			ret = 1;
			break;
		}
		cache_unlock(mc);
		map = map->next;
	}

	return ret;
}

