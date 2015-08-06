/* ----------------------------------------------------------------------- *
 *   
 *  lookup_userhome.c - module for Linux automount to generate symlinks
 *                      to user home directories
 *
 *   Copyright 1999 Transmeta Corporation - All Rights Reserved
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
#include <pwd.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MODPREFIX "lookup(userhome): "

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	return 0;		/* Nothing to do */
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

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct map_source *source;
	struct mapent_cache *mc;
	struct passwd *pw;
	char buf[MAX_ERR_BUF];
	int ret;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	debug(ap->logopt, MODPREFIX "looking up %s", name);

	/* Get the equivalent username */
	pw = getpwnam(name);
	if (!pw) {
		warn(ap->logopt, MODPREFIX "not found: %s", name);
		return NSS_STATUS_NOTFOUND;	/* Unknown user or error */
	}

	/* Create the appropriate symlink */
	if (chdir(ap->path)) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "chdir failed: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}

	cache_writelock(mc);
	ret = cache_update(mc, source, name, NULL, time(NULL));
	cache_unlock(mc);

	if (ret == CHE_FAIL) {
		ret = chdir("/");
		return NSS_STATUS_UNAVAIL;
	}

	if (symlink(pw->pw_dir, name) && errno != EEXIST) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "symlink failed: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}

	ret = chdir("/");

	return NSS_STATUS_SUCCESS;
}

int lookup_done(void *context)
{
	return 0;
}
