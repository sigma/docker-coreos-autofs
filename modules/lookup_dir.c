/* ----------------------------------------------------------------------- *
 *
 *  lookup_dir.c - module for including master files in a directory.
 *
 * Copyright 2011 Red Hat, Inc. All rights reserved.
 * Copyright 2011 Masatake YAMATO <yamato@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 * USA; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <malloc.h>
#include <pwd.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>


#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MODPREFIX "lookup(dir): "

#define MAX_INCLUDE_DEPTH	16

#define AUTOFS_DIR_EXT ".autofs"
#define AUTOFS_DIR_EXTSIZ (sizeof(AUTOFS_DIR_EXT) - 1)

/* Work around non-GNU systems that don't provide versionsort */
#ifdef WITHOUT_VERSIONSORT
#define versionsort alphasort
#endif

struct lookup_context {
  const char *mapname;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */


int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];
	struct stat st;

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
		     "dir map %s is not an absolute pathname", argv[0]);
		return 1;
	}

	if (access(ctxt->mapname, R_OK)) {
		free(ctxt);
		warn(LOGOPT_NONE, MODPREFIX
		     "dir map %s missing or not readable", argv[0]);
		return 1;
	}

	if (stat(ctxt->mapname, &st)) {
		free(ctxt);
		warn(LOGOPT_NONE, MODPREFIX
		     "dir map %s, could not stat", argv[0]);
		return 1;
	}

	if ( (!S_ISDIR(st.st_mode)) && (!S_ISLNK(st.st_mode)) ) {
		free(ctxt);
		warn(LOGOPT_NONE, MODPREFIX
		     "dir map %s, is not a directory", argv[0]);
		return 1;
	}

	*context = ctxt;
	return 0;
}

static int acceptable_dirent_p(const struct dirent *e)
{
  size_t namesz;

  namesz = strlen(e->d_name);
  if (!namesz)
	  return 0;

  if (e->d_name[0] == '.')
	  return 0;

  if (namesz < AUTOFS_DIR_EXTSIZ + 1 ||
      strcmp(e->d_name + (namesz - AUTOFS_DIR_EXTSIZ),
	     AUTOFS_DIR_EXT))
	  return 0;

  return 1;
}


static int include_file(struct master *master, time_t age, struct lookup_context* ctxt, struct dirent *e)
{
	unsigned int logopt = master->logopt;
	char included_path[PATH_MAX + 1];
	int included_path_len;
	char *save_name;
	int status;

	included_path_len = snprintf(included_path,
				     PATH_MAX + 1,
				     "%s/%s",
				     ctxt->mapname,
				     e->d_name);
	if (included_path_len > PATH_MAX)
		return NSS_STATUS_NOTFOUND;

	save_name = master->name;
	master->name = included_path;

	master->depth++;
	debug(logopt, MODPREFIX "include: %s", master->name);
	status = lookup_nss_read_master(master, age);
	if (!status) {
		warn(logopt,
		     MODPREFIX
		     "failed to read included master map %s",
		     master->name);
	}
	master->depth--;

	master->name = save_name;
	return NSS_STATUS_SUCCESS;
}


int lookup_read_master(struct master *master, time_t age, void *context)
{
        int n, i;
	struct dirent **namelist = NULL;
	struct lookup_context *ctxt = (struct lookup_context *) context;
	unsigned int logopt = master->logopt;
	char buf[MAX_ERR_BUF];


	if (master->depth > MAX_INCLUDE_DEPTH) {
		error(logopt, MODPREFIX
		      "maximum include depth exceeded %s", master->name);
		return NSS_STATUS_UNAVAIL;
	}

	debug(logopt, MODPREFIX "scandir: %s", ctxt->mapname);
	n = scandir(ctxt->mapname, &namelist, acceptable_dirent_p, versionsort);
	if (n < 0) {
	       char *estr = strerror_r(errno, buf, MAX_ERR_BUF);

		error(logopt,
		      MODPREFIX "could not scan master map dir %s: %s",
		      ctxt->mapname,
		      estr);
		return NSS_STATUS_UNAVAIL;
	}

	for (i = 0; i < n; i++) {
		struct dirent *e = namelist[i];

		include_file(master, age, ctxt, e);
		free(e);
	}
	free(namelist);

	return NSS_STATUS_SUCCESS;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);
	return NSS_STATUS_UNKNOWN;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);
	return NSS_STATUS_UNKNOWN;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;

	free(ctxt);
	return 0;
}
