/*
 * mount_afs.c
 *
 * Module for Linux automountd to "mount" AFS filesystems.  We don't bother
 * with any of the things "attach" would do (making sure there are tokens,
 * subscribing to ops messages if Zephyr is installed), but it works for me.
 *
 */

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_MOUNT
#include "automount.h"

#define MODPREFIX "mount(afs): "
int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

int mount_init(void **context)
{
	return 0;
}

int mount_mount(struct autofs_point *ap, const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options, void *context)
{
	/* PATH_MAX is allegedly longest path allowed */
	char dest[PATH_MAX + 1];
	size_t r_len = strlen(root);
	size_t d_len = r_len + name_len + 2;

	if (ap->flags & MOUNT_FLAG_REMOUNT)
		return 0;

	if (d_len > PATH_MAX)
		return 1;

	/* Convert the name to a mount point. */
	strcpy(dest, root);
	strcat(dest, "/");
	strcat(dest, name);

	/* remove trailing slash (http://bugs.debian.org/141775) */
	if (dest[strlen(dest)-1] == '/')
	    dest[strlen(dest)-1] = '\0';

	debug(ap->logopt, MODPREFIX "mounting AFS %s -> %s", dest, what);

	return symlink(what, dest);	/* Try it.  If it fails, return the error. */
}

int mount_done(void *context)
{
	return 0;
}
