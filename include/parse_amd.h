/* ----------------------------------------------------------------------- *
 *
 *  Copyright 2004-2006 Ian Kent <raven@themaw.net>
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

#ifndef PARSE_AMD_H
#define PARSE_AMD_H

#define AMD_MOUNT_TYPE_NONE	0x00000000
#define AMD_MOUNT_TYPE_AUTO	0x00000001
#define AMD_MOUNT_TYPE_NFS	0x00000002
#define AMD_MOUNT_TYPE_LINK	0x00000004
#define AMD_MOUNT_TYPE_HOST	0x00000008
#define AMD_MOUNT_TYPE_NFSL	0x00000010
#define AMD_MOUNT_TYPE_NFSX	0x00000020
#define AMD_MOUNT_TYPE_LINKX	0x00000040
#define AMD_MOUNT_TYPE_LOFS	0x00000080
#define AMD_MOUNT_TYPE_EXT	0x00000100
#define AMD_MOUNT_TYPE_UFS	0x00000200
#define AMD_MOUNT_TYPE_XFS	0x00000400
#define AMD_MOUNT_TYPE_JFS	0x00000800
#define AMD_MOUNT_TYPE_CACHEFS	0x00001000
#define AMD_MOUNT_TYPE_CDFS	0x00002000
#define AMD_MOUNT_TYPE_MASK	0x0000ffff

#define AMD_ENTRY_CUT		0x00010000
#define AMD_ENTRY_MASK		0x00ff0000

#define AMD_DEFAULTS_MERGE	0x01000000
#define AMD_DEFAULTS_RESET	0x02000000
#define AMD_DEFAULTS_MASK	0xff000000

struct amd_entry {
	char *path;
	unsigned long flags;
	char *type;
	char *map_type;
	char *pref;
	char *fs;
	char *rhost;
	char *rfs;
	char *dev;
	char *opts;
	char *addopts;
	char *remopts;
	char *sublink;
	struct selector *selector;
	struct list_head list;
	struct list_head entries;
	struct list_head ext_mount;
};

int amd_parse_list(struct autofs_point *,
		   const char *, struct list_head *, struct substvar **);

#endif
