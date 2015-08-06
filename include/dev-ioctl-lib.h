/* ----------------------------------------------------------------------- *
 *
 *  dev-ioctl-lib.h - autofs device control.
 *
 *   Copyright 2008 Red Hat, Inc. All rights reserved.
 *   Copyright 2008 Ian Kent <raven@themaw.net>
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

#ifndef AUTOFS_DEV_IOCTL_LIB_H
#define AUTOFS_DEV_IOCTL_LIB_H

#include <linux/auto_dev-ioctl.h>

#define CONTROL_DEVICE  "/dev/autofs"

#define DEV_IOCTL_IS_MOUNTED	0x0001
#define DEV_IOCTL_IS_AUTOFS	0x0002
#define DEV_IOCTL_IS_OTHER	0x0004

struct ioctl_ctl {
	int devfd;
	struct ioctl_ops *ops;
};

struct ioctl_ops {
	int (*version)(unsigned int, int, struct autofs_dev_ioctl *);
	int (*protover)(unsigned int, int, unsigned int *);
	int (*protosubver)(unsigned int, int, unsigned int *);
	int (*mount_device)(unsigned int, const char *, unsigned int, dev_t *);
	int (*open)(unsigned int, int *, dev_t, const char *);
	int (*close)(unsigned int, int);
	int (*send_ready)(unsigned int, int, unsigned int);
	int (*send_fail)(unsigned int, int, unsigned int, int);
	int (*setpipefd)(unsigned int, int, int);
	int (*catatonic)(unsigned int, int);
	int (*timeout)(unsigned int, int, time_t);
	int (*requestor)(unsigned int, int, const char *, uid_t *, gid_t *);
	int (*expire)(unsigned int, int, const char *, unsigned int);
	int (*askumount)(unsigned int, int, unsigned int *);
	int (*ismountpoint)(unsigned int, int, const char *, unsigned int *);
};

void init_ioctl_ctl(void);
void close_ioctl_ctl(void);
struct ioctl_ops *get_ioctl_ops(void);
struct autofs_dev_ioctl *alloc_ioctl_ctl_open(const char *, unsigned int);
void free_ioctl_ctl_open(struct autofs_dev_ioctl *);

#endif

