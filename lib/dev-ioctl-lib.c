/* ----------------------------------------------------------------------- *
 *
 *  ctl-dev-lib.c - module for Linux automount mount table lookup functions
 *
 *  Copyright 2008 Red Hat, Inc. All rights reserved.
 *  Copyright 2008 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *  USA; either version 2 of the License, or (at your option) any later
 *  version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/vfs.h>

#include "automount.h"

/* ioctld control function interface */
static struct ioctl_ctl ctl = { -1, NULL };

#ifndef AUTOFS_SUPER_MAGIC
#define AUTOFS_SUPER_MAGIC      0x0187
#endif

/*
 * Define functions for autofs ioctl control.
 *
 * We provide two interfaces. One which routes ioctls via a
 * miscelaneous device node and can be used to obtain an ioctl
 * file descriptor for autofs mounts that are covered by an
 * active mount (eg. active direct or multi-mount offsets).
 * The other provides the traditional autofs ioctl implementation.
 *
 * The miscielaneous device control functions are prefixed with
 * dev_ctl_ and the traditional ones are prefixed with ioctl_.
 */
static int dev_ioctl_version(unsigned int, int, struct autofs_dev_ioctl *);
static int dev_ioctl_protover(unsigned int, int, unsigned int *);
static int dev_ioctl_protosubver(unsigned int, int, unsigned int *);
static int dev_ioctl_mount_device(unsigned int, const char *, unsigned int, dev_t *);
static int dev_ioctl_open(unsigned int, int *, dev_t, const char *);
static int dev_ioctl_close(unsigned int, int);
static int dev_ioctl_send_ready(unsigned int, int, unsigned int);
static int dev_ioctl_send_fail(unsigned int, int, unsigned int, int);
static int dev_ioctl_setpipefd(unsigned int, int, int);
static int dev_ioctl_catatonic(unsigned int, int);
static int dev_ioctl_timeout(unsigned int, int, time_t);
static int dev_ioctl_requestor(unsigned int, int, const char *, uid_t *, gid_t *);
static int dev_ioctl_expire(unsigned int, int, const char *, unsigned int);
static int dev_ioctl_askumount(unsigned int, int, unsigned int *);
static int dev_ioctl_ismountpoint(unsigned int, int, const char *, unsigned int *);

static int ioctl_protover(unsigned int, int, unsigned int *);
static int ioctl_protosubver(unsigned int, int, unsigned int *);
static int ioctl_mount_device(unsigned int, const char *, unsigned int, dev_t *);
static int ioctl_open(unsigned int, int *, dev_t, const char *);
static int ioctl_close(unsigned int, int);
static int ioctl_send_ready(unsigned int, int, unsigned int);
static int ioctl_send_fail(unsigned int, int, unsigned int, int);
static int ioctl_catatonic(unsigned int, int);
static int ioctl_timeout(unsigned int, int, time_t);
static int ioctl_expire(unsigned int, int, const char *, unsigned int);
static int ioctl_askumount(unsigned int, int, unsigned int *);

static struct ioctl_ops dev_ioctl_ops = {
	.version	= dev_ioctl_version,
	.protover	= dev_ioctl_protover,
	.protosubver	= dev_ioctl_protosubver,
	.mount_device	= dev_ioctl_mount_device,
	.open		= dev_ioctl_open,
	.close		= dev_ioctl_close,
	.send_ready	= dev_ioctl_send_ready,
	.send_fail	= dev_ioctl_send_fail,
	.setpipefd	= dev_ioctl_setpipefd,
	.catatonic	= dev_ioctl_catatonic,
	.timeout	= dev_ioctl_timeout,
	.requestor	= dev_ioctl_requestor,
	.expire		= dev_ioctl_expire,
	.askumount	= dev_ioctl_askumount,
	.ismountpoint	= dev_ioctl_ismountpoint
};

static struct ioctl_ops ioctl_ops = {
	.version	= NULL,
	.protover	= ioctl_protover,
	.protosubver	= ioctl_protosubver,
	.mount_device	= ioctl_mount_device,
	.open		= ioctl_open,
	.close		= ioctl_close,
	.send_ready	= ioctl_send_ready,
	.send_fail	= ioctl_send_fail,
	.setpipefd	= NULL,
	.catatonic	= ioctl_catatonic,
	.timeout	= ioctl_timeout,
	.requestor	= NULL,
	.expire		= ioctl_expire,
	.askumount	= ioctl_askumount,
	.ismountpoint	= NULL
};

/*
 * Allocate the control struct that holds the misc device file
 * descriptor and operation despatcher table.
 */
void init_ioctl_ctl(void)
{
	int devfd;

	if (ctl.ops)
		return;

	devfd = open_fd(CONTROL_DEVICE, O_RDONLY);
	if (devfd == -1)
		ctl.ops = &ioctl_ops;
	else {
		struct autofs_dev_ioctl param;

		/*
		 * Check compile version against kernel.
		 * Selinux may allow us to open the device but not
		 * actually allow us to do anything.
		 */
		init_autofs_dev_ioctl(&param);
		if (ioctl(devfd, AUTOFS_DEV_IOCTL_VERSION, &param) == -1) {
			close(devfd);
			ctl.ops = &ioctl_ops;
		} else {
			ctl.devfd = devfd;
			ctl.ops = &dev_ioctl_ops;
		}
	}
	return;
}

void close_ioctl_ctl(void)
{
	if (ctl.devfd != -1) {
		close(ctl.devfd);
		ctl.devfd = -1;
	}
	ctl.ops = NULL;
	return;
}

/* Return a pointer to the operations control struct */
struct ioctl_ops *get_ioctl_ops(void)
{
	if (!ctl.ops)
		init_ioctl_ctl();
	return ctl.ops;
}

/* Get kenrel version of misc device code */
static int dev_ioctl_version(unsigned int logopt,
			     int ioctlfd, struct autofs_dev_ioctl *param)
{
	param->ioctlfd = ioctlfd;

	if (ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_VERSION, param) == -1)
		return -1;

	return 0;
}

/* Get major version of autofs kernel module mount protocol */
static int dev_ioctl_protover(unsigned int logopt,
			      int ioctlfd, unsigned int *major)
{
	struct autofs_dev_ioctl param;

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = ioctlfd;

	if (ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_PROTOVER, &param) == -1)
		return -1;

	*major = param.protover.version;

	return 0;
}

static int ioctl_protover(unsigned int logopt,
			  int ioctlfd, unsigned int *major)
{
	return ioctl(ioctlfd, AUTOFS_IOC_PROTOVER, major);
}

/* Get minor version of autofs kernel module mount protocol */
static int dev_ioctl_protosubver(unsigned int logopt,
				 int ioctlfd, unsigned int *minor)
{
	struct autofs_dev_ioctl param;

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = ioctlfd;

	if (ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_PROTOSUBVER, &param) == -1)
		return -1;

	*minor = param.protosubver.sub_version;

	return 0;
}

static int ioctl_protosubver(unsigned int logopt,
			     int ioctlfd, unsigned int *minor)
{
	return ioctl(ioctlfd, AUTOFS_IOC_PROTOSUBVER, minor);
}

/*
 * Allocate a parameter struct for misc device ioctl used when
 * opening an autofs mount point. Attach the path to the end
 * of the struct. and lookup the device number if not given.
 * Locating the device number relies on the mount option
 * "dev=<device number>" being present in the autofs fs mount
 * options.
 */
static struct autofs_dev_ioctl *alloc_dev_ioctl_open(const char *path, dev_t devid)
{
	struct autofs_dev_ioctl *ioctl;
	size_t size, p_len;
	dev_t devno = devid;

	if (!path)
		return NULL;

	p_len = strlen(path);
	size = sizeof(struct autofs_dev_ioctl) + p_len + 1;
	ioctl = malloc(size);
	if (!ioctl) {
		errno = ENOMEM;
		return NULL;
	}

	init_autofs_dev_ioctl(ioctl);
	ioctl->size = size;
	memcpy(ioctl->path, path, p_len);
	ioctl->path[p_len] = '\0';
	ioctl->openmount.devid = devno;

	return ioctl;
}

static void free_dev_ioctl_open(struct autofs_dev_ioctl *ioctl)
{
	free(ioctl);
	return;
}

/*
 * Allocate a parameter struct for misc device ioctl which includes
 * a path. This is used when getting the last mount requestor uid
 * and gid and when checking if a path within the autofs filesystem
 * is a mount point. We add the path to the end of the struct.
 */
static struct autofs_dev_ioctl *alloc_dev_ioctl_path(int ioctlfd, const char *path)
{
	struct autofs_dev_ioctl *ioctl;
	size_t size, p_len;

	if (!path) {
		errno = EINVAL;
		return NULL;
	}

	p_len = strlen(path);
	size = sizeof(struct autofs_dev_ioctl) + p_len + 1;
	ioctl = malloc(size);
	if (!ioctl) {
		errno = ENOMEM;
		return NULL;
	}

	init_autofs_dev_ioctl(ioctl);
	ioctl->ioctlfd = ioctlfd;
	ioctl->size = size;
	memcpy(ioctl->path, path, p_len);
	ioctl->path[p_len] = '\0';

	return ioctl;
}

static void free_dev_ioctl_path(struct autofs_dev_ioctl *ioctl)
{
	free(ioctl);
	return;
}

/*
 * Find the device number of an autofs mount with given path and
 * type (eg..AUTOFS_TYPE_DIRECT). The device number is used by
 * the kernel to identify the autofs super block when searching
 * for the mount.
 */
static int dev_ioctl_mount_device(unsigned int logopt, const char *path, unsigned int type, dev_t *devid)
{
	struct autofs_dev_ioctl *param;
	int err;

	if (!path) {
		errno = EINVAL;
		return -1;
	}

	*devid = -1;

	param = alloc_dev_ioctl_path(-1, path);
	if (!param)
		return -1;
	param->ismountpoint.in.type = type;

	err = ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_ISMOUNTPOINT, param);
	if (err == -1) {
		int save_errno = errno;
		free_dev_ioctl_path(param);
		errno = save_errno;
		return -1;
	}

	if (err)
		*devid = param->ismountpoint.out.devid;

	free_dev_ioctl_path(param);

	return err;
}

static int ioctl_mount_device(unsigned int logopt,
			      const char *path, unsigned int type,
			      dev_t *devid)
{
	return -1;
}

/* Get a file descriptor for control operations */
static int dev_ioctl_open(unsigned int logopt,
			  int *ioctlfd, dev_t devid, const char *path)
{
	struct autofs_dev_ioctl *param;

	*ioctlfd = -1;

	param = alloc_dev_ioctl_open(path, devid);
	if (!param)
		return -1;

	if (ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_OPENMOUNT, param) == -1) {
		int save_errno = errno;
		free_dev_ioctl_open(param);
		errno = save_errno;
		return -1;
	}

	*ioctlfd = param->ioctlfd;

	free_dev_ioctl_open(param);

	return 0;
}

static int ioctl_open(unsigned int logopt,
		      int *ioctlfd, dev_t devid, const char *path)
{
	struct statfs sfs;
	int save_errno, fd;

	*ioctlfd = -1;

	fd = open_fd(path, O_RDONLY);
	if (fd == -1)
		return -1;

	if (fstatfs(fd, &sfs) == -1) {
		save_errno = errno;
		goto err;
	}

	if (sfs.f_type != AUTOFS_SUPER_MAGIC) {
		save_errno = ENOENT;
		goto err;
	}

	*ioctlfd = fd;

	return 0;
err:
	close(fd);
	errno = save_errno;
	return -1;
}

/* Close */
static int dev_ioctl_close(unsigned int logopt, int ioctlfd)
{
	struct autofs_dev_ioctl param;

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = ioctlfd;

	if (ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_CLOSEMOUNT, &param) == -1)
		return -1;

	return 0;
}

static int ioctl_close(unsigned int logopt, int ioctlfd)
{
	return close(ioctlfd);
}

/* Send ready status for given token */
static int dev_ioctl_send_ready(unsigned int logopt,
				int ioctlfd, unsigned int token)
{
	struct autofs_dev_ioctl param;

	if (token == 0) {
		errno = EINVAL;
		return -1;
	}

	debug(logopt, "token = %d", token);

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = ioctlfd;
	param.ready.token = token;

	if (ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_READY, &param) == -1) {
		char *estr, buf[MAX_ERR_BUF];
		int save_errno = errno;
		estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("AUTOFS_DEV_IOCTL_READY: error %s", estr);
		errno = save_errno;
		return -1;
	}
	return 0;
}

static int ioctl_send_ready(unsigned int logopt,
			    int ioctlfd, unsigned int token)
{
	if (token == 0) {
		errno = EINVAL;
		return -1;
	}

	debug(logopt, "token = %d", token);

	if (ioctl(ioctlfd, AUTOFS_IOC_READY, token) == -1) {
		char *estr, buf[MAX_ERR_BUF];
		int save_errno = errno;
		estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("AUTOFS_IOC_READY: error %s", estr);
		errno = save_errno;
		return -1;
	}
	return 0;
}

/*
 * Send ready status for given token.
 *
 * The device node ioctl implementation allows for sending a status
 * of other than ENOENT, unlike the tradional interface.
 */
static int dev_ioctl_send_fail(unsigned int logopt,
			       int ioctlfd, unsigned int token, int status)
{
	struct autofs_dev_ioctl param;

	if (token == 0) {
		errno = EINVAL;
		return -1;
	}

	debug(logopt, "token = %d", token);

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = ioctlfd;
	param.fail.token = token;
	param.fail.status = status;

	if (ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_FAIL, &param) == -1) {
		char *estr, buf[MAX_ERR_BUF];
		int save_errno = errno;
		estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("AUTOFS_DEV_IOCTL_FAIL: error %s", estr);
		errno = save_errno;
		return -1;
	}
	return 0;
}

static int ioctl_send_fail(unsigned int logopt,
			   int ioctlfd, unsigned int token, int status)
{
	if (token == 0) {
		errno = EINVAL;
		return -1;
	}

	debug(logopt, "token = %d", token);

	if (ioctl(ioctlfd, AUTOFS_IOC_FAIL, token) == -1) {
		char *estr, buf[MAX_ERR_BUF];
		int save_errno = errno;
		estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("AUTOFS_IOC_FAIL: error %s", estr);
		errno = save_errno;
		return -1;
	}
	return 0;
}

/*
 * Set the pipe fd for kernel communication.
 *
 * Normally this is set at mount using an option but if we
 * are reconnecting to a busy mount then we need to use this
 * to tell the autofs kernel module about the new pipe fd. In
 * order to protect mounts against incorrectly setting the
 * pipefd we also require that the autofs mount be catatonic.
 *
 * If successful this also sets the process group id used to
 * identify the controlling process to the process group of
 * the caller.
 */
static int dev_ioctl_setpipefd(unsigned int logopt, int ioctlfd, int pipefd)
{
	struct autofs_dev_ioctl param;

	if (pipefd == -1) {
		errno = EBADF;
		return -1;
	}

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = ioctlfd;
	param.setpipefd.pipefd = pipefd;

	if (ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_SETPIPEFD, &param) == -1)
		return -1;

	return 0;
}

/*
 * Make the autofs mount point catatonic, no longer responsive to
 * mount requests. Also closes the kernel pipe file descriptor.
 */
static int dev_ioctl_catatonic(unsigned int logopt, int ioctlfd)
{
	struct autofs_dev_ioctl param;

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = ioctlfd;

	if (ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_CATATONIC, &param) == -1)
		return -1;

	return 0;
}

static int ioctl_catatonic(unsigned int logopt, int ioctlfd)
{
	return ioctl(ioctlfd, AUTOFS_IOC_CATATONIC, 0);
}

/* Set the autofs mount timeout */
static int dev_ioctl_timeout(unsigned int logopt, int ioctlfd, time_t timeout)
{
	struct autofs_dev_ioctl param;

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = ioctlfd;
	param.timeout.timeout = timeout;

	if (ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_TIMEOUT, &param) == -1)
		return -1;

	return 0;
}

static int ioctl_timeout(unsigned int logopt, int ioctlfd, time_t timeout)
{
	time_t tout = timeout;
	return ioctl(ioctlfd, AUTOFS_IOC_SETTIMEOUT, &tout);
}

/*
 * Get the uid and gid of the last request for the mountpoint, path.
 *
 * When reconstructing an autofs mount tree with active mounts
 * we need to re-connect to mounts that may have used the original
 * process uid and gid (or string variations of them) for mount
 * lookups within the map entry.
 */
static int dev_ioctl_requestor(unsigned int logopt,
			       int ioctlfd, const char *path,
			       uid_t *uid, gid_t *gid)
{
	struct autofs_dev_ioctl *param;
	int err;

	if (!path)
		errno = EINVAL;

	*uid = -1;
	*gid = -1;


	param = alloc_dev_ioctl_path(ioctlfd, path);
	if (!param)
		return -1;

	err = ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_REQUESTER, param);
	if (err == -1) {
		int save_errno = errno;
		free_dev_ioctl_open(param);
		errno = save_errno;
		return -1;
	}

	*uid = param->requester.uid;
	*gid = param->requester.gid;

	free_dev_ioctl_path(param);

	return 0;
}

/*
 * Call repeatedly until it returns EAGAIN, meaning there's nothing
 * more that can be done.
 */
static int expire(unsigned int logopt,
		  int cmd, int fd, int ioctlfd, const char *path, void *arg)
{
	int ret, retries = EXPIRE_RETRIES;
	unsigned int may_umount;

	while (retries--) {
		struct timespec tm = {0, 100000000};

		/* Ggenerate expire message for the mount. */
		ret = ioctl(fd, cmd, arg);
		if (ret == -1) {
			/* Mount has gone away */
			if (errno == EBADF || errno == EINVAL)
				return 0;

			/*
			 * Other than EAGAIN is an expire error so continue.
			 * Kernel will try the next mount for indirect maps
			 * and the same mount again for direct maps, limited
			 * by retries.
			 */
			if (errno == EAGAIN)
				break;
		}
		nanosleep(&tm, NULL);
	}

	may_umount = 0;
	if (ctl.ops->askumount(logopt, ioctlfd, &may_umount))
		return -1;

	if (!may_umount)
		return 1;

	return 0;
}

static int dev_ioctl_expire(unsigned int logopt,
			    int ioctlfd, const char *path, unsigned int when)
{
	struct autofs_dev_ioctl param;

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = ioctlfd;
	param.expire.how = when;

	return expire(logopt, AUTOFS_DEV_IOCTL_EXPIRE,
		      ctl.devfd, ioctlfd, path, (void *) &param);
}

static int ioctl_expire(unsigned int logopt,
		        int ioctlfd, const char *path, unsigned int when)
{
	return expire(logopt, AUTOFS_IOC_EXPIRE_MULTI,
		      ioctlfd, ioctlfd, path, (void *) &when);
}

/* Check if autofs mount point is in use */
static int dev_ioctl_askumount(unsigned int logopt,
			       int ioctlfd, unsigned int *busy)
{
	struct autofs_dev_ioctl param;

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = ioctlfd;

	if (ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_ASKUMOUNT, &param) == -1)
		return -1;

	*busy = param.askumount.may_umount;

	return 0;
}

static int ioctl_askumount(unsigned int logopt,
			   int ioctlfd, unsigned int *busy)
{
	return ioctl(ioctlfd, AUTOFS_IOC_ASKUMOUNT, busy);
}

/*
 * Check if the given path is a mountpoint.
 *
 * The path is considered a mountpoint if it is itself a mountpoint
 * or contains a mount, such as a multi-mount without a root mount.
 * In addition, if the path is itself a mountpoint we return whether
 * the mounted file system is an autofs filesystem or other file
 * system.
 */
static int dev_ioctl_ismountpoint(unsigned int logopt,
				  int ioctlfd, const char *path,
				  unsigned int *mountpoint)
{
	struct autofs_dev_ioctl *param;
	int err;

	*mountpoint = 0;

	if (!path) {
		errno = EINVAL;
		return -1;
	}

	param = alloc_dev_ioctl_path(ioctlfd, path);
	if (!param)
		return -1;
	set_autofs_type_any(&param->ismountpoint.in.type);

	err = ioctl(ctl.devfd, AUTOFS_DEV_IOCTL_ISMOUNTPOINT, param);
	if (err == -1) {
		int save_errno = errno;
		free_dev_ioctl_path(param);
		errno = save_errno;
		return -1;
	}

	if (err) {
		*mountpoint = DEV_IOCTL_IS_MOUNTED;

		if (param->ismountpoint.out.magic == AUTOFS_SUPER_MAGIC)
			*mountpoint |= DEV_IOCTL_IS_AUTOFS;
		else
			*mountpoint |= DEV_IOCTL_IS_OTHER;
	}

	free_dev_ioctl_path(param);

	return 0;
}
