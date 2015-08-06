/* ----------------------------------------------------------------------- *
 *
 *  direct.c - Linux automounter direct mount handling
 *   
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *   Copyright 2001-2005 Ian Kent <raven@themaw.net>
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

#include <dirent.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sched.h>

#define INCLUDE_PENDING_FUNCTIONS
#include "automount.h"

/* Attribute to create detached thread */
extern pthread_attr_t th_attr_detached;

struct mnt_params {
	char *options;
};

pthread_key_t key_mnt_direct_params;
pthread_key_t key_mnt_offset_params;
pthread_once_t key_mnt_params_once = PTHREAD_ONCE_INIT;

static void key_mnt_params_destroy(void *arg)
{
	struct mnt_params *mp;

	mp = (struct mnt_params *) arg;
	if (mp->options)
		free(mp->options);
	free(mp);
	return;
}

static void key_mnt_params_init(void)
{
	int status;

	status = pthread_key_create(&key_mnt_direct_params, key_mnt_params_destroy);
	if (status)
		fatal(status);

	status = pthread_key_create(&key_mnt_offset_params, key_mnt_params_destroy);
	if (status)
		fatal(status);

	return;
}

static void mnts_cleanup(void *arg)
{
	struct mnt_list *mnts = (struct mnt_list *) arg;
	tree_free_mnt_tree(mnts);
	return;
}

int do_umount_autofs_direct(struct autofs_point *ap, struct mnt_list *mnts, struct mapent *me)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	char buf[MAX_ERR_BUF];
	int ioctlfd = -1, rv, left, retries;
	int opened = 0;

	left = umount_multi(ap, me->key, 0);
	if (left) {
		warn(ap->logopt, "could not unmount %d dirs under %s",
		     left, me->key);
		return 1;
	}

	if (me->ioctlfd != -1) {
		if (tree_is_mounted(mnts, me->key, MNTS_REAL)) {
			error(ap->logopt,
			      "attempt to umount busy direct mount %s",
			      me->key);
			return 1;
		}
		ioctlfd = me->ioctlfd;
	} else {
		ops->open(ap->logopt, &ioctlfd, me->dev, me->key);
		opened = 1;
	}

	if (ioctlfd >= 0) {
		unsigned int status = 1;

		rv = ops->askumount(ap->logopt, ioctlfd, &status);
		if (rv) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, "ioctl failed: %s", estr);
			if (opened && ioctlfd != -1)
				ops->close(ap->logopt, ioctlfd);
			return 1;
		} else if (!status) {
			if (ap->state != ST_SHUTDOWN_FORCE) {
				error(ap->logopt,
				      "ask umount returned busy for %s",
				      me->key);
				if (opened && ioctlfd != -1)
					ops->close(ap->logopt, ioctlfd);
				return 1;
			} else {
				me->ioctlfd = -1;
				ops->catatonic(ap->logopt, ioctlfd);
				ops->close(ap->logopt, ioctlfd);
				goto force_umount;
			}
		}
		me->ioctlfd = -1;
		ops->catatonic(ap->logopt, ioctlfd);
		ops->close(ap->logopt, ioctlfd);
	} else {
		error(ap->logopt,
		      "couldn't get ioctl fd for direct mount %s", me->key);
		return 1;
	}

	sched_yield();

	retries = UMOUNT_RETRIES;
	while ((rv = umount(me->key)) == -1 && retries--) {
		struct timespec tm = {0, 200000000};
		if (errno != EBUSY)
			break;
		nanosleep(&tm, NULL);
	}

	if (rv == -1) {
		switch (errno) {
		case ENOENT:
		case EINVAL:
			warn(ap->logopt, "mount point %s does not exist",
			      me->key);
			return 0;
			break;
		case EBUSY:
			warn(ap->logopt, "mount point %s is in use", me->key);
			if (ap->state == ST_SHUTDOWN_FORCE)
				goto force_umount;
			else
				return 0;
			break;
		case ENOTDIR:
			error(ap->logopt, "mount point is not a directory");
			return 0;
			break;
		}
		return 1;
	}

force_umount:
	if (rv != 0) {
		info(ap->logopt, "forcing umount of direct mount %s", me->key);
		rv = umount2(me->key, MNT_DETACH);
	} else
		info(ap->logopt, "umounted direct mount %s", me->key);

	if (!rv && me->flags & MOUNT_FLAG_DIR_CREATED) {
		if  (rmdir(me->key) == -1) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn(ap->logopt, "failed to remove dir %s: %s",
			     me->key, estr);
		}
	}
	return rv;
}

int umount_autofs_direct(struct autofs_point *ap)
{
	struct map_source *map;
	struct mapent_cache *nc, *mc;
	struct mnt_list *mnts;
	struct mapent *me, *ne;

	mnts = tree_make_mnt_tree(_PROC_MOUNTS, "/");
	pthread_cleanup_push(mnts_cleanup, mnts);
	nc = ap->entry->master->nc;
	cache_readlock(nc);
	pthread_cleanup_push(cache_lock_cleanup, nc);
	map = ap->entry->maps;
	while (map) {
		mc = map->mc;
		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_readlock(mc);
		me = cache_enumerate(mc, NULL);
		while (me) {
			ne = cache_lookup_distinct(nc, me->key);
			if (ne && map->master_line > ne->age) {
				me = cache_enumerate(mc, me);
				continue;
			}

			/* TODO: check return, locking me */
			do_umount_autofs_direct(ap, mnts, me);

			me = cache_enumerate(mc, me);
		}
		pthread_cleanup_pop(1);
		map = map->next;
	}
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	close(ap->state_pipe[0]);
	close(ap->state_pipe[1]);
	if (ap->pipefd >= 0)
		close(ap->pipefd);
	if (ap->kpipefd >= 0) {
		close(ap->kpipefd);
		ap->kpipefd = -1;
	}

	return 0;
}

static int unlink_mount_tree(struct autofs_point *ap, struct list_head *list)
{
	struct list_head *p;
	int rv, ret;
	pid_t pgrp = getpgrp();
	char spgrp[20];

	sprintf(spgrp, "pgrp=%d", pgrp);

	ret = 1;
	list_for_each(p, list) {
		struct mnt_list *mnt;

		mnt = list_entry(p, struct mnt_list, list);

		if (strstr(mnt->opts, spgrp))
			continue;

		if (strcmp(mnt->fs_type, "autofs"))
			rv = spawn_umount(ap->logopt, "-l", mnt->path, NULL);
		else
			rv = umount2(mnt->path, MNT_DETACH);
		if (rv == -1) {
			debug(ap->logopt,
			      "can't unlink %s from mount tree", mnt->path);

			switch (errno) {
			case EINVAL:
				warn(ap->logopt,
				      "bad superblock or not mounted");
				break;

			case ENOENT:
			case EFAULT:
				ret = 0;
				warn(ap->logopt, "bad path for mount");
				break;
			}
		}
	}
	return ret;
}

static int unlink_active_mounts(struct autofs_point *ap, struct mnt_list *mnts, struct mapent *me)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct list_head list;

	INIT_LIST_HEAD(&list);

	if (tree_get_mnt_list(mnts, &list, me->key, 1)) {
		if (ap->state == ST_READMAP) {
			time_t tout = me->source->exp_timeout;
			int save_ioctlfd, ioctlfd;

			save_ioctlfd = ioctlfd = me->ioctlfd;

			if (ioctlfd == -1)
				ops->open(ap->logopt,
					  &ioctlfd, me->dev, me->key);

			if (ioctlfd < 0) {
				error(ap->logopt,
				     "failed to create ioctl fd for %s",
				     me->key);
				return 0;
			}

			ops->timeout(ap->logopt, ioctlfd, tout);

			if (save_ioctlfd == -1)
				ops->close(ap->logopt, ioctlfd);

			return 0;
		}
	}

	if (!unlink_mount_tree(ap, &list)) {
		debug(ap->logopt,
		      "already mounted as other than autofs "
		      "or failed to unlink entry in tree");
		return 0;
	}

	return 1;
}

int do_mount_autofs_direct(struct autofs_point *ap,
			   struct mnt_list *mnts, struct mapent *me,
			   time_t timeout)
{
	const char *str_direct = mount_type_str(t_direct);
	struct ioctl_ops *ops = get_ioctl_ops();
	struct mnt_params *mp;
	struct stat st;
	int status, ret, ioctlfd;
	const char *map_name;
	time_t runfreq;

	if (timeout) {
		/* Calculate the expire run frequency */
		runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;
		if (ap->exp_runfreq)
			ap->exp_runfreq = min(ap->exp_runfreq, runfreq);
		else
			ap->exp_runfreq = runfreq;
	}

	if (ops->version && !do_force_unlink) {
		ap->flags |= MOUNT_FLAG_REMOUNT;
		ret = try_remount(ap, me, t_direct);
		ap->flags &= ~MOUNT_FLAG_REMOUNT;
		if (ret == 1)
			return 0;
		if (ret == 0)
			return -1;
	} else {
		/*
		 * A return of 0 indicates we're re-reading the map.
		 * A return of 1 indicates we successfully unlinked
		 * the mount tree if there was one. A return of -1
		 * inducates we failed to unlink the mount tree so
		 * we have to return a failure.
		 */
		ret = unlink_active_mounts(ap, mnts, me);
		if (ret == -1 || ret == 0)
			return ret;

		if (me->ioctlfd != -1) {
			error(ap->logopt, "active direct mount %s", me->key);
			return -1;
		}
	}

	status = pthread_once(&key_mnt_params_once, key_mnt_params_init);
	if (status)
		fatal(status);

	mp = pthread_getspecific(key_mnt_direct_params);
	if (!mp) {
		mp = (struct mnt_params *) malloc(sizeof(struct mnt_params));
		if (!mp) {
			crit(ap->logopt,
			  "mnt_params value create failed for direct mount %s",
			  ap->path);
			return 0;
		}
		mp->options = NULL;

		status = pthread_setspecific(key_mnt_direct_params, mp);
		if (status) {
			free(mp);
			fatal(status);
		}
	}

	if (!mp->options) {
		mp->options = make_options_string(ap->path, ap->kpipefd, str_direct);
		if (!mp->options)
			return 0;
	}

	/* In case the directory doesn't exist, try to mkdir it */
	if (mkdir_path(me->key, 0555) < 0) {
		if (errno != EEXIST && errno != EROFS) {
			crit(ap->logopt,
			     "failed to create mount directory %s", me->key);
			return -1;
		}
		/* If we recieve an error, and it's EEXIST or EROFS we know
		   the directory was not created. */
		me->flags &= ~MOUNT_FLAG_DIR_CREATED;
	} else {
		/* No errors so the directory was successfully created */
		me->flags |= MOUNT_FLAG_DIR_CREATED;
	}

	map_name = me->mc->map->argv[0];

	ret = mount(map_name, me->key, "autofs", MS_MGC_VAL, mp->options);
	if (ret) {
		crit(ap->logopt, "failed to mount autofs path %s", me->key);
		goto out_err;
	}

	ret = stat(me->key, &st);
	if (ret == -1) {
		error(ap->logopt,
		      "failed to stat direct mount trigger %s", me->key);
		goto out_umount;
	}

	ops->open(ap->logopt, &ioctlfd, st.st_dev, me->key);
	if (ioctlfd < 0) {
		crit(ap->logopt, "failed to create ioctl fd for %s", me->key);
		goto out_umount;
	}

	ops->timeout(ap->logopt, ioctlfd, timeout);
	notify_mount_result(ap, me->key, timeout, str_direct);
	cache_set_ino_index(me->mc, me->key, st.st_dev, st.st_ino);
	ops->close(ap->logopt, ioctlfd);

	debug(ap->logopt, "mounted trigger %s", me->key);

	return 0;

out_umount:
	/* TODO: maybe force umount (-l) */
	umount(me->key);
out_err:
	if (me->flags & MOUNT_FLAG_DIR_CREATED)
		rmdir(me->key);

	return -1;
}

int mount_autofs_direct(struct autofs_point *ap)
{
	struct map_source *map;
	struct mapent_cache *nc, *mc;
	struct mapent *me, *ne, *nested;
	struct mnt_list *mnts;
	time_t now = time(NULL);

	if (strcmp(ap->path, "/-")) {
		error(ap->logopt, "expected direct map, exiting");
		return -1;
	}

	/* TODO: check map type */
	if (lookup_nss_read_map(ap, NULL, now))
		lookup_prune_cache(ap, now);
	else {
		error(ap->logopt, "failed to read direct map");
		return -1;
	}

	mnts = tree_make_mnt_tree(_PROC_MOUNTS, "/");
	pthread_cleanup_push(mnts_cleanup, mnts);
	pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
	master_source_readlock(ap->entry);
	nc = ap->entry->master->nc;
	cache_readlock(nc);
	pthread_cleanup_push(cache_lock_cleanup, nc);
	map = ap->entry->maps;
	while (map) {
		time_t timeout;
		/*
		 * Only consider map sources that have been read since
		 * the map entry was last updated.
		 */
		if (ap->entry->age > map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		timeout = map->exp_timeout;
		cache_readlock(mc);
		pthread_cleanup_push(cache_lock_cleanup, mc);
		me = cache_enumerate(mc, NULL);
		while (me) {
			ne = cache_lookup_distinct(nc, me->key);
			if (ne) {
				if (map->master_line < ne->age) {
					/* TODO: check return, locking me */
					do_mount_autofs_direct(ap, mnts, me, timeout);
				}
				me = cache_enumerate(mc, me);
				continue;
			}

			nested = cache_partial_match(nc, me->key);
			if (nested) {
				error(ap->logopt,
				   "removing invalid nested null entry %s",
				   nested->key);
				nested = cache_partial_match(nc, me->key);
				if (nested)
					cache_delete(nc, nested->key);
			}

			/* TODO: check return, locking me */
			do_mount_autofs_direct(ap, mnts, me, timeout);

			me = cache_enumerate(mc, me);
		}
		pthread_cleanup_pop(1);
		map = map->next;
	}
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return 0;
}

int umount_autofs_offset(struct autofs_point *ap, struct mapent *me)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	char buf[MAX_ERR_BUF];
	int ioctlfd = -1, rv = 1, retries;
	int opened = 0;

	if (me->ioctlfd != -1) {
		if (is_mounted(_PATH_MOUNTED, me->key, MNTS_REAL)) {
			error(ap->logopt,
			      "attempt to umount busy offset %s", me->key);
			return 1;
		}
		ioctlfd = me->ioctlfd;
	} else {
		/* offset isn't mounted, return success and try to recover */
		if (!is_mounted(_PROC_MOUNTS, me->key, MNTS_AUTOFS)) {
			debug(ap->logopt,
			      "offset %s not mounted",
			      me->key);
			return 0;
		}
		ops->open(ap->logopt, &ioctlfd, me->dev, me->key);
		opened = 1;
	}

	if (ioctlfd >= 0) {
		unsigned int status = 1;

		rv = ops->askumount(ap->logopt, ioctlfd, &status);
		if (rv) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			logerr("ioctl failed: %s", estr);
			if (opened && ioctlfd != -1)
				ops->close(ap->logopt, ioctlfd);
			return 1;
		} else if (!status) {
			if (ap->state != ST_SHUTDOWN_FORCE) {
				if (ap->shutdown)
					error(ap->logopt,
					     "ask umount returned busy for %s",
					     me->key);
				if (opened && ioctlfd != -1)
					ops->close(ap->logopt, ioctlfd);
				return 1;
			} else {
				me->ioctlfd = -1;
				ops->catatonic(ap->logopt, ioctlfd);
				ops->close(ap->logopt, ioctlfd);
				goto force_umount;
			}
		}
		me->ioctlfd = -1;
		ops->catatonic(ap->logopt, ioctlfd);
		ops->close(ap->logopt, ioctlfd);
	} else {
		struct stat st;
		char *estr;
		int save_errno = errno;

		/* Non existent directory on remote fs - no mount */
		if (stat(me->key, &st) == -1 && errno == ENOENT)
			return 0;

		estr = strerror_r(save_errno, buf, MAX_ERR_BUF);
		error(ap->logopt,
		      "couldn't get ioctl fd for offset %s: %s",
		      me->key, estr);
		goto force_umount;
	}

	sched_yield();

	retries = UMOUNT_RETRIES;
	while ((rv = umount(me->key)) == -1 && retries--) {
		struct timespec tm = {0, 200000000};
		if (errno != EBUSY)
			break;
		nanosleep(&tm, NULL);
	}

	if (rv == -1) {
		switch (errno) {
		case ENOENT:
			warn(ap->logopt, "mount point does not exist");
			return 0;
			break;
		case EBUSY:
			error(ap->logopt, "mount point %s is in use", me->key);
			if (ap->state != ST_SHUTDOWN_FORCE)
				return 1;
			break;
		case ENOTDIR:
			error(ap->logopt, "mount point is not a directory");
			return 0;
			break;
		}
		goto force_umount;
	}

force_umount:
	if (rv != 0) {
		info(ap->logopt, "forcing umount of offset mount %s", me->key);
		rv = umount2(me->key, MNT_DETACH);
	} else
		info(ap->logopt, "umounted offset mount %s", me->key);

	return rv;
}

int mount_autofs_offset(struct autofs_point *ap, struct mapent *me, const char *root, const char *offset)
{
	const char *str_offset = mount_type_str(t_offset);
	struct ioctl_ops *ops = get_ioctl_ops();
	char buf[MAX_ERR_BUF];
	struct mnt_params *mp;
	time_t timeout = me->source->exp_timeout;
	struct stat st;
	int ioctlfd, status, ret;
	const char *hosts_map_name = "-hosts";
	const char *map_name = hosts_map_name;
	const char *type;
	char mountpoint[PATH_MAX];

	if (ops->version && ap->flags & MOUNT_FLAG_REMOUNT) {
		ret = try_remount(ap, me, t_offset);
		if (ret == 1)
			return MOUNT_OFFSET_OK;
		/* Offset mount not found, fall thru and try to mount it */
		if (!(ret == -1 && errno == ENOENT))
			return MOUNT_OFFSET_FAIL;
	} else {
		if (is_mounted(_PROC_MOUNTS, me->key, MNTS_AUTOFS)) {
			if (ap->state != ST_READMAP)
				warn(ap->logopt,
				     "trigger %s already mounted", me->key);
			return MOUNT_OFFSET_OK;
		}

		if (me->ioctlfd != -1) {
			error(ap->logopt, "active offset mount %s", me->key);
			return MOUNT_OFFSET_FAIL;
		}
	}

	status = pthread_once(&key_mnt_params_once, key_mnt_params_init);
	if (status)
		fatal(status);

	mp = pthread_getspecific(key_mnt_offset_params);
	if (!mp) {
		mp = (struct mnt_params *) malloc(sizeof(struct mnt_params));
		if (!mp) {
			crit(ap->logopt,
			  "mnt_params value create failed for offset mount %s",
			  me->key);
			return MOUNT_OFFSET_OK;
		}
		mp->options = NULL;

		status = pthread_setspecific(key_mnt_offset_params, mp);
		if (status) {
			free(mp);
			fatal(status);
		}
	}

	if (!mp->options) {
		mp->options = make_options_string(ap->path, ap->kpipefd, str_offset);
		if (!mp->options)
			return MOUNT_OFFSET_OK;
	}

	strcpy(mountpoint, root);
	strcat(mountpoint, offset);

	/* In case the directory doesn't exist, try to mkdir it */
	if (mkdir_path(mountpoint, 0555) < 0) {
		if (errno == EEXIST) {
			/*
			 * If the mount point directory is a real mount
			 * and it isn't the root offset then it must be
			 * a mount that has been automatically mounted by
			 * the kernel NFS client.
			 */
			if (me->multi != me &&
			    is_mounted(_PROC_MOUNTS, mountpoint, MNTS_REAL))
				return MOUNT_OFFSET_IGNORE;

			/* 
			 * If we recieve an error, and it's EEXIST
			 * we know the directory was not created.
			 */
			me->flags &= ~MOUNT_FLAG_DIR_CREATED;
		} else if (errno == EACCES) {
			/*
			 * We require the mount point directory to exist when
			 * installing multi-mount triggers into a host
			 * filesystem.
			 *
			 * If it doesn't exist it is not a valid part of the
			 * mount heirachy.
			 */
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			debug(ap->logopt,
			     "can't create mount directory: %s, %s",
			     mountpoint, estr);
			return MOUNT_OFFSET_FAIL;
		} else {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			crit(ap->logopt,
			     "failed to create mount directory: %s, %s",
			     mountpoint, estr);
			return MOUNT_OFFSET_FAIL;
		}
	} else {
		/* No errors so the directory was successfully created */
		me->flags |= MOUNT_FLAG_DIR_CREATED;
	}

	debug(ap->logopt,
	      "calling mount -t autofs " SLOPPY " -o %s automount %s",
	      mp->options, mountpoint);

	type = ap->entry->maps->type;
	if (!type || strcmp(ap->entry->maps->type, "hosts"))
		map_name = me->mc->map->argv[0];

	ret = mount(map_name, mountpoint, "autofs", MS_MGC_VAL, mp->options);
	if (ret) {
		crit(ap->logopt,
		     "failed to mount offset trigger %s at %s",
		     me->key, mountpoint);
		goto out_err;
	}

	ret = stat(mountpoint, &st);
	if (ret == -1) {
		error(ap->logopt,
		     "failed to stat direct mount trigger %s", mountpoint);
		goto out_umount;
	}

	ops->open(ap->logopt, &ioctlfd, st.st_dev, mountpoint);
	if (ioctlfd < 0) {
		crit(ap->logopt, "failed to create ioctl fd for %s", mountpoint);
		goto out_umount;
	}

	ops->timeout(ap->logopt, ioctlfd, timeout);
	cache_set_ino_index(me->mc, me->key, st.st_dev, st.st_ino);
	if (ap->logopt & LOGOPT_DEBUG)
		notify_mount_result(ap, mountpoint, timeout, str_offset);
	else
		notify_mount_result(ap, me->key, timeout, str_offset);
	ops->close(ap->logopt, ioctlfd);

	debug(ap->logopt, "mounted trigger %s at %s", me->key, mountpoint);

	return MOUNT_OFFSET_OK;

out_umount:
	umount(mountpoint);
out_err:
	if (stat(mountpoint, &st) == 0 && me->flags & MOUNT_FLAG_DIR_CREATED)
		 rmdir_path(ap, mountpoint, st.st_dev);

	return MOUNT_OFFSET_FAIL;
}

void *expire_proc_direct(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct mnt_list *mnts = NULL, *next;
	struct list_head list, *p;
	struct expire_args *ea;
	struct expire_args ec;
	struct autofs_point *ap;
	struct mapent *me = NULL;
	unsigned int now;
	int ioctlfd, cur_state;
	int status, ret, left;

	ea = (struct expire_args *) arg;

	status = pthread_mutex_lock(&ea->mutex);
	if (status)
		fatal(status);

	ap = ec.ap = ea->ap;
	now = ea->when;
	ec.status = -1;

	ea->signaled = 1;
	status = pthread_cond_signal(&ea->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_unlock(&ea->mutex);
	if (status)
		fatal(status);

	pthread_cleanup_push(expire_cleanup, &ec);

	left = 0;

	mnts = tree_make_mnt_tree(_PROC_MOUNTS, "/");
	pthread_cleanup_push(mnts_cleanup, mnts);

	/* Get a list of mounts select real ones and expire them if possible */
	INIT_LIST_HEAD(&list);
	if (!tree_get_mnt_list(mnts, &list, "/", 0)) {
		ec.status = 0;
		return NULL;
	}

	list_for_each(p, &list) {
		next = list_entry(p, struct mnt_list, list);

		/*
		 * All direct mounts must be present in the map
		 * entry cache.
		 */
		pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
		master_source_readlock(ap->entry);
		me = lookup_source_mapent(ap, next->path, LKP_DISTINCT);
		pthread_cleanup_pop(1);
		if (!me)
			continue;

		if (!strcmp(next->fs_type, "autofs")) {
			struct stat st;
			int ioctlfd;

			cache_unlock(me->mc);

			/*
			 * If we have submounts check if this path lives below
			 * one of them and pass on state change.
			 */
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
			if (strstr(next->opts, "indirect")) {
				master_notify_submount(ap, next->path, ap->state);
				pthread_setcancelstate(cur_state, NULL);
				continue;
			}

			if (me->ioctlfd == -1) {
				pthread_setcancelstate(cur_state, NULL);
				continue;
			}

			/* It's got a mount, deal with in the outer loop */
			if (tree_is_mounted(mnts, me->key, MNTS_REAL)) {
				pthread_setcancelstate(cur_state, NULL);
				continue;
			}

			/*
			 * Maybe a manual umount, repair.
			 * It will take ap->exp_timeout/4 for us to relaize
			 * this so user must still use USR1 signal to close
			 * the open file handle for mounts atop multi-mount
			 * triggers. There is no way that I'm aware of to
			 * avoid maintaining a file handle for control
			 * functions as once it's mounted all opens are
			 * directed to the mount not the trigger.
			 */

			/* Check for manual umount */
			cache_writelock(me->mc);
			if (me->ioctlfd != -1 && 
			    fstat(me->ioctlfd, &st) != -1 &&
			    !count_mounts(ap, next->path, st.st_dev)) {
				ops->close(ap->logopt, me->ioctlfd);
				me->ioctlfd = -1;
				cache_unlock(me->mc);
				pthread_setcancelstate(cur_state, NULL);
				continue;
			}
			cache_unlock(me->mc);

			ioctlfd = me->ioctlfd;

			ret = ops->expire(ap->logopt, ioctlfd, next->path, now);
			if (ret) {
				left++;
				pthread_setcancelstate(cur_state, NULL);
				continue;
			}

			pthread_setcancelstate(cur_state, NULL);
			continue;
		}

		if (me->ioctlfd >= 0) {
			/* Real mounts have an open ioctl fd */
			ioctlfd = me->ioctlfd;
			cache_unlock(me->mc);
		} else {
			cache_unlock(me->mc);
			continue;
		}

		if (ap->state == ST_EXPIRE || ap->state == ST_PRUNE)
			pthread_testcancel();

		debug(ap->logopt, "send expire to trigger %s", next->path);

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
		ret = ops->expire(ap->logopt, ioctlfd, next->path, now);
		if (ret)
			left++;
		pthread_setcancelstate(cur_state, NULL);
	}
	pthread_cleanup_pop(1);

	if (left)
		info(ap->logopt, "%d remaining in %s", left, ap->path);

	ec.status = left;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	pthread_cleanup_pop(1);
	pthread_setcancelstate(cur_state, NULL);

	return NULL;
}

static void expire_send_fail(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *mt = arg;
	struct autofs_point *ap = mt->ap;
	ops->send_fail(ap->logopt,
		       mt->ioctlfd, mt->wait_queue_token, -ENOENT);
}

static void *do_expire_direct(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *args, mt;
	struct autofs_point *ap;
	size_t len;
	int status, state;

	args = (struct pending_args *) arg;

	pending_mutex_lock(args);

	memcpy(&mt, args, sizeof(struct pending_args));

	ap = mt.ap;

	args->signaled = 1;
	status = pthread_cond_signal(&args->cond);
	if (status)
		fatal(status);

	pending_mutex_unlock(args);

	pthread_cleanup_push(expire_send_fail, &mt);

	len = _strlen(mt.name, KEY_MAX_LEN);
	if (!len) {
		warn(ap->logopt, "direct key path too long %s", mt.name);
		/* TODO: force umount ?? */
		pthread_exit(NULL);
	}

	status = do_expire(ap, mt.name, len);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status)
		ops->send_fail(ap->logopt,
			       mt.ioctlfd, mt.wait_queue_token, -ENOENT);
	else {
		struct mapent *me;
		cache_writelock(mt.mc);
		me = cache_lookup_distinct(mt.mc, mt.name);
		if (me)
			me->ioctlfd = -1;
		cache_unlock(mt.mc);
		ops->send_ready(ap->logopt, mt.ioctlfd, mt.wait_queue_token);
		ops->close(ap->logopt, mt.ioctlfd);
	}
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);

	return NULL;
}

int handle_packet_expire_direct(struct autofs_point *ap, autofs_packet_expire_direct_t *pkt)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct map_source *map;
	struct mapent_cache *mc = NULL;
	struct mapent *me = NULL;
	struct pending_args *mt;
	char buf[MAX_ERR_BUF];
	pthread_t thid;
	struct timespec wait;
	struct timeval now;
	int status, state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	/*
	 * This is a bit of a big deal.
	 * If we can't find the path and the map entry then
	 * we can't send a notification back to the kernel.
	 * Hang results.
	 *
	 * OTOH there is a mount so there should be a path
	 * and since it got mounted we have to trust that
	 * there is an entry in the cache.
	 */
	master_source_writelock(ap->entry);
	map = ap->entry->maps;
	while (map) {
		mc = map->mc;
		cache_writelock(mc);
		me = cache_lookup_ino(mc, pkt->dev, pkt->ino);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}

	if (!me) {
		/*
		 * Shouldn't happen as we have been sent this following
		 * successful thread creation and lookup.
		 */
		crit(ap->logopt, "can't find map entry for (%lu,%lu)",
		    (unsigned long) pkt->dev, (unsigned long) pkt->ino);
		master_source_unlock(ap->entry);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	/* Can't expire it if it isn't mounted */
	if (me->ioctlfd == -1) {
		int ioctlfd;
		ops->open(ap->logopt, &ioctlfd, me->dev, me->key);
		if (ioctlfd == -1) {
			crit(ap->logopt, "can't open ioctlfd for %s", me->key);
			cache_unlock(mc);
			master_source_unlock(ap->entry);
			pthread_setcancelstate(state, NULL);
			return 1;
		}
		ops->send_ready(ap->logopt, ioctlfd, pkt->wait_queue_token);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		pthread_setcancelstate(state, NULL);
		return 0;
	}

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "malloc: %s", estr);
		ops->send_fail(ap->logopt,
			       me->ioctlfd, pkt->wait_queue_token, -ENOMEM);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	status = pthread_cond_init(&mt->cond, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_init(&mt->mutex, NULL);
	if (status)
		fatal(status);

	mt->ap = ap;
	mt->ioctlfd = me->ioctlfd;
	mt->mc = mc;
	/* TODO: check length here */
	strcpy(mt->name, me->key);
	mt->dev = me->dev;
	mt->type = NFY_EXPIRE;
	mt->wait_queue_token = pkt->wait_queue_token;

	debug(ap->logopt, "token %ld, name %s",
		  (unsigned long) pkt->wait_queue_token, mt->name);

	pending_mutex_lock(mt);

	status = pthread_create(&thid, &th_attr_detached, do_expire_direct, mt);
	if (status) {
		error(ap->logopt, "expire thread create failed");
		ops->send_fail(ap->logopt,
			       mt->ioctlfd, pkt->wait_queue_token, -status);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		pending_mutex_unlock(mt);
		pending_cond_destroy(mt);
		pending_mutex_destroy(mt);
		free_pending_args(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	cache_unlock(mc);
	master_source_unlock(ap->entry);

	pthread_cleanup_push(free_pending_args, mt);
	pthread_cleanup_push(pending_mutex_destroy, mt);
	pthread_cleanup_push(pending_cond_destroy, mt);
	pthread_cleanup_push(pending_mutex_unlock, mt);
	pthread_setcancelstate(state, NULL);

	mt->signaled = 0;
	while (!mt->signaled) {
		gettimeofday(&now, NULL);
		wait.tv_sec = now.tv_sec + 2;
		wait.tv_nsec = now.tv_usec * 1000;
		status = pthread_cond_timedwait(&mt->cond, &mt->mutex, &wait);
		if (status && status != ETIMEDOUT)
			fatal(status);
	}

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return 0;
}

static void mount_send_fail(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *mt = arg;
	struct autofs_point *ap = mt->ap;
	ops->send_fail(ap->logopt, mt->ioctlfd, mt->wait_queue_token, -ENOENT);
	ops->close(ap->logopt, mt->ioctlfd);
}

static void *do_mount_direct(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *args, mt;
	struct autofs_point *ap;
	struct stat st;
	int status, state;

	args = (struct pending_args *) arg;

	pending_mutex_lock(args);

	memcpy(&mt, args, sizeof(struct pending_args));

	ap = mt.ap;

	args->signaled = 1;
	status = pthread_cond_signal(&args->cond);
	if (status)
		fatal(status);

	pending_mutex_unlock(args);

	pthread_cleanup_push(mount_send_fail, &mt);

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	status = fstat(mt.ioctlfd, &st);
	if (status == -1) {
		error(ap->logopt,
		      "can't stat direct mount trigger %s", mt.name);
		ops->send_fail(ap->logopt,
			       mt.ioctlfd, mt.wait_queue_token, -ENOENT);
		ops->close(ap->logopt, mt.ioctlfd);
		pthread_setcancelstate(state, NULL);
		pthread_exit(NULL);
	}

	status = stat(mt.name, &st);
	if (status != 0 || !S_ISDIR(st.st_mode) || st.st_dev != mt.dev) {
		error(ap->logopt,
		     "direct trigger not valid or already mounted %s",
		     mt.name);
		ops->send_ready(ap->logopt, mt.ioctlfd, mt.wait_queue_token);
		ops->close(ap->logopt, mt.ioctlfd);
		pthread_setcancelstate(state, NULL);
		pthread_exit(NULL);
	}

	pthread_setcancelstate(state, NULL);

	info(ap->logopt, "attempting to mount entry %s", mt.name);

	set_tsd_user_vars(ap->logopt, mt.uid, mt.gid);

	status = lookup_nss_mount(ap, NULL, mt.name, mt.len);
	/*
	 * Direct mounts are always a single mount. If it fails there's
	 * nothing to undo so just complain
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status) {
		struct mapent *me;
		struct statfs fs;
		unsigned int close_fd = 0;

		if (statfs(mt.name, &fs) == -1 ||
		   (fs.f_type == AUTOFS_SUPER_MAGIC &&
		    !master_find_submount(ap, mt.name)))
			close_fd = 1;
		cache_writelock(mt.mc);
		if ((me = cache_lookup_distinct(mt.mc, mt.name))) {
			/*
			 * Careful here, we need to leave the file handle open
			 * for direct mount multi-mounts with no real mount at
			 * their base so they will be expired.
			 */
			if (close_fd && me == me->multi)
				close_fd = 0;
			if (!close_fd)
				me->ioctlfd = mt.ioctlfd;
		}
		ops->send_ready(ap->logopt, mt.ioctlfd, mt.wait_queue_token);
		cache_unlock(mt.mc);
		if (close_fd)
			ops->close(ap->logopt, mt.ioctlfd);
		info(ap->logopt, "mounted %s", mt.name);
	} else {
		/* TODO: get mount return status from lookup_nss_mount */
		ops->send_fail(ap->logopt,
			       mt.ioctlfd, mt.wait_queue_token, -ENOENT);
		ops->close(ap->logopt, mt.ioctlfd);
		info(ap->logopt, "failed to mount %s", mt.name);
	}
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);

	return NULL;
}

int handle_packet_missing_direct(struct autofs_point *ap, autofs_packet_missing_direct_t *pkt)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct map_source *map;
	struct mapent_cache *mc = NULL;
	struct mapent *me = NULL;
	pthread_t thid;
	struct pending_args *mt;
	char buf[MAX_ERR_BUF];
	int status = 0;
	struct timespec wait;
	struct timeval now;
	int ioctlfd, len, state;
	unsigned int kver_major = get_kver_major();
	unsigned int kver_minor = get_kver_minor();

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	master_mutex_lock();

	/*
	 * If our parent is a direct or offset mount that has been
	 * covered by a mount and another lookup occurs after the
	 * mount but before the device and inode are set in the
	 * cache entry we will not be able to find the mapent. So
	 * we must take the source writelock to ensure the parent
	 * has mount is complete before we look for the entry.
	 *
	 * Since the vfs-automount kernel changes we can now block
	 * on covered mounts during mount tree construction so a
	 * write lock is no longer needed. So we now can handle a
	 * wider class of recursively define mount lookups.
	 */
	if (kver_major > 5 || (kver_major == 5 && kver_minor > 1))
		master_source_readlock(ap->entry);
	else
		master_source_writelock(ap->entry);
	map = ap->entry->maps;
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
		me = cache_lookup_ino(mc, pkt->dev, pkt->ino);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}

	if (!me) {
		/*
		 * Shouldn't happen as the kernel is telling us
		 * someone has walked on our mount point.
		 */
		logerr("can't find map entry for (%lu,%lu)",
		    (unsigned long) pkt->dev, (unsigned long) pkt->ino);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	if (me->ioctlfd != -1) {
		/* Maybe someone did a manual umount, clean up ! */
		close(me->ioctlfd);
		me->ioctlfd = -1;
	}
	ops->open(ap->logopt, &ioctlfd, me->dev, me->key);

	if (ioctlfd == -1) {
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		crit(ap->logopt, "failed to create ioctl fd for %s", me->key);
		/* TODO:  how do we clear wait q in kernel ?? */
		return 1;
	}

	debug(ap->logopt, "token %ld, name %s, request pid %u",
		  (unsigned long) pkt->wait_queue_token, me->key, pkt->pid);

	/* Ignore packet if we're trying to shut down */
	if (ap->shutdown || ap->state == ST_SHUTDOWN_FORCE) {
		ops->send_fail(ap->logopt,
			       ioctlfd, pkt->wait_queue_token, -ENOENT);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 0;
	}

	/* Check if we recorded a mount fail for this key */
	if (me->status >= time(NULL)) {
		ops->send_fail(ap->logopt,
			       ioctlfd, pkt->wait_queue_token, -ENOENT);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 0;
	}

	len = strlen(me->key);
	if (len >= PATH_MAX) {
		error(ap->logopt, "direct mount path too long %s", me->key);
		ops->send_fail(ap->logopt,
			       ioctlfd, pkt->wait_queue_token, -ENAMETOOLONG);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 0;
	}

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "malloc: %s", estr);
		ops->send_fail(ap->logopt,
			       ioctlfd, pkt->wait_queue_token, -ENOMEM);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 0;
	}
	memset(mt, 0, sizeof(struct pending_args));

	status = pthread_cond_init(&mt->cond, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_init(&mt->mutex, NULL);
	if (status)
		fatal(status);

	pending_mutex_lock(mt);

	mt->ap = ap;
	mt->ioctlfd = ioctlfd;
	mt->mc = mc;
	strcpy(mt->name, me->key);
	mt->len = len;
	mt->dev = me->dev;
	mt->type = NFY_MOUNT;
	mt->uid = pkt->uid;
	mt->gid = pkt->gid;
	mt->wait_queue_token = pkt->wait_queue_token;

	status = pthread_create(&thid, &th_attr_detached, do_mount_direct, mt);
	if (status) {
		error(ap->logopt, "missing mount thread create failed");
		ops->send_fail(ap->logopt,
			       ioctlfd, pkt->wait_queue_token, -status);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pending_mutex_unlock(mt);
		pending_cond_destroy(mt);
		pending_mutex_destroy(mt);
		free_pending_args(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	cache_unlock(mc);
	master_source_unlock(ap->entry);

	master_mutex_unlock();

	pthread_cleanup_push(free_pending_args, mt);
	pthread_cleanup_push(pending_mutex_destroy, mt);
	pthread_cleanup_push(pending_cond_destroy, mt);
	pthread_cleanup_push(pending_mutex_unlock, mt);
	pthread_setcancelstate(state, NULL);

	mt->signaled = 0;
	while (!mt->signaled) {
		gettimeofday(&now, NULL);
		wait.tv_sec = now.tv_sec + 2;
		wait.tv_nsec = now.tv_usec * 1000;
		status = pthread_cond_timedwait(&mt->cond, &mt->mutex, &wait);
		if (status && status != ETIMEDOUT)
			fatal(status);
	}

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return 0;
}

