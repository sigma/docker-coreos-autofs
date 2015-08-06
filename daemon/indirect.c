/* ----------------------------------------------------------------------- *
 *
 *  indirect.c - Linux automounter indirect mount handling
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
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sched.h>

#define INCLUDE_PENDING_FUNCTIONS
#include "automount.h"

/* Attribute to create detached thread */
extern pthread_attr_t th_attr_detached;

static int unlink_mount_tree(struct autofs_point *ap, struct mnt_list *mnts)
{
	struct mnt_list *this;
	int rv, ret;
	pid_t pgrp = getpgrp();
	char spgrp[20];

	sprintf(spgrp, "pgrp=%d", pgrp);

	ret = 1;
	this = mnts;
	while (this) {
		if (strstr(this->opts, spgrp)) {
			this = this->next;
			continue;
		}

		if (strcmp(this->fs_type, "autofs"))
			rv = spawn_umount(ap->logopt, "-l", this->path, NULL);
		else
			rv = umount2(this->path, MNT_DETACH);
		if (rv == -1) {
			debug(ap->logopt,
			      "can't unlink %s from mount tree", this->path);

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
		this = this->next;
	}
	return ret;
}

static int do_mount_autofs_indirect(struct autofs_point *ap, const char *root)
{
	const char *str_indirect = mount_type_str(t_indirect);
	struct ioctl_ops *ops = get_ioctl_ops();
	time_t timeout = ap->entry->maps->exp_timeout;
	char *options = NULL;
	const char *hosts_map_name = "-hosts";
	const char *map_name = hosts_map_name;
	const char *type;
	struct stat st;
	struct mnt_list *mnts;
	int ret;

	ap->exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;

	if (ops->version && !do_force_unlink) {
		ap->flags |= MOUNT_FLAG_REMOUNT;
		ret = try_remount(ap, NULL, t_indirect);
		ap->flags &= ~MOUNT_FLAG_REMOUNT;
		if (ret == 1)
			return 0;
		if (ret == 0)
			return -1;
	} else {
		mnts = get_mnt_list(_PROC_MOUNTS, ap->path, 1);
		if (mnts) {
			ret = unlink_mount_tree(ap, mnts);
			free_mnt_list(mnts);
			if (!ret) {
				error(ap->logopt,
				      "already mounted as other than autofs "
				      "or failed to unlink entry in tree");
				goto out_err;
			}
		}
	}

	options = make_options_string(ap->path, ap->kpipefd, str_indirect);
	if (!options) {
		error(ap->logopt, "options string error");
		goto out_err;
	}

	/* In case the directory doesn't exist, try to mkdir it */
	if (mkdir_path(root, 0555) < 0) {
		if (errno != EEXIST && errno != EROFS) {
			crit(ap->logopt,
			     "failed to create autofs directory %s",
			     root);
			goto out_err;
		}
		/* If we recieve an error, and it's EEXIST or EROFS we know
		   the directory was not created. */
		ap->flags &= ~MOUNT_FLAG_DIR_CREATED;
	} else {
		/* No errors so the directory was successfully created */
		ap->flags |= MOUNT_FLAG_DIR_CREATED;
	}

	type = ap->entry->maps->type;
	if (!type || strcmp(ap->entry->maps->type, "hosts"))
		map_name = ap->entry->maps->argv[0];

	ret = mount(map_name, root, "autofs", MS_MGC_VAL, options);
	if (ret) {
		crit(ap->logopt,
		     "failed to mount autofs path %s at %s", ap->path, root);
		goto out_rmdir;
	}

	free(options);
	options = NULL;

	ret = stat(root, &st);
	if (ret == -1) {
		crit(ap->logopt,
		     "failed to stat mount for autofs path %s", ap->path);
		goto out_umount;
	}

	if (ops->open(ap->logopt, &ap->ioctlfd, st.st_dev, root)) {
		crit(ap->logopt,
		     "failed to create ioctl fd for autofs path %s", ap->path);
		goto out_umount;
	}

	ap->dev = st.st_dev;	/* Device number for mount point checks */

	ops->timeout(ap->logopt, ap->ioctlfd, timeout);
	if (ap->logopt & LOGOPT_DEBUG)
		notify_mount_result(ap, root, timeout, str_indirect);
	else
		notify_mount_result(ap, ap->path, timeout, str_indirect);

	return 0;

out_umount:
	umount(root);
out_rmdir:
	if (ap->flags & MOUNT_FLAG_DIR_CREATED)
		rmdir(root);
out_err:
	if (options)
		free(options);
	close(ap->state_pipe[0]);
	close(ap->state_pipe[1]);
	close(ap->pipefd);
	close(ap->kpipefd);

	return -1;
}

int mount_autofs_indirect(struct autofs_point *ap, const char *root)
{
	time_t now = time(NULL);
	int status;
	int map;

	/* TODO: read map, determine map type is OK */
	if (lookup_nss_read_map(ap, NULL, now))
		lookup_prune_cache(ap, now);
	else {
		error(ap->logopt, "failed to read map for %s", ap->path);
		return -1;
	}

	status = do_mount_autofs_indirect(ap, root);
	if (status < 0)
		return -1;

	map = lookup_ghost(ap, root);
	if (map & LKP_FAIL) {
		if (map & LKP_DIRECT) {
			error(ap->logopt,
			      "bad map format,found direct, "
			      "expected indirect exiting");
		} else {
			error(ap->logopt, "failed to load map, exiting");
		}
		/* TODO: Process cleanup ?? */
		return -1;
	}

	if (map & LKP_NOTSUP)
		ap->flags &= ~MOUNT_FLAG_GHOST;

	return 0;
}

void close_mount_fds(struct autofs_point *ap)
{
	/*
	 * Since submounts look after themselves the parent never knows
	 * it needs to close the ioctlfd for offset mounts so we have
	 * to do it here. If the cache entry isn't found then there aren't
	 * any offset mounts.
	 */
	if (ap->submount)
		lookup_source_close_ioctlfd(ap->parent, ap->path);

	close(ap->state_pipe[0]);
	close(ap->state_pipe[1]);
	ap->state_pipe[0] = -1;
	ap->state_pipe[1] = -1;

	if (ap->pipefd >= 0)
		close(ap->pipefd);

	if (ap->kpipefd >= 0)
		close(ap->kpipefd);

	return;
}

int umount_autofs_indirect(struct autofs_point *ap, const char *root)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	char buf[MAX_ERR_BUF];
	char mountpoint[PATH_MAX + 1];
	int rv, retries;
	unsigned int unused;

	if (root)
		strcpy(mountpoint, root);
	else
		strcpy(mountpoint, ap->path);

	/* If we are trying to shutdown make sure we can umount */
	rv = ops->askumount(ap->logopt, ap->ioctlfd, &unused);
	if (rv == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("ioctl failed: %s", estr);
		return 1;
	} else if (!unused) {
#if defined(ENABLE_IGNORE_BUSY_MOUNTS) || defined(ENABLE_FORCED_SHUTDOWN)
		if (!ap->shutdown)
			return 1;
		error(ap->logopt, "ask umount returned busy %s", ap->path);
#else
		return 1;
#endif
	}

	if (ap->shutdown)
		ops->catatonic(ap->logopt, ap->ioctlfd);

	ops->close(ap->logopt, ap->ioctlfd);
	ap->ioctlfd = -1;
	sched_yield();

	retries = UMOUNT_RETRIES;
	while ((rv = umount(mountpoint)) == -1 && retries--) {
		struct timespec tm = {0, 200000000};
		if (errno != EBUSY)
			break;
		nanosleep(&tm, NULL);
	}

	if (rv == -1) {
		switch (errno) {
		case ENOENT:
		case EINVAL:
			error(ap->logopt,
			      "mount point %s does not exist", mountpoint);
			close_mount_fds(ap);
			return 0;
			break;
		case EBUSY:
			debug(ap->logopt,
			      "mount point %s is in use", mountpoint);
			if (ap->state == ST_SHUTDOWN_FORCE) {
				close_mount_fds(ap);
				goto force_umount;
			} else {
				/*
				 * If the umount returns EBUSY there may be
				 * a mount request in progress so we need to
				 * recover unless we have been explicitly
				 * asked to shutdown and configure option
				 * ENABLE_IGNORE_BUSY_MOUNTS is enabled.
				 */
#ifdef ENABLE_IGNORE_BUSY_MOUNTS
				if (ap->shutdown) {
					close_mount_fds(ap);
					return 0;
				}
#endif
				ops->open(ap->logopt,
					  &ap->ioctlfd, ap->dev, mountpoint);
				if (ap->ioctlfd < 0) {
					warn(ap->logopt,
					     "could not recover autofs path %s",
					     mountpoint);
					close_mount_fds(ap);
					return 0;
				}
			}
			break;
		case ENOTDIR:
			error(ap->logopt, "mount point is not a directory");
			close_mount_fds(ap);
			return 0;
			break;
		}
		return 1;
	}

	/*
	 * We have successfully umounted the mount so we now close
	 * the descriptors. The kernel end of the kernel pipe will
	 * have been put during the umount super block cleanup.
	 */
	close_mount_fds(ap);

force_umount:
	if (rv != 0) {
		warn(ap->logopt,
		     "forcing umount of indirect mount %s", mountpoint);
		rv = umount2(mountpoint, MNT_DETACH);
	} else {
		info(ap->logopt, "umounted indirect mount %s", mountpoint);
		if (ap->submount)
			rm_unwanted(ap, mountpoint, 1);
	}

	return rv;
}

static void mnts_cleanup(void *arg)
{
	struct mnt_list *mnts = (struct mnt_list *) arg;
	free_mnt_list(mnts);
	return;
}

void *expire_proc_indirect(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct autofs_point *ap;
	struct mapent *me = NULL;
	struct mnt_list *mnts = NULL, *next;
	struct expire_args *ea;
	struct expire_args ec;
	unsigned int now;
	int offsets, submnts, count;
	int retries;
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

	/* Get a list of real mounts and expire them if possible */
	mnts = get_mnt_list(_PROC_MOUNTS, ap->path, 0);
	pthread_cleanup_push(mnts_cleanup, mnts);
	for (next = mnts; next; next = next->next) {
		char *ind_key;
		int ret;

		if (!strcmp(next->fs_type, "autofs")) {
			/*
			 * If we have submounts check if this path lives below
			 * one of them and pass on the state change.
			 */
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
			if (strstr(next->opts, "indirect"))
				master_notify_submount(ap, next->path, ap->state);
			else if (strstr(next->opts, "offset")) {
				struct map_source *map;
				struct mapent_cache *mc = NULL;
				struct mapent *me = NULL;
				struct stat st;

				/* It's got a mount, deal with in the outer loop */
				if (is_mounted(_PATH_MOUNTED, next->path, MNTS_REAL)) {
					pthread_setcancelstate(cur_state, NULL);
					continue;
				}

				/* Don't touch submounts */
				if (master_find_submount(ap, next->path)) {
					pthread_setcancelstate(cur_state, NULL);
					continue;
				}

				master_source_writelock(ap->entry);

				map = ap->entry->maps;
				while (map) {
					mc = map->mc;
					cache_writelock(mc);
					me = cache_lookup_distinct(mc, next->path);
					if (me)
						break;
					cache_unlock(mc);
					map = map->next;
				}

				if (!mc || !me) {
					master_source_unlock(ap->entry);
					pthread_setcancelstate(cur_state, NULL);
					continue;
				}

				if (me->ioctlfd == -1) {
					cache_unlock(mc);
					master_source_unlock(ap->entry);
					pthread_setcancelstate(cur_state, NULL);
					continue;
				}

				/* Check for manual umount */
				if (fstat(me->ioctlfd, &st) == -1 ||
				    !count_mounts(ap, me->key, st.st_dev)) {
					ops->close(ap->logopt, me->ioctlfd);
					me->ioctlfd = -1;
				}

				cache_unlock(mc);
				master_source_unlock(ap->entry);
			}

			pthread_setcancelstate(cur_state, NULL);
			continue;
		}

		if (ap->state == ST_EXPIRE || ap->state == ST_PRUNE)
			pthread_testcancel();

		/*
		 * If the mount corresponds to an offset trigger then
		 * the key is the path, otherwise it's the last component.
		 */
		ind_key = strrchr(next->path, '/');
		if (ind_key)
			ind_key++;

		/*
		 * If me->key starts with a '/' and it's not an autofs
		 * filesystem it's a nested mount and we need to use
		 * the ioctlfd of the mount to send the expire.
		 * Otherwise it's a top level indirect mount (possibly
		 * with offsets in it) and we use the usual ioctlfd.
		 */
		pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
		master_source_readlock(ap->entry);
		me = lookup_source_mapent(ap, next->path, LKP_DISTINCT);
		if (!me && ind_key)
			me = lookup_source_mapent(ap, ind_key, LKP_NORMAL);
		pthread_cleanup_pop(1);

		ioctlfd = ap->ioctlfd;
		if (me) {
			if (*me->key == '/')
				ioctlfd = me->ioctlfd;
			cache_unlock(me->mc);
		}

		debug(ap->logopt, "expire %s", next->path);

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
		ret = ops->expire(ap->logopt, ioctlfd, next->path, now);
		if (ret)
			left++;
		pthread_setcancelstate(cur_state, NULL);
	}

	/*
	 * If there are no more real mounts left we could still
	 * have some offset mounts with no '/' offset or symlinks
	 * so we need to umount or unlink them here.
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	retries = (count_mounts(ap, ap->path, ap->dev) + 1);
	while (retries--) {
		ret = ops->expire(ap->logopt, ap->ioctlfd, ap->path, now);
		if (ret)
			left++;
	}
	pthread_setcancelstate(cur_state, NULL);
	pthread_cleanup_pop(1);

	count = offsets = submnts = 0;
	mnts = get_mnt_list(_PROC_MOUNTS, ap->path, 0);
	pthread_cleanup_push(mnts_cleanup, mnts);
	/* Are there any real mounts left */
	for (next = mnts; next; next = next->next) {
		if (strcmp(next->fs_type, "autofs"))
			count++;
		else {
			if (strstr(next->opts, "indirect"))
				submnts++;
			else
				offsets++;
		}
	}
	pthread_cleanup_pop(1);

	if (submnts)
		info(ap->logopt,
		     "%d submounts remaining in %s", submnts, ap->path);

	/* 
	 * EXPIRE_MULTI is synchronous, so we can be sure (famous last
	 * words) the umounts are done by the time we reach here
	 */
	if (count)
		info(ap->logopt, "%d remaining in %s", count, ap->path);

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
		       ap->ioctlfd, mt->wait_queue_token, -ENOENT);
}

static void *do_expire_indirect(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *args, mt;
	struct autofs_point *ap;
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

	status = do_expire(mt.ap, mt.name, mt.len);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status)
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, mt.wait_queue_token, -status);
	else
		ops->send_ready(ap->logopt,
				ap->ioctlfd, mt.wait_queue_token);
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);

	return NULL;
}

int handle_packet_expire_indirect(struct autofs_point *ap, autofs_packet_expire_indirect_t *pkt)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *mt;
	char buf[MAX_ERR_BUF];
	pthread_t thid;
	struct timespec wait;
	struct timeval now;
	int status, state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	debug(ap->logopt, "token %ld, name %s",
		  (unsigned long) pkt->wait_queue_token, pkt->name);

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("malloc: %s", estr);
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -ENOMEM);
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
	strncpy(mt->name, pkt->name, pkt->len);
	mt->name[pkt->len] = '\0';
	mt->len = pkt->len;
	mt->wait_queue_token = pkt->wait_queue_token;

	pending_mutex_lock(mt);

	status = pthread_create(&thid, &th_attr_detached, do_expire_indirect, mt);
	if (status) {
		error(ap->logopt, "expire thread create failed");
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -status);
		pending_mutex_unlock(mt);
		pending_cond_destroy(mt);
		pending_mutex_destroy(mt);
		free_pending_args(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

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
	ops->send_fail(ap->logopt,
		       ap->ioctlfd, mt->wait_queue_token, -ENOENT);
}

static void *do_mount_indirect(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *args, mt;
	struct autofs_point *ap;
	char buf[PATH_MAX + 1];
	struct stat st;
	int len, status, state;

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

	len = ncat_path(buf, sizeof(buf), ap->path, mt.name, mt.len);
	if (!len) {
		crit(ap->logopt, "path to be mounted is to long");
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, mt.wait_queue_token,
			      -ENAMETOOLONG);
		pthread_setcancelstate(state, NULL);
		pthread_exit(NULL);
	}

	status = lstat(buf, &st);
	if (status != -1 && !(S_ISDIR(st.st_mode) && st.st_dev == mt.dev)) {
		error(ap->logopt,
		      "indirect trigger not valid or already mounted %s", buf);
		ops->send_ready(ap->logopt, ap->ioctlfd, mt.wait_queue_token);
		pthread_setcancelstate(state, NULL);
		pthread_exit(NULL);
	}

	pthread_setcancelstate(state, NULL);

	info(ap->logopt, "attempting to mount entry %s", buf);

	set_tsd_user_vars(ap->logopt, mt.uid, mt.gid);

	status = lookup_nss_mount(ap, NULL, mt.name, mt.len);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status) {
		ops->send_ready(ap->logopt,
				ap->ioctlfd, mt.wait_queue_token);
		info(ap->logopt, "mounted %s", buf);
	} else {
		/* TODO: get mount return status from lookup_nss_mount */
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, mt.wait_queue_token, -ENOENT);
		info(ap->logopt, "failed to mount %s", buf);
	}
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);

	return NULL;
}

int handle_packet_missing_indirect(struct autofs_point *ap, autofs_packet_missing_indirect_t *pkt)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	pthread_t thid;
	char buf[MAX_ERR_BUF];
	struct pending_args *mt;
	struct timespec wait;
	struct timeval now;
	struct mapent *me;
	int status, state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	master_mutex_lock();

	debug(ap->logopt, "token %ld, name %s, request pid %u",
		(unsigned long) pkt->wait_queue_token, pkt->name, pkt->pid);

	/* Ignore packet if we're trying to shut down */
	if (ap->shutdown || ap->state == ST_SHUTDOWN_FORCE) {
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -ENOENT);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 0;
	}

	/* Check if we recorded a mount fail for this key anywhere */
	me = lookup_source_mapent(ap, pkt->name, LKP_DISTINCT);
	if (me) {
		if (me->status >= time(NULL)) {
			ops->send_fail(ap->logopt, ap->ioctlfd,
				       pkt->wait_queue_token, -ENOENT);
			cache_unlock(me->mc);
			master_mutex_unlock();
			pthread_setcancelstate(state, NULL);
			return 0;
		}
		cache_unlock(me->mc);
	}

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("malloc: %s", estr);
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -ENOMEM);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 1;
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
	strncpy(mt->name, pkt->name, pkt->len);
	mt->name[pkt->len] = '\0';
	mt->len = pkt->len;
	mt->dev = pkt->dev;
	mt->uid = pkt->uid;
	mt->gid = pkt->gid;
	mt->wait_queue_token = pkt->wait_queue_token;

	status = pthread_create(&thid, &th_attr_detached, do_mount_indirect, mt);
	if (status) {
		error(ap->logopt, "expire thread create failed");
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -status);
		master_mutex_unlock();
		pending_mutex_unlock(mt);
		pending_cond_destroy(mt);
		pending_mutex_destroy(mt);
		free_pending_args(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

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

