/* ----------------------------------------------------------------------- *
 *   
 *  mounts.c - module for mount utilities.
 *
 *   Copyright 2002-2005 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <ctype.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/vfs.h>
#include <pwd.h>
#include <grp.h>
#include <libgen.h>

#include "automount.h"

#define MAX_OPTIONS_LEN		80
#define MAX_MNT_NAME_LEN	30
#define MAX_ENV_NAME		15

#define EBUFSIZ 1024

const unsigned int t_indirect = AUTOFS_TYPE_INDIRECT;
const unsigned int t_direct = AUTOFS_TYPE_DIRECT;
const unsigned int t_offset = AUTOFS_TYPE_OFFSET;
const unsigned int type_count = 3;

static const char options_template[]       = "fd=%d,pgrp=%u,minproto=5,maxproto=%d";
static const char options_template_extra[] = "fd=%d,pgrp=%u,minproto=5,maxproto=%d,%s";
static const char mnt_name_template[]      = "automount(pid%u)";

static struct kernel_mod_version kver = {0, 0};
static const char kver_options_template[]  = "fd=%d,pgrp=%u,minproto=3,maxproto=5";

#define EXT_MOUNTS_HASH_SIZE    50

struct ext_mount {
	char *mountpoint;
	unsigned int umount;
	struct list_head mount;
	struct list_head mounts;
};
static struct list_head ext_mounts_hash[EXT_MOUNTS_HASH_SIZE];
static unsigned int ext_mounts_hash_init_done = 0;
static pthread_mutex_t ext_mount_hash_mutex = PTHREAD_MUTEX_INITIALIZER;

unsigned int linux_version_code(void)
{
	struct utsname my_utsname;
	unsigned int p, q, r;
	char *tmp, *save;

	if (uname(&my_utsname))
		return 0;

	p = q = r = 0;

	tmp = strtok_r(my_utsname.release, ".", &save);
	if (!tmp)
		return 0;
	p = (unsigned int ) atoi(tmp);

	tmp = strtok_r(NULL, ".", &save);
	if (!tmp)
		return KERNEL_VERSION(p, 0, 0);
	q = (unsigned int) atoi(tmp);

	tmp = strtok_r(NULL, ".", &save);
	if (!tmp)
		return KERNEL_VERSION(p, q, 0);
	r = (unsigned int) atoi(tmp);

	return KERNEL_VERSION(p, q, r);
}

unsigned int query_kproto_ver(void)
{
	struct ioctl_ops *ops;
	char dir[] = "/tmp/autoXXXXXX", *t_dir;
	char options[MAX_OPTIONS_LEN + 1];
	pid_t pgrp = getpgrp();
	int pipefd[2], ioctlfd, len;
	struct stat st;

	t_dir = mkdtemp(dir);
	if (!t_dir)
		return 0;

	if (pipe(pipefd) == -1) {
		rmdir(t_dir);
		return 0;
	}

	len = snprintf(options, MAX_OPTIONS_LEN,
		       kver_options_template, pipefd[1], (unsigned) pgrp);
	if (len < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		rmdir(t_dir);
		return 0;
	}

	if (mount("automount", t_dir, "autofs", MS_MGC_VAL, options)) {
		close(pipefd[0]);
		close(pipefd[1]);
		rmdir(t_dir);
		return 0;
	}

	close(pipefd[1]);

	if (stat(t_dir, &st) == -1) {
		umount(t_dir);
		close(pipefd[0]);
		rmdir(t_dir);
		return 0;
	}

	ops = get_ioctl_ops();
	if (!ops) {
		umount(t_dir);
		close(pipefd[0]);
		rmdir(t_dir);
		return 0;
	}

	ops->open(LOGOPT_NONE, &ioctlfd, st.st_dev, t_dir);
	if (ioctlfd == -1) {
		umount(t_dir);
		close(pipefd[0]);
		close_ioctl_ctl();
		rmdir(t_dir);
		return 0;
	}

	ops->catatonic(LOGOPT_NONE, ioctlfd);

	/* If this ioctl() doesn't work, it is kernel version 2 */
	if (ops->protover(LOGOPT_NONE, ioctlfd, &kver.major)) {
		ops->close(LOGOPT_NONE, ioctlfd);
		umount(t_dir);
		close(pipefd[0]);
		close_ioctl_ctl();
		rmdir(t_dir);
		return 0;
	}

	/* If this ioctl() doesn't work, version is 4 or less */
	if (ops->protosubver(LOGOPT_NONE, ioctlfd, &kver.minor)) {
		ops->close(LOGOPT_NONE, ioctlfd);
		umount(t_dir);
		close(pipefd[0]);
		close_ioctl_ctl();
		rmdir(t_dir);
		return 0;
	}

	ops->close(LOGOPT_NONE, ioctlfd);
	umount(t_dir);
	close(pipefd[0]);
	close_ioctl_ctl();
	rmdir(t_dir);

	return 1;
}

unsigned int get_kver_major(void)
{
	return kver.major;
}

unsigned int get_kver_minor(void)
{
	return kver.minor;
}

#ifdef HAVE_MOUNT_NFS
static int extract_version(char *start, struct nfs_mount_vers *vers)
{
	char *s_ver = strchr(start, ' ');
	if (!s_ver)
		return 0;
	while (*s_ver && !isdigit(*s_ver)) {
		s_ver++;
		if (!*s_ver)
			return 0;
		break;
	}
	vers->major = atoi(strtok(s_ver, "."));
	vers->minor = (unsigned int) atoi(strtok(NULL, "."));
	vers->fix = (unsigned int) atoi(strtok(NULL, "."));
	return 1;
}

int check_nfs_mount_version(struct nfs_mount_vers *vers,
			    struct nfs_mount_vers *check)
{
	pid_t f;
	int ret, status, pipefd[2];
	char errbuf[EBUFSIZ + 1], *p, *sp;
	int errp, errn;
	sigset_t allsigs, tmpsig, oldsig;
	char *s_ver;
	int cancel_state;

	if (pipe(pipefd))
		return -1;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	sigfillset(&allsigs);
	pthread_sigmask(SIG_BLOCK, &allsigs, &oldsig);

	f = fork();
	if (f == 0) {
		reset_signals();
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);

		execl(PATH_MOUNT_NFS, PATH_MOUNT_NFS, "-V", (char *) NULL);
		_exit(255);	/* execv() failed */
	}

	ret = 0;

	tmpsig = oldsig;

	sigaddset(&tmpsig, SIGCHLD);
	pthread_sigmask(SIG_SETMASK, &tmpsig, NULL);

	close(pipefd[1]);

	if (f < 0) {
		close(pipefd[0]);
		pthread_sigmask(SIG_SETMASK, &oldsig, NULL);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	errp = 0;
	do {
		while (1) {
			errn = read(pipefd[0], errbuf + errp, EBUFSIZ - errp);
			if (errn == -1 && errno == EINTR)
				continue;
			break;
		}

		if (errn > 0) {
			errp += errn;

			sp = errbuf;
			while (errp && (p = memchr(sp, '\n', errp))) {
				*p++ = '\0';
				errp -= (p - sp);
				sp = p;
			}

			if (errp && sp != errbuf)
				memmove(errbuf, sp, errp);

			if (errp >= EBUFSIZ) {
				/* Line too long, split */
				errbuf[errp] = '\0';
				if ((s_ver = strstr(errbuf, "nfs-utils"))) {
					if (extract_version(s_ver, vers))
						ret = 1;
				}
				errp = 0;
			}

			if ((s_ver = strstr(errbuf, "nfs-utils"))) {
				if (extract_version(s_ver, vers))
					ret = 1;
			}
		}
	} while (errn > 0);

	close(pipefd[0]);

	if (errp > 0) {
		/* End of file without \n */
		errbuf[errp] = '\0';
		if ((s_ver = strstr(errbuf, "nfs-utils"))) {
			if (extract_version(s_ver, vers))
				ret = 1;
		}
	}

	if (ret) {
		if ((vers->major < check->major) ||
		    ((vers->major == check->major) && (vers->minor < check->minor)) ||
		    ((vers->major == check->major) && (vers->minor == check->minor) &&
		     (vers->fix < check->fix)))
			ret = 0;
	}

	if (waitpid(f, &status, 0) != f)
		debug(LOGOPT_NONE, "no process found to wait for");

	pthread_sigmask(SIG_SETMASK, &oldsig, NULL);
	pthread_setcancelstate(cancel_state, NULL);

	return ret;
}
#else
int check_nfs_mount_version(struct nfs_mount_vers *vers,
			    struct nfs_mount_vers *check)
{
	return 0;
}
#endif

static char *set_env_name(const char *prefix, const char *name, char *buf)
{
	size_t len;

	len = strlen(name);
	if (prefix)
		len += strlen(prefix);
	len++;

	if (len > MAX_ENV_NAME)
		return NULL;

	if (!prefix)
		strcpy(buf, name);
	else {
		strcpy(buf, prefix);
		strcat(buf, name);
	}
	return buf;
}

static struct substvar *do_macro_addvar(struct substvar *list,
					const char *prefix,
					const char *name,
					const char *val)
{
	char buf[MAX_ENV_NAME + 1];
	char *new;
	size_t len;

	new = set_env_name(prefix, name, buf);
	if (new) {
		len = strlen(new);
		list = macro_addvar(list, new, len, val);
	}
	return list;
}

static struct substvar *do_macro_removevar(struct substvar *list,
					   const char *prefix,
					   const char *name)
{
	char buf[MAX_ENV_NAME + 1];
	char *new;
	size_t len;

	new = set_env_name(prefix, name, buf);
	if (new) {
		len = strlen(new);
		list = macro_removevar(list, new, len);
	}
	return list;
}

struct substvar *addstdenv(struct substvar *sv, const char *prefix)
{
	struct substvar *list = sv;
	struct thread_stdenv_vars *tsv;
	char numbuf[16];

	tsv = pthread_getspecific(key_thread_stdenv_vars);
	if (tsv) {
		const struct substvar *mv;
		int ret;
		long num;

		num = (long) tsv->uid;
		ret = sprintf(numbuf, "%ld", num);
		if (ret > 0)
			list = do_macro_addvar(list, prefix, "UID", numbuf);
		num = (long) tsv->gid;
		ret = sprintf(numbuf, "%ld", num);
		if (ret > 0)
			list = do_macro_addvar(list, prefix, "GID", numbuf);
		list = do_macro_addvar(list, prefix, "USER", tsv->user);
		list = do_macro_addvar(list, prefix, "GROUP", tsv->group);
		list = do_macro_addvar(list, prefix, "HOME", tsv->home);
		mv = macro_findvar(list, "HOST", 4);
		if (mv) {
			char *shost = strdup(mv->val);
			if (shost) {
				char *dot = strchr(shost, '.');
				if (dot)
					*dot = '\0';
				list = do_macro_addvar(list,
						       prefix, "SHOST", shost);
				free(shost);
			}
		}
	}
	return list;
}

struct substvar *removestdenv(struct substvar *sv, const char *prefix)
{
	struct substvar *list = sv;

	list = do_macro_removevar(list, prefix, "UID");
	list = do_macro_removevar(list, prefix, "USER");
	list = do_macro_removevar(list, prefix, "HOME");
	list = do_macro_removevar(list, prefix, "GID");
	list = do_macro_removevar(list, prefix, "GROUP");
	list = do_macro_removevar(list, prefix, "SHOST");
	return list;
}

void add_std_amd_vars(struct substvar *sv)
{
	char *tmp;

	tmp = conf_amd_get_arch();
	if (tmp) {
		macro_global_addvar("arch", 4, tmp);
		free(tmp);
	}

	tmp = conf_amd_get_karch();
	if (tmp) {
		macro_global_addvar("karch", 5, tmp);
		free(tmp);
	}

	tmp = conf_amd_get_os();
	if (tmp) {
		macro_global_addvar("os", 2, tmp);
		free(tmp);
	}

	tmp = conf_amd_get_full_os();
	if (tmp) {
		macro_global_addvar("full_os", 7, tmp);
		free(tmp);
	}

	tmp = conf_amd_get_os_ver();
	if (tmp) {
		macro_global_addvar("osver", 5, tmp);
		free(tmp);
	}

	tmp = conf_amd_get_vendor();
	if (tmp) {
		macro_global_addvar("vendor", 6, tmp);
		free(tmp);
	}

	/* Umm ... HP_UX cluster name, probably not used */
	tmp = conf_amd_get_cluster();
	if (tmp) {
		macro_global_addvar("cluster", 7, tmp);
		free(tmp);
	} else {
		const struct substvar *v = macro_findvar(sv, "domain", 4);
		if (v && *v->val) {
			tmp = strdup(v->val);
			if (tmp)
				macro_global_addvar("cluster", 7, tmp);
		}
	}

	tmp = conf_amd_get_auto_dir();
	if (tmp) {
		macro_global_addvar("autodir", 7, tmp);
		free(tmp);
	}

	return;
}

void remove_std_amd_vars(void)
{
	macro_global_removevar("autodir", 7);
	macro_global_removevar("cluster", 7);
	macro_global_removevar("vendor", 6);
	macro_global_removevar("osver", 5);
	macro_global_removevar("full_os", 7);
	macro_global_removevar("os", 2);
	macro_global_removevar("karch", 5);
	macro_global_removevar("arch", 4);
	return;
 }

struct amd_entry *new_amd_entry(const struct substvar *sv)
{
	struct amd_entry *new;
	const struct substvar *v;
	char *path;

	v = macro_findvar(sv, "path", 4);
	if (!v)
		return NULL;

	path = strdup(v->val);
	if (!path)
		return NULL;

	new = malloc(sizeof(struct amd_entry));
	if (!new) {
		free(path);
		return NULL;
	}

	memset(new, 0, sizeof(*new));
	new->path = path;
	INIT_LIST_HEAD(&new->list);
	INIT_LIST_HEAD(&new->entries);
	INIT_LIST_HEAD(&new->ext_mount);

	return new;
}

void clear_amd_entry(struct amd_entry *entry)
{
	if (!entry)
		return;
	if (entry->path)
		free(entry->path);
	if (entry->map_type)
		free(entry->map_type);
	if (entry->pref)
		free(entry->pref);
	if (entry->fs)
		free(entry->fs);
	if (entry->rhost)
		free(entry->rhost);
	if (entry->rfs)
		free(entry->rfs);
	if (entry->opts)
		free(entry->opts);
	if (entry->addopts)
		free(entry->addopts);
	if (entry->remopts)
		free(entry->remopts);
	if (entry->sublink)
		free(entry->sublink);
	if (entry->selector)
		free_selector(entry->selector);
	return;
}

void free_amd_entry(struct amd_entry *entry)
{
	clear_amd_entry(entry);
	free(entry);
	return;
}

void free_amd_entry_list(struct list_head *entries)
{
	if (!list_empty(entries)) {
		struct list_head *head = entries;
		struct amd_entry *this;
		struct list_head *p;

		p = head->next;
		while (p != head) {
			this = list_entry(p, struct amd_entry, list);
			p = p->next;
			free_amd_entry(this);
		}
	}
}

/*
 * Make common autofs mount options string
 */
char *make_options_string(char *path, int pipefd, const char *extra)
{
	char *options;
	int len;

	options = malloc(MAX_OPTIONS_LEN + 1);
	if (!options) {
		logerr("can't malloc options string");
		return NULL;
	}

	if (extra) 
		len = snprintf(options, MAX_OPTIONS_LEN,
				options_template_extra,
				pipefd, (unsigned) getpgrp(),
				AUTOFS_MAX_PROTO_VERSION, extra);
	else
		len = snprintf(options, MAX_OPTIONS_LEN, options_template,
			pipefd, (unsigned) getpgrp(),
			AUTOFS_MAX_PROTO_VERSION);

	if (len >= MAX_OPTIONS_LEN) {
		logerr("buffer to small for options - truncated");
		len = MAX_OPTIONS_LEN - 1;
	}

	if (len < 0) {
		logerr("failed to malloc autofs mount options for %s", path);
		free(options);
		return NULL;
	}
	options[len] = '\0';

	return options;
}

char *make_mnt_name_string(char *path)
{
	char *mnt_name;
	int len;

	mnt_name = malloc(MAX_MNT_NAME_LEN + 1);
	if (!mnt_name) {
		logerr("can't malloc mnt_name string");
		return NULL;
	}

	len = snprintf(mnt_name, MAX_MNT_NAME_LEN,
			mnt_name_template, (unsigned) getpid());

	if (len >= MAX_MNT_NAME_LEN) {
		logerr("buffer to small for mnt_name - truncated");
		len = MAX_MNT_NAME_LEN - 1;
	}

	if (len < 0) {
		logerr("failed setting up mnt_name for autofs path %s", path);
		free(mnt_name);
		return NULL;
	}
	mnt_name[len] = '\0';

	return mnt_name;
}

static void ext_mounts_hash_init(void)
{
	int i;
	for (i = 0; i < EXT_MOUNTS_HASH_SIZE; i++)
		INIT_LIST_HEAD(&ext_mounts_hash[i]);
	ext_mounts_hash_init_done = 1;
}

static struct ext_mount *ext_mount_lookup(const char *mountpoint)
{
	u_int32_t hval = hash(mountpoint, EXT_MOUNTS_HASH_SIZE);
	struct list_head *p, *head;

	if (!ext_mounts_hash_init_done)
		ext_mounts_hash_init();

	if (list_empty(&ext_mounts_hash[hval]))
		return NULL;

	head = &ext_mounts_hash[hval];
	list_for_each(p, head) {
		struct ext_mount *this = list_entry(p, struct ext_mount, mount);
		if (!strcmp(this->mountpoint, mountpoint))
			return this;
	}
	return NULL;
}

int ext_mount_add(struct list_head *entry, const char *path, unsigned int umount)
{
	struct ext_mount *em;
	char *auto_dir;
	u_int32_t hval;
	int ret = 0;

	/* Not a mount in the external mount directory */
	auto_dir = conf_amd_get_auto_dir();
	if (strncmp(path, auto_dir, strlen(auto_dir))) {
		free(auto_dir);
		return 0;
	}
	free(auto_dir);

	pthread_mutex_lock(&ext_mount_hash_mutex);

	em = ext_mount_lookup(path);
	if (em) {
		struct list_head *p, *head;
		head = &em->mounts;
		list_for_each(p, head) {
			if (p == entry)
				goto done;
		}
		list_add_tail(entry, &em->mounts);
		ret = 1;
		goto done;
	}

	em = malloc(sizeof(struct ext_mount));
	if (!em) {
		ret = -1;
		goto done;
	}

	em->mountpoint = strdup(path);
	if (!em->mountpoint) {
		free(em);
		ret = -1;
		goto done;
	}
	em->umount = umount;
	INIT_LIST_HEAD(&em->mount);
	INIT_LIST_HEAD(&em->mounts);

	hval = hash(path, EXT_MOUNTS_HASH_SIZE);
	list_add_tail(&em->mount, &ext_mounts_hash[hval]);

	list_add_tail(entry, &em->mounts);

	ret = 1;
done:
	pthread_mutex_unlock(&ext_mount_hash_mutex);
	return ret;
}

int ext_mount_remove(struct list_head *entry, const char *path)
{
	struct ext_mount *em;
	char *auto_dir;
	int ret = 0;

	/* Not a mount in the external mount directory */
	auto_dir = conf_amd_get_auto_dir();
	if (strncmp(path, auto_dir, strlen(auto_dir))) {
		free(auto_dir);
		return 0;
	}
	free(auto_dir);

	pthread_mutex_lock(&ext_mount_hash_mutex);

	em = ext_mount_lookup(path);
	if (!em)
		goto done;

	list_del_init(entry);

	if (!list_empty(&em->mounts))
		goto done;
	else {
		list_del_init(&em->mount);
		if (em->umount)
			ret = 1;
		if (list_empty(&em->mount)) {
			free(em->mountpoint);
			free(em);
		}
	}
done:
	pthread_mutex_unlock(&ext_mount_hash_mutex);
	return ret;
}

/*
 * Get list of mounts under path in longest->shortest order
 */
struct mnt_list *get_mnt_list(const char *table, const char *path, int include)
{
	FILE *tab;
	size_t pathlen = strlen(path);
	struct mntent mnt_wrk;
	char buf[PATH_MAX * 3];
	struct mntent *mnt;
	struct mnt_list *ent, *mptr, *last;
	struct mnt_list *list = NULL;
	char *pgrp;
	size_t len;

	if (!path || !pathlen || pathlen > PATH_MAX)
		return NULL;

	tab = open_setmntent_r(table);
	if (!tab) {
		char *estr = strerror_r(errno, buf, PATH_MAX - 1);
		logerr("setmntent: %s", estr);
		return NULL;
	}

	while ((mnt = getmntent_r(tab, &mnt_wrk, buf, PATH_MAX * 3))) {
		len = strlen(mnt->mnt_dir);

		if ((!include && len <= pathlen) ||
	  	     strncmp(mnt->mnt_dir, path, pathlen) != 0)
			continue;

		/* Not a subdirectory of requested path ? */
		/* pathlen == 1 => everything is subdir    */
		if (pathlen > 1 && len > pathlen &&
				mnt->mnt_dir[pathlen] != '/')
			continue;

		ent = malloc(sizeof(*ent));
		if (!ent) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		memset(ent, 0, sizeof(*ent));

		mptr = list;
		last = NULL;
		while (mptr) {
			if (len >= strlen(mptr->path))
				break;
			last = mptr;
			mptr = mptr->next;
		}

		if (mptr == list)
			list = ent;
		else
			last->next = ent;

		ent->next = mptr;

		ent->path = malloc(len + 1);
		if (!ent->path) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		strcpy(ent->path, mnt->mnt_dir);

		ent->fs_name = malloc(strlen(mnt->mnt_fsname) + 1);
		if (!ent->fs_name) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		strcpy(ent->fs_name, mnt->mnt_fsname);

		ent->fs_type = malloc(strlen(mnt->mnt_type) + 1);
		if (!ent->fs_type) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		strcpy(ent->fs_type, mnt->mnt_type);

		ent->opts = malloc(strlen(mnt->mnt_opts) + 1);
		if (!ent->opts) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		strcpy(ent->opts, mnt->mnt_opts);

		ent->owner = 0;
		pgrp = strstr(mnt->mnt_opts, "pgrp=");
		if (pgrp) {
			char *end = strchr(pgrp, ',');
			if (end)
				*end = '\0';
			sscanf(pgrp, "pgrp=%d", &ent->owner);
		}
	}
	endmntent(tab);

	return list;
}

/*
 * Reverse a list of mounts
 */
struct mnt_list *reverse_mnt_list(struct mnt_list *list)
{
	struct mnt_list *next, *last;

	if (!list)
		return NULL;

	next = list;
	last = NULL;
	while (next) {
		struct mnt_list *this = next;
		next = this->next;
		this->next = last;
		last = this;
	}
	return last;
}

void free_mnt_list(struct mnt_list *list)
{
	struct mnt_list *next;

	if (!list)
		return;

	next = list;
	while (next) {
		struct mnt_list *this = next;

		next = this->next;

		if (this->path)
			free(this->path);

		if (this->fs_name)
			free(this->fs_name);

		if (this->fs_type)
			free(this->fs_type);

		if (this->opts)
			free(this->opts);

		free(this);
	}
}

int contained_in_local_fs(const char *path)
{
	struct mnt_list *mnts, *this;
	size_t pathlen = strlen(path);
	int ret;

	if (!path || !pathlen || pathlen > PATH_MAX)
		return 0;

	mnts = get_mnt_list(_PATH_MOUNTED, "/", 1);
	if (!mnts)
		return 0;

	ret = 0;

	for (this = mnts; this != NULL; this = this->next) {
		size_t len = strlen(this->path);

		if (!strncmp(path, this->path, len)) {
			if (len > 1 && pathlen > len && path[len] != '/')
				continue;
			else if (len == 1 && this->path[0] == '/') {
				/*
				 * always return true on rootfs, we don't
				 * want to break diskless clients.
				 */
				ret = 1;
			} else if (this->fs_name[0] == '/') {
				if (strlen(this->fs_name) > 1) {
					if (this->fs_name[1] != '/')
						ret = 1;
				} else
					ret = 1;
			} else if (!strncmp("LABEL=", this->fs_name, 6) ||
				   !strncmp("UUID=", this->fs_name, 5))
				ret = 1;
			break;
		}
	}

	free_mnt_list(mnts);

	return ret;
}

static int table_is_mounted(const char *table, const char *path, unsigned int type)
{
	struct mntent *mnt;
	struct mntent mnt_wrk;
	char buf[PATH_MAX * 3];
	size_t pathlen = strlen(path);
	FILE *tab;
	int ret = 0;

	if (!path || !pathlen || pathlen >= PATH_MAX)
		return 0;

	tab = open_setmntent_r(table);
	if (!tab) {
		char *estr = strerror_r(errno, buf, PATH_MAX - 1);
		logerr("setmntent: %s", estr);
		return 0;
	}

	while ((mnt = getmntent_r(tab, &mnt_wrk, buf, PATH_MAX * 3))) {
		size_t len = strlen(mnt->mnt_dir);

		if (type) {
			unsigned int autofs_fs;

			autofs_fs = !strcmp(mnt->mnt_type, "autofs");

			if (type & MNTS_REAL)
				if (autofs_fs)
					continue;

			if (type & MNTS_AUTOFS)
				if (!autofs_fs)
					continue;
		}

		if (pathlen == len && !strncmp(path, mnt->mnt_dir, pathlen)) {
			ret = 1;
			break;
		}
	}
	endmntent(tab);

	return ret;
}

static int ioctl_is_mounted(const char *path, unsigned int type)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	unsigned int mounted;

	ops->ismountpoint(LOGOPT_NONE, -1, path, &mounted);
	if (mounted) {
		switch (type) {
		case MNTS_ALL:
			return 1;
		case MNTS_AUTOFS:
			return (mounted & DEV_IOCTL_IS_AUTOFS);
		case MNTS_REAL:
			return (mounted & DEV_IOCTL_IS_OTHER);
		}
	}
	return 0;
}

int is_mounted(const char *table, const char *path, unsigned int type)
{
	struct ioctl_ops *ops = get_ioctl_ops();

	if (ops->ismountpoint)
		return ioctl_is_mounted(path, type);
	else
		return table_is_mounted(table, path, type);
}

int has_fstab_option(const char *opt)
{
	struct mntent *mnt;
	struct mntent mnt_wrk;
	char buf[PATH_MAX * 3];
	FILE *tab;
	int ret = 0;

	if (!opt)
		return 0;

	tab = open_setmntent_r(_PATH_MNTTAB);
	if (!tab) {
		char *estr = strerror_r(errno, buf, PATH_MAX - 1);
		logerr("setmntent: %s", estr);
		return 0;
	}

	while ((mnt = getmntent_r(tab, &mnt_wrk, buf, PATH_MAX * 3))) {
		if (hasmntopt(mnt, opt)) {
			ret = 1;
			break;
		}
	}
	endmntent(tab);

	return ret;
}

/*
 * Since we have to look at the entire mount tree for direct
 * mounts (all mounts under "/") and we may have a large number
 * of entries to traverse again and again we need to
 * use a more efficient method than the routines above.
 *
 * Thre tree_... routines allow us to read the mount tree
 * once and pass it to subsequent functions for use. Since
 * it's a tree structure searching should be a low overhead
 * operation.
 */
void tree_free_mnt_tree(struct mnt_list *tree)
{
	struct list_head *head, *p;

	if (!tree)
		return;

	tree_free_mnt_tree(tree->left);
	tree_free_mnt_tree(tree->right);

	head = &tree->self;
	p = head->next;
	while (p != head) {
		struct mnt_list *this;

		this = list_entry(p, struct mnt_list, self);

		p = p->next;

		list_del(&this->self);

		free(this->path);
		free(this->fs_name);
		free(this->fs_type);

		if (this->opts)
			free(this->opts);

		free(this);
	}

	free(tree->path);
	free(tree->fs_name);
	free(tree->fs_type);

	if (tree->opts)
		free(tree->opts);

	free(tree);
}

/*
 * Make tree of system mounts in /proc/mounts.
 */
struct mnt_list *tree_make_mnt_tree(const char *table, const char *path)
{
	FILE *tab;
	struct mntent mnt_wrk;
	char buf[PATH_MAX * 3];
	struct mntent *mnt;
	struct mnt_list *ent, *mptr;
	struct mnt_list *tree = NULL;
	char *pgrp;
	size_t plen;
	int eq;

	tab = open_setmntent_r(table);
	if (!tab) {
		char *estr = strerror_r(errno, buf, PATH_MAX - 1);
		logerr("setmntent: %s", estr);
		return NULL;
	}

	plen = strlen(path);

	while ((mnt = getmntent_r(tab, &mnt_wrk, buf, PATH_MAX * 3))) {
		size_t len = strlen(mnt->mnt_dir);

		/* Not matching path */
		if (strncmp(mnt->mnt_dir, path, plen))
			continue;

		/* Not a subdirectory of requested path */
		if (plen > 1 && len > plen && mnt->mnt_dir[plen] != '/')
			continue;

		ent = malloc(sizeof(*ent));
		if (!ent) {
			endmntent(tab);
			tree_free_mnt_tree(tree);
			return NULL;
		}
		memset(ent, 0, sizeof(*ent));

		INIT_LIST_HEAD(&ent->self);
		INIT_LIST_HEAD(&ent->list);
		INIT_LIST_HEAD(&ent->entries);
		INIT_LIST_HEAD(&ent->sublist);

		ent->path = malloc(len + 1);
		if (!ent->path) {
			endmntent(tab);
			free(ent);
			tree_free_mnt_tree(tree);
			return NULL;
		}
		strcpy(ent->path, mnt->mnt_dir);

		ent->fs_name = malloc(strlen(mnt->mnt_fsname) + 1);
		if (!ent->fs_name) {
			free(ent->path);
			free(ent);
			endmntent(tab);
			tree_free_mnt_tree(tree);
			return NULL;
		}
		strcpy(ent->fs_name, mnt->mnt_fsname);

		ent->fs_type = malloc(strlen(mnt->mnt_type) + 1);
		if (!ent->fs_type) {
			free(ent->fs_name);
			free(ent->path);
			free(ent);
			endmntent(tab);
			tree_free_mnt_tree(tree);
			return NULL;
		}
		strcpy(ent->fs_type, mnt->mnt_type);

		ent->opts = malloc(strlen(mnt->mnt_opts) + 1);
		if (!ent->opts) {
			free(ent->fs_type);
			free(ent->fs_name);
			free(ent->path);
			free(ent);
			endmntent(tab);
			tree_free_mnt_tree(tree);
			return NULL;
		}
		strcpy(ent->opts, mnt->mnt_opts);

		ent->owner = 0;
		pgrp = strstr(mnt->mnt_opts, "pgrp=");
		if (pgrp) {
			char *end = strchr(pgrp, ',');
			if (end)
				*end = '\0';
			sscanf(pgrp, "pgrp=%d", &ent->owner);
		}

		mptr = tree;
		while (mptr) {
			int elen = strlen(ent->path);
			int mlen = strlen(mptr->path);

			if (elen < mlen) {
				if (mptr->left) {
					mptr = mptr->left;
					continue;
				} else {
					mptr->left = ent;
					break;
				}
			} else if (elen > mlen) {
				if (mptr->right) {
					mptr = mptr->right;
					continue;
				} else {
					mptr->right = ent;
					break;
				}
			}

			eq = strcmp(ent->path, mptr->path);
			if (eq < 0) {
				if (mptr->left)
					mptr = mptr->left;
				else {
					mptr->left = ent;
					break;
				}
			} else if (eq > 0) {
				if (mptr->right)
					mptr = mptr->right;
				else {
					mptr->right = ent;
					break;
				}
			} else {
				list_add_tail(&ent->self, &mptr->self);
				break;
			}
		}

		if (!tree)
			tree = ent;
	}
	endmntent(tab);

	return tree;
}

/*
 * Get list of mounts under "path" in longest->shortest order
 */
int tree_get_mnt_list(struct mnt_list *mnts, struct list_head *list, const char *path, int include)
{
	size_t mlen, plen;

	if (!mnts)
		return 0;

	plen = strlen(path);
	mlen = strlen(mnts->path);
	if (mlen < plen)
		return tree_get_mnt_list(mnts->right, list, path, include);
	else {
		struct list_head *self, *p;

		tree_get_mnt_list(mnts->left, list, path, include);

		if ((!include && mlen <= plen) ||
				strncmp(mnts->path, path, plen))
			goto skip;

		if (plen > 1 && mlen > plen && mnts->path[plen] != '/')
			goto skip;

		INIT_LIST_HEAD(&mnts->list);
		list_add(&mnts->list, list);

		self = &mnts->self;
		list_for_each(p, self) {
			struct mnt_list *this;

			this = list_entry(p, struct mnt_list, self);
			INIT_LIST_HEAD(&this->list);
			list_add(&this->list, list);
		}
skip:
		tree_get_mnt_list(mnts->right, list, path, include);
	}

	if (list_empty(list))
		return 0;

	return 1;
}

/*
 * Get list of mounts under "path" in longest->shortest order
 */
int tree_get_mnt_sublist(struct mnt_list *mnts, struct list_head *list, const char *path, int include)
{
	size_t mlen, plen;

	if (!mnts)
		return 0;

	plen = strlen(path);
	mlen = strlen(mnts->path);
	if (mlen < plen)
		return tree_get_mnt_sublist(mnts->right, list, path, include);
	else {
		struct list_head *self, *p;

		tree_get_mnt_sublist(mnts->left, list, path, include);

		if ((!include && mlen <= plen) ||
				strncmp(mnts->path, path, plen))
			goto skip;

		if (plen > 1 && mlen > plen && mnts->path[plen] != '/')
			goto skip;

		INIT_LIST_HEAD(&mnts->sublist);
		list_add(&mnts->sublist, list);

		self = &mnts->self;
		list_for_each(p, self) {
			struct mnt_list *this;

			this = list_entry(p, struct mnt_list, self);
			INIT_LIST_HEAD(&this->sublist);
			list_add(&this->sublist, list);
		}
skip:
		tree_get_mnt_sublist(mnts->right, list, path, include);
	}

	if (list_empty(list))
		return 0;

	return 1;
}

int tree_find_mnt_ents(struct mnt_list *mnts, struct list_head *list, const char *path)
{
	int mlen, plen;

	if (!mnts)
		return 0;

	plen = strlen(path);
	mlen = strlen(mnts->path);
	if (mlen < plen)
		return tree_find_mnt_ents(mnts->right, list, path);
	else if (mlen > plen)
		return tree_find_mnt_ents(mnts->left, list, path);
	else {
		struct list_head *self, *p;

		tree_find_mnt_ents(mnts->left, list, path);

		if (!strcmp(mnts->path, path)) {
			INIT_LIST_HEAD(&mnts->entries);
			list_add(&mnts->entries, list);
		}

		self = &mnts->self;
		list_for_each(p, self) {
			struct mnt_list *this;

			this = list_entry(p, struct mnt_list, self);

			if (!strcmp(this->path, path)) {
				INIT_LIST_HEAD(&this->entries);
				list_add(&this->entries, list);
			}
		}

		tree_find_mnt_ents(mnts->right, list, path);

		if (!list_empty(list))
			return 1;
	}

	return 0;
}

int tree_is_mounted(struct mnt_list *mnts, const char *path, unsigned int type)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct list_head *p;
	struct list_head list;
	int mounted = 0;

	if (ops->ismountpoint)
		return ioctl_is_mounted(path, type);

	INIT_LIST_HEAD(&list);

	if (!tree_find_mnt_ents(mnts, &list, path))
		return 0;

	list_for_each(p, &list) {
		struct mnt_list *mptr;

		mptr = list_entry(p, struct mnt_list, entries);

		if (type) {
			unsigned int autofs_fs;

			autofs_fs = !strcmp(mptr->fs_type, "autofs");

			if (type & MNTS_REAL) {
				if (!autofs_fs) {
					mounted = 1;
					break;
				}
			} else if (type & MNTS_AUTOFS) {
				if (autofs_fs) {
					mounted = 1;
					break;
				}
			} else {
				mounted = 1;
				break;
			}
		}
	}
	return mounted;
}

void set_tsd_user_vars(unsigned int logopt, uid_t uid, gid_t gid)
{
	struct thread_stdenv_vars *tsv;
	struct passwd pw;
	struct passwd *ppw = &pw;
	struct passwd **pppw = &ppw;
	struct group gr;
	struct group *pgr;
	struct group **ppgr;
	char *pw_tmp, *gr_tmp;
	int status, tmplen, grplen;

	/*
	 * Setup thread specific data values for macro
	 * substution in map entries during the mount.
	 * Best effort only as it must go ahead.
	 */

	tsv = malloc(sizeof(struct thread_stdenv_vars));
	if (!tsv) {
		error(logopt, "failed alloc tsv storage");
		return;
	}

	tsv->uid = uid;
	tsv->gid = gid;

	/* Try to get passwd info */

	tmplen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (tmplen < 0) {
		error(logopt, "failed to get buffer size for getpwuid_r");
		goto free_tsv;
	}

	pw_tmp = malloc(tmplen + 1);
	if (!pw_tmp) {
		error(logopt, "failed to malloc buffer for getpwuid_r");
		goto free_tsv;
	}

	status = getpwuid_r(uid, ppw, pw_tmp, tmplen, pppw);
	if (status || !ppw) {
		error(logopt, "failed to get passwd info from getpwuid_r");
		free(pw_tmp);
		goto free_tsv;
	}

	tsv->user = strdup(pw.pw_name);
	if (!tsv->user) {
		error(logopt, "failed to malloc buffer for user");
		free(pw_tmp);
		goto free_tsv;
	}

	tsv->home = strdup(pw.pw_dir);
	if (!tsv->home) {
		error(logopt, "failed to malloc buffer for home");
		free(pw_tmp);
		goto free_tsv_user;
	}

	free(pw_tmp);

	/* Try to get group info */

	grplen = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (grplen < 0) {
		error(logopt, "failed to get buffer size for getgrgid_r");
		goto free_tsv_home;
	}

	gr_tmp = NULL;
	tmplen = grplen;
	while (1) {
		char *tmp = realloc(gr_tmp, tmplen + 1);
		if (!tmp) {
			error(logopt, "failed to malloc buffer for getgrgid_r");
			if (gr_tmp)
				free(gr_tmp);
			goto free_tsv_home;
		}
		gr_tmp = tmp;
		pgr = &gr;
		ppgr = &pgr;
		status = getgrgid_r(gid, pgr, gr_tmp, tmplen, ppgr);
		if (status != ERANGE)
			break;
		tmplen += grplen;
	}

	if (status || !pgr) {
		error(logopt, "failed to get group info from getgrgid_r");
		free(gr_tmp);
		goto free_tsv_home;
	}

	tsv->group = strdup(gr.gr_name);
	if (!tsv->group) {
		error(logopt, "failed to malloc buffer for group");
		free(gr_tmp);
		goto free_tsv_home;
	}

	free(gr_tmp);

	status = pthread_setspecific(key_thread_stdenv_vars, tsv);
	if (status) {
		error(logopt, "failed to set stdenv thread var");
		goto free_tsv_group;
	}

	return;

free_tsv_group:
	free(tsv->group);
free_tsv_home:
	free(tsv->home);
free_tsv_user:
	free(tsv->user);
free_tsv:
	free(tsv);
	return;
}

const char *mount_type_str(const unsigned int type)
{
	static const char *str_type[] = {
		"indirect",
		"direct",
		"offset"
	};
	unsigned int pos, i;

	for (pos = 0, i = type; pos < type_count; i >>= 1, pos++)
		if (i & 0x1)
			break;

	return (pos == type_count ? NULL : str_type[pos]);
}

void notify_mount_result(struct autofs_point *ap,
			 const char *path, time_t timeout, const char *type)
{
	if (timeout)
		info(ap->logopt,
		    "mounted %s on %s with timeout %u, freq %u seconds",
		    type, path, (unsigned int) timeout,
		    (unsigned int) ap->exp_runfreq);
	else
		info(ap->logopt,
		     "mounted %s on %s with timeouts disabled",
		     type, path);

	return;
}

static int do_remount_direct(struct autofs_point *ap, int fd, const char *path)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	int status = REMOUNT_SUCCESS;
	uid_t uid;
	gid_t gid;
	int ret;

	ops->requestor(ap->logopt, fd, path, &uid, &gid);
	if (uid != -1 && gid != -1)
		set_tsd_user_vars(ap->logopt, uid, gid);

	ret = lookup_nss_mount(ap, NULL, path, strlen(path));
	if (ret)
		info(ap->logopt, "re-connected to %s", path);
	else {
		status = REMOUNT_FAIL;
		info(ap->logopt, "failed to re-connect %s", path);
	}

	return status;
}

static int do_remount_indirect(struct autofs_point *ap, int fd, const char *path)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	int status = REMOUNT_SUCCESS;
	struct dirent **de;
	char buf[PATH_MAX + 1];
	uid_t uid;
	gid_t gid;
	unsigned int mounted;
	int n, size;

	n = scandir(path, &de, 0, alphasort);
	if (n < 0)
		return -1;

	size = sizeof(buf);

	while (n--) {
		int ret, len;

		if (strcmp(de[n]->d_name, ".") == 0 ||
		    strcmp(de[n]->d_name, "..") == 0) {
			free(de[n]);
			continue;
		}

		ret = cat_path(buf, size, path, de[n]->d_name);
		if (!ret) {
			do {
				free(de[n]);
			} while (n--);
			free(de);
			return -1;
		}

		ops->ismountpoint(ap->logopt, -1, buf, &mounted);
		if (!mounted) {
			struct dirent **de2;
			int i, j;

			i = j = scandir(buf, &de2, 0, alphasort);
			if (i < 0) {
				free(de[n]);
				continue;
			}
			while (i--)
				free(de2[i]);
			free(de2);
			if (j <= 2) {
				free(de[n]);
				continue;
			}
		}

		ops->requestor(ap->logopt, fd, buf, &uid, &gid);
		if (uid != -1 && gid != -1)
			set_tsd_user_vars(ap->logopt, uid, gid);

		len = strlen(de[n]->d_name);

		ret = lookup_nss_mount(ap, NULL, de[n]->d_name, len);
		if (ret)
			info(ap->logopt, "re-connected to %s", buf);
		else {
			status = REMOUNT_FAIL;
			info(ap->logopt, "failed to re-connect %s", buf);
		}
		free(de[n]);
	}
	free(de);

	return status;
}

static int remount_active_mount(struct autofs_point *ap,
				struct mapent *me, const char *path, dev_t devid,
				const unsigned int type, int *ioctlfd)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	const char *str_type = mount_type_str(type);
	char buf[MAX_ERR_BUF];
	unsigned int mounted;
	time_t timeout;
	struct stat st;
	int fd;

	*ioctlfd = -1;

	/* Open failed, no mount present */
	ops->open(ap->logopt, &fd, devid, path);
	if (fd == -1)
		return REMOUNT_OPEN_FAIL;
	else {
		if (type == t_indirect || type == t_offset)
			timeout = ap->entry->maps->exp_timeout;
		else
			timeout = me->source->exp_timeout;
	}

	/* Re-reading the map, set timeout and return */
	if (ap->state == ST_READMAP) {
		debug(ap->logopt, "already mounted, update timeout");
		ops->timeout(ap->logopt, fd, timeout);
		ops->close(ap->logopt, fd);
		return REMOUNT_READ_MAP;
	}

	debug(ap->logopt, "trying to re-connect to mount %s", path);

	/* Mounted so set pipefd and timeout etc. */
	if (ops->catatonic(ap->logopt, fd) == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "set catatonic failed: %s", estr);
		debug(ap->logopt, "couldn't re-connect to mount %s", path);
		ops->close(ap->logopt, fd);
		return REMOUNT_OPEN_FAIL;
	}
	if (ops->setpipefd(ap->logopt, fd, ap->kpipefd) == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "set pipefd failed: %s", estr);
		debug(ap->logopt, "couldn't re-connect to mount %s", path);
		ops->close(ap->logopt, fd);
		return REMOUNT_OPEN_FAIL;
	}
	ops->timeout(ap->logopt, fd, timeout);
	if (fstat(fd, &st) == -1) {
		error(ap->logopt,
		      "failed to stat %s mount %s", str_type, path);
		debug(ap->logopt, "couldn't re-connect to mount %s", path);
		ops->close(ap->logopt, fd);
		return REMOUNT_STAT_FAIL;
	}
	if (type != t_indirect)
		cache_set_ino_index(me->mc, path, st.st_dev, st.st_ino);
	else
		ap->dev = st.st_dev;
	notify_mount_result(ap, path, timeout, str_type);

	*ioctlfd = fd;

	/* Any mounts on or below? */
	if (ops->ismountpoint(ap->logopt, fd, path, &mounted) == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "ismountpoint %s failed: %s", path, estr);
		debug(ap->logopt, "couldn't re-connect to mount %s", path);
		ops->close(ap->logopt, fd);
		return REMOUNT_FAIL;
	}
	if (!mounted) {
		/*
		 * If we're an indirect mount we pass back the fd.
		 * But if were a direct or offset mount with no active
		 * mount we don't retain an open file descriptor.
		 */
		if (type != t_indirect) {
			ops->close(ap->logopt, fd);
			*ioctlfd = -1;
		}
	} else {
		int ret;
		/*
		 * What can I do if we can't remount the existing
		 * mount(s) (possibly a partial failure), everything
		 * following will be broken?
		 */
		if (type == t_indirect)
			ret = do_remount_indirect(ap, fd, path);
		else
			ret = do_remount_direct(ap, fd, path);
	}

	debug(ap->logopt, "re-connected to mount %s", path);

	return REMOUNT_SUCCESS;
}

int try_remount(struct autofs_point *ap, struct mapent *me, unsigned int type)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	const char *path;
	int ret, fd;
	dev_t devid;

	if (type == t_indirect)
		path = ap->path;
	else
		path = me->key;

	ret = ops->mount_device(ap->logopt, path, type, &devid);
	if (ret == -1 || ret == 0)
		return -1;

	ret = remount_active_mount(ap, me, path, devid, type, &fd);

	/*
	 * The directory must exist since we found a device
	 * number for the mount but we can't know if we created
	 * it or not. However, if this is an indirect mount with
	 * the nobrowse option we need to remove the mount point
	 * directory at umount anyway.
	 */
	if (type == t_indirect) {
		if (ap->flags & MOUNT_FLAG_GHOST)
			ap->flags &= ~MOUNT_FLAG_DIR_CREATED;
		else
			ap->flags |= MOUNT_FLAG_DIR_CREATED;
	} else
		me->flags &= ~MOUNT_FLAG_DIR_CREATED;

	/*
	 * Either we opened the mount or we're re-reading the map.
	 * If we opened the mount and ioctlfd is not -1 we have
	 * a descriptor for the indirect mount so we need to
	 * record that in the mount point struct. Otherwise we're
	 * re-reading the map.
	*/
	if (ret == REMOUNT_READ_MAP)
		return 1;
	else if (ret == REMOUNT_SUCCESS) {
		if (fd != -1) {
			if (type == t_indirect)
				ap->ioctlfd = fd;
			else
				me->ioctlfd = fd;
			return 1;
		}

		/* Indirect mount requires a valid fd */
		if (type != t_indirect)
			return 1;
	}

	/*
	 * Since we got the device number above a mount exists so
	 * any other failure warrants a failure return here.
	 */
	return 0;
}

int umount_ent(struct autofs_point *ap, const char *path)
{
	int rv;

	rv = spawn_umount(ap->logopt, path, NULL);
	/* We are doing a forced shutcwdown down so unlink busy mounts */
	if (rv && (ap->state == ST_SHUTDOWN_FORCE || ap->state == ST_SHUTDOWN)) {
		if (ap->state == ST_SHUTDOWN_FORCE) {
			info(ap->logopt, "forcing umount of %s", path);
			rv = spawn_umount(ap->logopt, "-l", path, NULL);
		}

		/*
		 * Verify that we actually unmounted the thing.  This is a
		 * belt and suspenders approach to not eating user data.
		 * We have seen cases where umount succeeds, but there is
		 * still a file system mounted on the mount point.  How
		 * this happens has not yet been determined, but we want to
		 * make sure to return failure here, if that is the case,
		 * so that we do not try to call rmdir_path on the
		 * directory.
		 */
		if (!rv && is_mounted(_PATH_MOUNTED, path, MNTS_REAL)) {
			crit(ap->logopt,
			     "the umount binary reported that %s was "
			     "unmounted, but there is still something "
			     "mounted on this path.", path);
			rv = -1;
		}
	}

	return rv;
}

static int do_mount_autofs_offset(struct autofs_point *ap,
				  struct mapent *oe, const char *root,
				  char *offset)

{
	int mounted = 0;
	int ret;

	debug(ap->logopt, "mount offset %s at %s", oe->key, root);

	ret = mount_autofs_offset(ap, oe, root, offset);
	if (ret >= MOUNT_OFFSET_OK)
		mounted++;
	else {
		if (ret != MOUNT_OFFSET_IGNORE)
			warn(ap->logopt, "failed to mount offset");
		else {
			debug(ap->logopt, "ignoring \"nohide\" trigger %s",
			      oe->key);
			free(oe->mapent);
			oe->mapent = NULL;
		}
	}

	return mounted;
}

int mount_multi_triggers(struct autofs_point *ap, struct mapent *me,
			 const char *root, unsigned int start, const char *base)
{
	char path[PATH_MAX + 1];
	char *offset = path;
	struct mapent *oe;
	struct list_head *pos = NULL;
	unsigned int fs_path_len;
	int mounted;

	fs_path_len = start + strlen(base);
	if (fs_path_len > PATH_MAX)
		return -1;

	mounted = 0;
	offset = cache_get_offset(base, offset, start, &me->multi_list, &pos);
	while (offset) {
		int plen = fs_path_len + strlen(offset);

		if (plen > PATH_MAX) {
			warn(ap->logopt, "path loo long");
			goto cont;
		}

		oe = cache_lookup_offset(base, offset, start, &me->multi_list);
		if (!oe || !oe->mapent)
			goto cont;

		mounted += do_mount_autofs_offset(ap, oe, root, offset);

		/*
		 * If re-constructing a multi-mount it's necessary to walk
		 * into nested mounts, unlike the usual "mount only what's
		 * needed as you go" behavior.
		 */
		if (ap->state == ST_READMAP && ap->flags & MOUNT_FLAG_REMOUNT) {
			if (oe->ioctlfd != -1 ||
			    is_mounted(_PROC_MOUNTS, oe->key, MNTS_REAL)) {
				char oe_root[PATH_MAX + 1];
				strcpy(oe_root, root);
				strcat(oe_root, offset); 
				mount_multi_triggers(ap, oe, oe_root, strlen(oe_root), base);
			}
		}
cont:
		offset = cache_get_offset(base,
				offset, start, &me->multi_list, &pos);
	}

	return mounted;
}

static int rmdir_path_offset(struct autofs_point *ap, struct mapent *oe)
{
	char *dir, *path;
	unsigned int split;
	int ret;

	if (ap->type == LKP_DIRECT)
		return rmdir_path(ap, oe->key, oe->multi->dev);

	dir = strdup(oe->key);

	if (ap->flags & MOUNT_FLAG_GHOST)
		split = strlen(ap->path) + strlen(oe->multi->key) + 1;
	else
		split = strlen(ap->path);

	dir[split] = '\0';
	path = &dir[split + 1];

	if (chdir(dir) == -1) {
		error(ap->logopt, "failed to chdir to %s", dir);
		free(dir);
		return -1;
	}

	ret = rmdir_path(ap, path, ap->dev);

	free(dir);

	if (chdir("/") == -1)
		error(ap->logopt, "failed to chdir to /");

	return ret;
}

int umount_multi_triggers(struct autofs_point *ap, struct mapent *me, char *root, const char *base)
{
	char path[PATH_MAX + 1];
	char *offset;
	struct mapent *oe;
	struct list_head *mm_root, *pos;
	const char o_root[] = "/";
	const char *mm_base;
	int left, start;

	left = 0;
	start = strlen(root);

	mm_root = &me->multi->multi_list;

	if (!base)
		mm_base = o_root;
	else
		mm_base = base;

	pos = NULL;
	offset = path;

	while ((offset = cache_get_offset(mm_base, offset, start, mm_root, &pos))) {
		char *oe_base;

		oe = cache_lookup_offset(mm_base, offset, start, &me->multi_list);
		/* root offset is a special case */
		if (!oe || (strlen(oe->key) - start) == 1)
			continue;

		/*
		 * Check for and umount subtree offsets resulting from
		 * nonstrict mount fail.
		 */
		oe_base = oe->key + strlen(root);
		left += umount_multi_triggers(ap, oe, root, oe_base);

		if (oe->ioctlfd != -1 ||
		    is_mounted(_PROC_MOUNTS, oe->key, MNTS_REAL)) {
			left++;
			continue;
		}

		debug(ap->logopt, "umount offset %s", oe->key);

		if (umount_autofs_offset(ap, oe)) {
			warn(ap->logopt, "failed to umount offset");
			left++;
		} else {
			struct stat st;
			int ret;

			if (!(oe->flags & MOUNT_FLAG_DIR_CREATED))
				continue;

			/*
			 * An error due to partial directory removal is
			 * ok so only try and remount the offset if the
			 * actual mount point still exists.
			 */
			ret = rmdir_path_offset(ap, oe);
			if (ret == -1 && !stat(oe->key, &st)) {
				ret = do_mount_autofs_offset(ap, oe, root, offset);
				if (ret)
					left++;
				/* But we did origianlly create this */
				oe->flags |= MOUNT_FLAG_DIR_CREATED;
			}
		}
	}

	if (!left && me->multi == me) {
		struct mapent_cache *mc = me->mc;
		int status;

		/*
		 * Special case.
		 * If we can't umount the root container then we can't
		 * delete the offsets from the cache and we need to put
		 * the offset triggers back.
		 */
		if (is_mounted(_PATH_MOUNTED, root, MNTS_REAL)) {
			info(ap->logopt, "unmounting dir = %s", root);
			if (umount_ent(ap, root) &&
			    is_mounted(_PATH_MOUNTED, root, MNTS_REAL)) {
				if (mount_multi_triggers(ap, me, root, strlen(root), "/") < 0)
					warn(ap->logopt,
					     "failed to remount offset triggers");
				return left++;
			}
		}

		/* We're done - clean out the offsets */
		status = cache_delete_offset_list(mc, me->key);
		if (status != CHE_OK)
			warn(ap->logopt, "couldn't delete offset list");
	}

	return left;
}

int clean_stale_multi_triggers(struct autofs_point *ap,
			       struct mapent *me, char *top, const char *base)
{
	char *root;
	char mm_top[PATH_MAX + 1];
	char path[PATH_MAX + 1];
	char buf[MAX_ERR_BUF];
	char *offset;
	struct mapent *oe;
	struct list_head *mm_root, *pos;
	const char o_root[] = "/";
	const char *mm_base;
	int left, start;
	time_t age;

	if (top)
		root = top;
	else {
		if (!strchr(me->multi->key, '/'))
			/* Indirect multi-mount root */
			/* sprintf okay - if it's mounted, it's
			 * PATH_MAX or less bytes */
			sprintf(mm_top, "%s/%s", ap->path, me->multi->key);
		else
			strcpy(mm_top, me->multi->key);
		root = mm_top;
	}

	left = 0;
	start = strlen(root);

	mm_root = &me->multi->multi_list;

	if (!base)
		mm_base = o_root;
	else
		mm_base = base;

	pos = NULL;
	offset = path;
	age = me->multi->age;

	while ((offset = cache_get_offset(mm_base, offset, start, mm_root, &pos))) {
		char *oe_base;
		char *key;
		int ret;

		oe = cache_lookup_offset(mm_base, offset, start, &me->multi_list);
		/* root offset is a special case */
		if (!oe || (strlen(oe->key) - start) == 1)
			continue;

		/* Check for and umount stale subtree offsets */
		oe_base = oe->key + strlen(root);
		ret = clean_stale_multi_triggers(ap, oe, root, oe_base);
		left += ret;
		if (ret)
			continue;

		if (oe->age == age)
			continue;

		/*
		 * If an offset that has an active mount has been removed
		 * from the multi-mount we don't want to attempt to trigger
		 * mounts for it. Obviously this is because it has been
		 * removed, but less obvious is the potential strange
		 * behaviour that can result if we do try and mount it
		 * again after it's been expired. For example, if an NFS
		 * file system is no longer exported and is later umounted
		 * it can be mounted again without any error message but
		 * shows as an empty directory. That's going to confuse
		 * people for sure.
		 *
		 * If the mount cannot be umounted (the process is now
		 * using a stale mount) the offset needs to be invalidated
		 * so no further mounts will be attempted but the offset
		 * cache entry must remain so expires can continue to
		 * attempt to umount it. If the mount can be umounted and
		 * the offset is removed, at least for NFS we will get
		 * ESTALE errors when attempting list the directory.
		 */
		if (oe->ioctlfd != -1 ||
		    is_mounted(_PROC_MOUNTS, oe->key, MNTS_REAL)) {
			if (umount_ent(ap, oe->key) &&
			    is_mounted(_PROC_MOUNTS, oe->key, MNTS_REAL)) {
				debug(ap->logopt,
				      "offset %s has active mount, invalidate",
				      oe->key);
				if (oe->mapent) {
					free(oe->mapent);
					oe->mapent = NULL;
				}
				left++;
				continue;
			}
		}

		key = strdup(oe->key);
		if (!key) {
	                char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		        error(ap->logopt, "malloc: %s", estr);
			left++;
			continue;
		}

		debug(ap->logopt, "umount offset %s", oe->key);

		if (umount_autofs_offset(ap, oe)) {
			warn(ap->logopt, "failed to umount offset %s", key);
			left++;
		} else {
			struct stat st;

			/* Mount point not ours to delete ? */
			if (!(oe->flags & MOUNT_FLAG_DIR_CREATED)) {
				debug(ap->logopt, "delete offset key %s", key);
				if (cache_delete_offset(oe->mc, key) == CHE_FAIL)
					error(ap->logopt,
					     "failed to delete offset key %s", key);
				free(key);
				continue;
			}

			/*
			 * An error due to partial directory removal is
			 * ok so only try and remount the offset if the
			 * actual mount point still exists.
			 */
			ret = rmdir_path_offset(ap, oe);
			if (ret == -1 && !stat(oe->key, &st)) {
				ret = do_mount_autofs_offset(ap, oe, root, offset);
				if (ret) {
					left++;
					/* But we did origianlly create this */
					oe->flags |= MOUNT_FLAG_DIR_CREATED;
					free(key);
					continue;
				}
				/*
				 * Fall through if the trigger can't be mounted
				 * again, since there is no offset there can't
				 * be any mount requests so remove the map
				 * entry from the cache. There's now a dead
				 * offset mount, but what else can we do ....
				 */
			}

			debug(ap->logopt, "delete offset key %s", key);

			if (cache_delete_offset(oe->mc, key) == CHE_FAIL)
				error(ap->logopt,
				     "failed to delete offset key %s", key);
		}
		free(key);
	}

	return left;
}

