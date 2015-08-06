/*
 * automount.h
 *
 * Header file for automounter modules
 *
 */

#ifndef AUTOMOUNT_H
#define AUTOMOUNT_H

#include <paths.h>
#include <limits.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <mntent.h>
#include "config.h"
#include "list.h"

#include <linux/auto_fs4.h>

#include "defaults.h"
#include "state.h"
#include "master.h"
#include "macros.h"
#include "log.h"
#include "rpc_subs.h"
#include "mounts.h"
#include "parse_subs.h"
#include "mounts.h"
#include "dev-ioctl-lib.h"
#include "parse_amd.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif

#define ENABLE_CORES	1

/* We MUST have the paths to mount(8) and umount(8) */
#ifndef HAVE_MOUNT
#error Failed to locate mount(8)!
#endif

#ifndef HAVE_UMOUNT
#error Failed to locate umount(8)!
#endif

#ifndef HAVE_MODPROBE
#error Failed to locate modprobe(8)!
#endif

#ifndef HAVE_LINUX_PROCFS
#error Failed to verify existence of procfs filesystem!
#endif

#define FS_MODULE_NAME  "autofs4"
int load_autofs4_module(void);

/* The -s (sloppy) option to mount is good, if we have it... */

#ifdef HAVE_SLOPPY_MOUNT
#define SLOPPYOPT "-s",		/* For use in spawnl() lists */
#define SLOPPY    "-s "		/* For use in strings */
#else
#define SLOPPYOPT
#define SLOPPY
#endif

#define AUTOFS_SUPER_MAGIC 0x00000187L
#define SMB_SUPER_MAGIC    0x0000517BL
#define CIFS_MAGIC_NUMBER  0xFF534D42L

/* This sould be enough for at least 20 host aliases */
#define HOST_ENT_BUF_SIZE	2048

#define CHECK_RATIO	4			/* exp_runfreq = exp_timeout/CHECK_RATIO */
#define AUTOFS_LOCK	"/var/lock/autofs"	/* To serialize access to mount */
#define MOUNTED_LOCK	_PATH_MOUNTED "~"	/* mounts' lock file */
#define MTAB_NOTUPDATED 0x1000			/* mtab succeded but not updated */
#define NOT_MOUNTED     0x0100			/* path notmounted */
#define MNT_FORCE_FAIL	-1
#define _PROC_MOUNTS		"/proc/mounts"
#define _PROC_SELF_MOUNTS	"/proc/self/mounts"

/* Constants for lookup modules */

#define LKP_FAIL	0x0001

#define LKP_INDIRECT	0x0002
#define LKP_DIRECT	0x0004
#define LKP_MULTI	0x0008
#define LKP_NOMATCH	0x0010
#define LKP_MATCH	0x0020
#define LKP_NEXT	0x0040
#define LKP_MOUNT	0x0080
#define LKP_WILD	0x0100
#define LKP_LOOKUP	0x0200
#define LKP_GHOST	0x0400
#define LKP_REREAD	0x0800
#define LKP_NORMAL	0x1000
#define LKP_DISTINCT	0x2000
#define LKP_ERR_MOUNT	0x4000
#define LKP_NOTSUP	0x8000

#define MAX_ERR_BUF	128

#ifdef DEBUG
#define DB(x)           do { x; } while(0)
#else
#define DB(x)           do { } while(0)
#endif

#define min(a, b)	(a <= b ? a : b)

/* Forward declaraion */
struct autofs_point; 

/* mapent cache definition */

#define CHE_FAIL	0x0000
#define CHE_OK		0x0001
#define CHE_UPDATED	0x0002
#define CHE_RMPATH	0x0004
#define CHE_MISSING	0x0008
#define CHE_COMPLETED	0x0010
#define CHE_DUPLICATE	0x0020
#define CHE_UNAVAIL	0x0040

#define NULL_MAP_HASHSIZE	64
#define NEGATIVE_TIMEOUT	10
#define UMOUNT_RETRIES		8
#define EXPIRE_RETRIES		3

static u_int32_t inline hash(const char *key, unsigned int size)
{
	u_int32_t hashval;
	char *s = (char *) key;

	for (hashval = 0; *s != '\0';) {
		hashval += (unsigned char) *s++;
		hashval += (hashval << 10);
		hashval ^= (hashval >> 6);
	}

	hashval += (hashval << 3);
	hashval ^= (hashval >> 11);
	hashval += (hashval << 15);

	return hashval % size;
}

struct mapent_cache {
	pthread_rwlock_t rwlock;
	unsigned int size;
	pthread_mutex_t ino_index_mutex;
	struct list_head *ino_index;
	struct autofs_point *ap;
	struct map_source *map;
	struct mapent **hash;
};

struct stack {
	char *mapent;
	time_t age;
	struct stack *next;
};

struct mapent {
	struct mapent *next;
	struct list_head ino_index;
	pthread_rwlock_t multi_rwlock;
	struct list_head multi_list;
	struct mapent_cache *mc;
	struct map_source *source;
	/* Need to know owner if we're a multi-mount */
	struct mapent *multi;
	/* Parent nesting point within multi-mount */
	struct mapent *parent;
	char *key;
	char *mapent;
	struct stack *stack;
	time_t age;
	/* Time of last mount fail */
	time_t status;
	/* For direct mounts per entry context is kept here */
	int flags;
	/* File descriptor for ioctls */
	int ioctlfd;
	dev_t dev;
	ino_t ino;
};

void cache_lock_cleanup(void *arg);
void cache_readlock(struct mapent_cache *mc);
void cache_writelock(struct mapent_cache *mc);
int cache_try_writelock(struct mapent_cache *mc);
void cache_unlock(struct mapent_cache *mc);
int cache_push_mapent(struct mapent *me, char *mapent);
int cache_pop_mapent(struct mapent *me);
struct mapent_cache *cache_init(struct autofs_point *ap, struct map_source *map);
struct mapent_cache *cache_init_null_cache(struct master *master);
int cache_set_ino_index(struct mapent_cache *mc, const char *key, dev_t dev, ino_t ino);
/* void cache_set_ino(struct mapent *me, dev_t dev, ino_t ino); */
struct mapent *cache_lookup_ino(struct mapent_cache *mc, dev_t dev, ino_t ino);
struct mapent *cache_lookup_first(struct mapent_cache *mc);
struct mapent *cache_lookup_next(struct mapent_cache *mc, struct mapent *me);
struct mapent *cache_lookup_key_next(struct mapent *me);
struct mapent *cache_lookup(struct mapent_cache *mc, const char *key);
struct mapent *cache_lookup_distinct(struct mapent_cache *mc, const char *key);
struct mapent *cache_lookup_offset(const char *prefix, const char *offset, int start, struct list_head *head);
struct mapent *cache_partial_match(struct mapent_cache *mc, const char *prefix);
struct mapent *cache_partial_match_wild(struct mapent_cache *mc, const char *prefix);
int cache_add(struct mapent_cache *mc, struct map_source *ms, const char *key, const char *mapent, time_t age);
int cache_update_offset(struct mapent_cache *mc, const char *mkey, const char *key, const char *mapent, time_t age);
void cache_update_negative(struct mapent_cache *mc, struct map_source *ms, const char *key, time_t timeout);
int cache_set_parents(struct mapent *mm);
int cache_update(struct mapent_cache *mc, struct map_source *ms, const char *key, const char *mapent, time_t age);
int cache_delete(struct mapent_cache *mc, const char *key);
int cache_delete_offset(struct mapent_cache *mc, const char *key);
void cache_multi_readlock(struct mapent *me);
void cache_multi_writelock(struct mapent *me);
void cache_multi_unlock(struct mapent *me);
int cache_delete_offset_list(struct mapent_cache *mc, const char *key);
void cache_release(struct map_source *map);
void cache_clean_null_cache(struct mapent_cache *mc);
void cache_release_null_cache(struct master *master);
struct mapent *cache_enumerate(struct mapent_cache *mc, struct mapent *me);
char *cache_get_offset(const char *prefix, char *offset, int start, struct list_head *head, struct list_head **pos);

/* Utility functions */

char **add_argv(int argc, char **argv, char *str);
char **append_argv(int argc1, char **argv1, int argc2, char **argv2);
const char **copy_argv(int argc, const char **argv);
int compare_argv(int argc1, const char **argv1, int argc2, const char **argv2);
int free_argv(int argc, const char **argv);

void dump_core(void);
int aquire_lock(void);
void release_lock(void);
int spawnl(unsigned logopt, const char *prog, ...);
int spawnv(unsigned logopt, const char *prog, const char *const *argv);
int spawn_mount(unsigned logopt, ...);
int spawn_bind_mount(unsigned logopt, ...);
int spawn_umount(unsigned logopt, ...);
void reset_signals(void);
int do_mount(struct autofs_point *ap, const char *root, const char *name,
	     int name_len, const char *what, const char *fstype,
	     const char *options);
int mkdir_path(const char *path, mode_t mode);
int rmdir_path(struct autofs_point *ap, const char *path, dev_t dev);

/* Prototype for module functions */

/* lookup module */

#define AUTOFS_LOOKUP_VERSION 5

#define KEY_MAX_LEN    NAME_MAX
#define MAPENT_MAX_LEN 16384
#define PARSE_MAX_BUF	KEY_MAX_LEN + MAPENT_MAX_LEN + 2

int lookup_nss_read_master(struct master *master, time_t age);
int lookup_nss_read_map(struct autofs_point *ap, struct map_source *source, time_t age);
int lookup_enumerate(struct autofs_point *ap,
	int (*fn)(struct autofs_point *,struct mapent *, int), time_t now);
int lookup_ghost(struct autofs_point *ap, const char *root);
int lookup_nss_mount(struct autofs_point *ap, struct map_source *source, const char *name, int name_len);
void lookup_close_lookup(struct autofs_point *ap);
void lookup_prune_one_cache(struct autofs_point *ap, struct mapent_cache *mc, time_t age);
int lookup_prune_cache(struct autofs_point *ap, time_t age);
struct mapent *lookup_source_valid_mapent(struct autofs_point *ap, const char *key, unsigned int type);
struct mapent *lookup_source_mapent(struct autofs_point *ap, const char *key, unsigned int type);
int lookup_source_close_ioctlfd(struct autofs_point *ap, const char *key);

#ifdef MODULE_LOOKUP
int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context);
int lookup_read_master(struct master *master, time_t age, void *context);
int lookup_read_map(struct autofs_point *, time_t, void *context);
int lookup_mount(struct autofs_point *, const char *, int, void *);
int lookup_done(void *);
#endif
typedef int (*lookup_init_t) (const char *, int, const char *const *, void **);
typedef int (*lookup_read_master_t) (struct master *master, time_t, void *);
typedef int (*lookup_read_map_t) (struct autofs_point *, time_t, void *);
typedef int (*lookup_mount_t) (struct autofs_point *, const char *, int, void *);
typedef int (*lookup_done_t) (void *);

struct lookup_mod {
	lookup_init_t lookup_init;
	lookup_read_master_t lookup_read_master;
	lookup_read_map_t lookup_read_map;
	lookup_mount_t lookup_mount;
	lookup_done_t lookup_done;
	void *dlhandle;
	void *context;
};

struct lookup_mod *open_lookup(const char *name, const char *err_prefix,
			       const char *mapfmt, int argc, const char *const *argv);
int close_lookup(struct lookup_mod *);

/* parse module */

#define AUTOFS_PARSE_VERSION 5

#ifdef MODULE_PARSE
int parse_init(int argc, const char *const *argv, void **context);
int parse_mount(struct autofs_point *ap, const char *name,
		int name_len, const char *mapent, void *context);
int parse_done(void *);
#endif
typedef int (*parse_init_t) (int, const char *const *, void **);
typedef int (*parse_mount_t) (struct autofs_point *, const char *, int, const char *, void *);
typedef int (*parse_done_t) (void *);

struct parse_mod {
	parse_init_t parse_init;
	parse_mount_t parse_mount;
	parse_done_t parse_done;
	void *dlhandle;
	void *context;
};

struct parse_mod *open_parse(const char *name, const char *err_prefix,
			     int argc, const char *const *argv);
int close_parse(struct parse_mod *);

/* mount module */

#define AUTOFS_MOUNT_VERSION 4

#ifdef MODULE_MOUNT
int mount_init(void **context);
int mount_mount(struct autofs_point *ap, const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options, void *context);
int mount_done(void *context);
#endif
typedef int (*mount_init_t) (void **);
typedef int (*mount_mount_t) (struct autofs_point *, const char *, const char *, int,
				const char *, const char *, const char *, void *);
typedef int (*mount_done_t) (void *);

struct mount_mod {
	mount_init_t mount_init;
	mount_mount_t mount_mount;
	mount_done_t mount_done;
	void *dlhandle;
	void *context;
};

struct mount_mod *open_mount(const char *name, const char *err_prefix);
int close_mount(struct mount_mod *);

/* buffer management */

size_t _strlen(const char *str, size_t max);
int cat_path(char *buf, size_t len, const char *dir, const char *base);
int ncat_path(char *buf, size_t len,
              const char *dir, const char *base, size_t blen);
int _strncmp(const char *s1, const char *s2, size_t n);

/* Core automount definitions */

#ifndef MNT_DETACH
#define MNT_DETACH	0x00000002	/* Just detach from the tree */
#endif

struct startup_cond {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	struct autofs_point *ap;
	char *root;
	unsigned int done;
	unsigned int status;
};

int handle_mounts_startup_cond_init(struct startup_cond *suc);
void handle_mounts_startup_cond_destroy(void *arg);

struct master_readmap_cond {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	pthread_t thid;		 /* map reader thread id */
	struct master *master;
	time_t age;		 /* Last time read */
	enum states state;	 /* Next state */
	unsigned int signaled;   /* Condition has been signaled */
	unsigned int busy;	 /* Map read in progress. */
};

struct pending_args {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	unsigned int signaled;		/* Condition has been signaled */
	struct autofs_point *ap;	/* autofs mount we are working on */
	int status;			/* Return status */
	int type;			/* Type of packet */
	int ioctlfd;			/* Mount ioctl fd */
	struct mapent_cache *mc;	/* Cache Containing entry */
	char name[PATH_MAX];		/* Name field of the request */
	dev_t dev;			/* device number of mount */
	unsigned int len;		/* Name field len */
	uid_t uid;			/* uid of requestor */
	gid_t gid;			/* gid of requestor */
	unsigned long wait_queue_token;	/* Associated kernel wait token */
};

#ifdef INCLUDE_PENDING_FUNCTIONS
static void pending_cond_destroy(void *arg)
{
	struct pending_args *mt = (struct pending_args *) arg;
	int status;
	status = pthread_cond_destroy(&mt->cond);
	if (status)
		fatal(status);
}

static void pending_mutex_destroy(void *arg)
{
	struct pending_args *mt = (struct pending_args *) arg;
	int status = pthread_mutex_destroy(&mt->mutex);
	if (status)
		fatal(status);
}

static void free_pending_args(void *arg)
{
	struct pending_args *mt = (struct pending_args *) arg;
	free(mt);
}

static void pending_mutex_lock(void *arg)
{
        struct pending_args *mt = (struct pending_args *) arg;
        int status = pthread_mutex_lock(&mt->mutex);
        if (status)
                fatal(status);
}

static void pending_mutex_unlock(void *arg)
{
        struct pending_args *mt = (struct pending_args *) arg;
        int status = pthread_mutex_unlock(&mt->mutex);
        if (status)
                fatal(status);
}
#endif

struct thread_stdenv_vars {
	uid_t uid;
	gid_t gid;
	char *user;
	char *group;
	char *home;
};

extern pthread_key_t key_thread_stdenv_vars;

struct kernel_mod_version {
	unsigned int major;
	unsigned int minor;
};

/* Enable/disable gohsted directories */
#define MOUNT_FLAG_GHOST		0x0001

/* Directory created for this mount? */
#define MOUNT_FLAG_DIR_CREATED		0x0002

/* Use random policy when selecting a host from which to mount */
#define MOUNT_FLAG_RANDOM_SELECT	0x0004

/* Mount being re-mounted */
#define MOUNT_FLAG_REMOUNT		0x0008

/* Use server weight only for selection */
#define MOUNT_FLAG_USE_WEIGHT_ONLY	0x0010

/* Don't use bind mounts even when system supports them */
#define MOUNT_FLAG_NOBIND		0x0020

/* Use symlinks instead of bind mounting local mounts */
#define MOUNT_FLAG_SYMLINK		0x0040

struct autofs_point {
	pthread_t thid;
	char *path;			/* Mount point name */
	char *pref;			/* amd prefix */
	int pipefd;			/* File descriptor for pipe */
	int kpipefd;			/* Kernel end descriptor for pipe */
	int ioctlfd;			/* File descriptor for ioctls */
	int logpri_fifo;		/* FIFO used for changing log levels */
	dev_t dev;			/* "Device" number assigned by kernel */
	struct master_mapent *entry;	/* Master map entry for this mount */
	unsigned int type;		/* Type of map direct or indirect */
	time_t exp_runfreq;		/* Frequency for polling for timeouts */
	time_t negative_timeout;	/* timeout in secs for failed mounts */
	unsigned int flags;		/* autofs mount flags */
	unsigned int logopt;		/* Per map logging */
	pthread_t exp_thread;		/* Thread that is expiring */
	pthread_t readmap_thread;	/* Thread that is reading maps */
	enum states state;		/* Current state */
	int state_pipe[2];		/* State change router pipe */
	struct autofs_point *parent;	/* Owner of mounts list for submount */
	pthread_mutex_t mounts_mutex;	/* Protect mount lists */
	struct list_head mounts;	/* List of autofs mounts at current level */
	struct list_head amdmounts;	/* List of non submount amd mounts */
	unsigned int submount;		/* Is this a submount */
	unsigned int shutdown;		/* Shutdown notification */
	unsigned int submnt_count;	/* Number of submounts */
	struct list_head submounts;	/* List of child submounts */
};

/* Foreably unlink existing mounts at startup. */
extern int do_force_unlink;

/* Standard functions used by daemon or modules */

#define	MOUNT_OFFSET_OK		0
#define	MOUNT_OFFSET_FAIL	-1
#define MOUNT_OFFSET_IGNORE	-2

void *handle_mounts(void *arg);
int umount_multi(struct autofs_point *ap, const char *path, int incl);
int do_expire(struct autofs_point *ap, const char *name, int namelen);
void *expire_proc_indirect(void *);
void *expire_proc_direct(void *);
int expire_offsets_direct(struct autofs_point *ap, struct mapent *me, int now);
int mount_autofs_indirect(struct autofs_point *ap, const char *root);
int do_mount_autofs_direct(struct autofs_point *ap, struct mnt_list *mnts, struct mapent *me, time_t timeout);
int mount_autofs_direct(struct autofs_point *ap);
int mount_autofs_offset(struct autofs_point *ap, struct mapent *me, const char *root, const char *offset);
void submount_signal_parent(struct autofs_point *ap, unsigned int success);
void close_mount_fds(struct autofs_point *ap);
int umount_autofs(struct autofs_point *ap, const char *root, int force);
int umount_autofs_indirect(struct autofs_point *ap, const char *root);
int do_umount_autofs_direct(struct autofs_point *ap, struct mnt_list *mnts, struct mapent *me);
int umount_autofs_direct(struct autofs_point *ap);
int umount_autofs_offset(struct autofs_point *ap, struct mapent *me);
int handle_packet_expire_indirect(struct autofs_point *ap, autofs_packet_expire_indirect_t *pkt);
int handle_packet_expire_direct(struct autofs_point *ap, autofs_packet_expire_direct_t *pkt);
int handle_packet_missing_indirect(struct autofs_point *ap, autofs_packet_missing_indirect_t *pkt);
int handle_packet_missing_direct(struct autofs_point *ap, autofs_packet_missing_direct_t *pkt);
void rm_unwanted(struct autofs_point *ap, const char *path, int incl);
int count_mounts(struct autofs_point *ap, const char *path, dev_t dev);

#define mounts_mutex_lock(ap) \
do { \
	int _m_lock = pthread_mutex_lock(&ap->mounts_mutex); \
	if (_m_lock) \
		fatal(_m_lock); \
} while (0)

#define mounts_mutex_unlock(ap) \
do { \
	int _m_unlock = pthread_mutex_unlock(&ap->mounts_mutex); \
	if (_m_unlock) \
		fatal(_m_unlock); \
} while(0)

/* Expire alarm handling routines */
int alarm_start_handler(void);
int alarm_add(struct autofs_point *ap, time_t seconds);
void alarm_delete(struct autofs_point *ap);

/*
 * Use CLOEXEC flag for open(), pipe(), fopen() (read-only case) and
 * socket() if possible.
 */
static int cloexec_works;

static inline void check_cloexec(int fd)
{
	if (cloexec_works == 0) {
		int fl = fcntl(fd, F_GETFD);
		if (fl != -1)
			cloexec_works = (fl & FD_CLOEXEC) ? 1 : -1;
	}
	if (cloexec_works > 0)
		return;
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	return;
}

static inline int open_fd(const char *path, int flags)
{
	int fd;

#if defined(O_CLOEXEC) && defined(SOCK_CLOEXEC)
	if (cloexec_works != -1)
		flags |= O_CLOEXEC;
#endif
	fd = open(path, flags);
	if (fd == -1)
		return -1;
	check_cloexec(fd);
	return fd;
}

static inline int open_fd_mode(const char *path, int flags, int mode)
{
	int fd;

#if defined(O_CLOEXEC) && defined(SOCK_CLOEXEC)
	if (cloexec_works != -1)
		flags |= O_CLOEXEC;
#endif
	fd = open(path, flags, mode);
	if (fd == -1)
		return -1;
	check_cloexec(fd);
	return fd;
}

static inline int open_pipe(int pipefd[2])
{
	int ret;

#if defined(O_CLOEXEC) && defined(SOCK_CLOEXEC) && defined(__have_pipe2)
	if (cloexec_works != -1) {
		ret = pipe2(pipefd, O_CLOEXEC);
		if (ret != -1)
			return 0;
		if (errno != EINVAL)
			return -1;
	}
#endif
	ret = pipe(pipefd);
	if (ret == -1)
		return -1;
	check_cloexec(pipefd[0]);
	check_cloexec(pipefd[1]);
	return 0;
}

static inline int open_sock(int domain, int type, int protocol)
{
	int fd;

#ifdef SOCK_CLOEXEC
	if (cloexec_works != -1)
		type |= SOCK_CLOEXEC;
#endif
	fd = socket(domain, type, protocol);
	if (fd == -1)
		return -1;
	check_cloexec(fd);
	return fd;
}

static inline FILE *open_fopen_r(const char *path)
{
	FILE *f;

#if defined(O_CLOEXEC) && defined(SOCK_CLOEXEC)
	if (cloexec_works != -1) {
		f = fopen(path, "re");
		if (f != NULL) {
			check_cloexec(fileno(f));
			return f;
		}
	}
#endif
	f = fopen(path, "r");
	if (f == NULL)
		return NULL;
	check_cloexec(fileno(f));
	return f;
}

static inline FILE *open_setmntent_r(const char *table)
{
	FILE *tab;

#if defined(O_CLOEXEC) && defined(SOCK_CLOEXEC)
	if (cloexec_works != -1) {
		tab = setmntent(table, "re");
		if (tab != NULL) {
			check_cloexec(fileno(tab));
			return tab;
		}
	}
#endif
	tab = fopen(table, "r");
	if (tab == NULL)
		return NULL;
	check_cloexec(fileno(tab));
	return tab;
}

#endif

