/* ----------------------------------------------------------------------- *
 *
 *  master.h - header file for master map parser utility routines.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net>
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

#ifndef MASTER_H
#define MASTER_H

#define MAP_FLAG_FORMAT_AMD	0x0001

struct map_source {
	unsigned int flags;
	char *type;
	char *format;
	char *name;
	time_t exp_timeout;		/* Timeout for expiring mounts */
	time_t age;
	unsigned int master_line;
	struct mapent_cache *mc;
	unsigned int stale;
	unsigned int recurse;
	unsigned int depth;
	struct lookup_mod *lookup;
	int argc;
	const char **argv;
	struct map_source *instance;
	struct map_source *next;
};

struct master_mapent {
	char *path;
	pthread_t thid;
	time_t age;
	struct master *master;
	pthread_rwlock_t source_lock;
	pthread_mutex_t current_mutex;
	pthread_cond_t current_cond;
	struct map_source *current;
	struct map_source *maps;
	struct autofs_point *ap;
	struct list_head list;
	struct list_head join;
};

struct master {
	char *name;
	unsigned int recurse;
	unsigned int depth;
	unsigned int reading;
	unsigned int read_fail;
	unsigned int default_ghost;
	unsigned int default_logging;
	unsigned int default_timeout;
	unsigned int logopt;
	struct mapent_cache *nc;
	struct list_head mounts;
	struct list_head completed;
};

/* From the yacc master map parser */

void master_init_scan(void);
int master_parse_entry(const char *, unsigned int, unsigned int, time_t);

/* From master.c master parser utility routines */

void master_mutex_lock(void);
void master_mutex_unlock(void);
void master_mutex_lock_cleanup(void *);
void master_set_default_timeout(void);
void master_set_default_ghost_mode(void);
int master_add_autofs_point(struct master_mapent *, unsigned, unsigned, unsigned, int);
void master_free_autofs_point(struct autofs_point *);
struct map_source *
master_add_map_source(struct master_mapent *, char *, char *, time_t, int, const char **);
struct map_source *
master_find_map_source(struct master_mapent *, const char *, const char *, int, const char **);
void master_free_map_source(struct map_source *, unsigned int);
struct map_source *
master_find_source_instance(struct map_source *, const char *, const char *, int, const char **);
struct map_source *
master_add_source_instance(struct map_source *, const char *, const char *, time_t, int, const char **);
void clear_stale_instances(struct map_source *);
void send_map_update_request(struct autofs_point *);
void master_source_writelock(struct master_mapent *);
void master_source_readlock(struct master_mapent *);
void master_source_unlock(struct master_mapent *);
void master_source_lock_cleanup(void *);
void master_source_current_wait(struct master_mapent *);
void master_source_current_signal(struct master_mapent *);
struct master_mapent *master_find_mapent(struct master *, const char *);
struct autofs_point *__master_find_submount(struct autofs_point *, const char *);
struct autofs_point *master_find_submount(struct autofs_point *, const char *);
struct amd_entry *__master_find_amdmount(struct autofs_point *, const char *);
struct amd_entry *master_find_amdmount(struct autofs_point *, const char *);
struct master_mapent *master_new_mapent(struct master *, const char *, time_t);
void master_add_mapent(struct master *, struct master_mapent *);
void master_remove_mapent(struct master_mapent *);
void master_free_mapent_sources(struct master_mapent *, unsigned int);
void master_free_mapent(struct master_mapent *);
struct master *master_new(const char *, unsigned int, unsigned int);
int master_read_master(struct master *, time_t, int);
int master_submount_list_empty(struct autofs_point *ap);
int master_notify_submount(struct autofs_point *, const char *path, enum states);
void master_notify_state_change(struct master *, int);
int master_mount_mounts(struct master *, time_t, int);
int dump_map(struct master *, const char *, const char *);
int master_show_mounts(struct master *);
unsigned int master_get_logopt(void);
int master_list_empty(struct master *);
int master_done(struct master *);
int master_kill(struct master *);

#endif
