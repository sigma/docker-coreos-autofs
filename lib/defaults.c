/* ----------------------------------------------------------------------- *
 *
 *  defaults.h - system initialization defaults.
 *
 *   Copyright 2013 Red Hat, Inc.
 *   Copyright 2006, 2013 Ian Kent <raven@themaw.net>
 *   All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <stdarg.h>

#include "config.h"
#include "list.h"
#include "defaults.h"
#ifdef WITH_LDAP
#include "lookup_ldap.h"
#endif
#include "log.h"
#include "automount.h"

#define AUTOFS_GLOBAL_SECTION		"autofs"
#define AMD_GLOBAL_SECTION		"amd"

/*
 * The configuration location has changed.
 * The name of the configuration is now autofs.conf and it is
 * located in the same directory as the maps. AUTOFS_CONF_DIR
 * remains pointed at the init system configuration.
 */
#define DEFAULT_CONFIG_FILE		AUTOFS_MAP_DIR "/autofs.conf"
#define OLD_CONFIG_FILE			AUTOFS_CONF_DIR "/autofs"
#define MAX_LINE_LEN			256
#define MAX_SECTION_NAME		MAX_LINE_LEN

#define NAME_MASTER_MAP			"master_map_name"

#define NAME_TIMEOUT			"timeout"
#define NAME_NEGATIVE_TIMEOUT		"negative_timeout"
#define NAME_BROWSE_MODE		"browse_mode"
#define NAME_LOGGING			"logging"
#define NAME_FORCE_STD_PROG_MAP_ENV	"force_standard_program_map_env"

#define NAME_LDAP_URI			"ldap_uri"
#define NAME_LDAP_TIMEOUT		"ldap_timeout"
#define NAME_LDAP_NETWORK_TIMEOUT	"ldap_network_timeout"

#define NAME_SEARCH_BASE		"search_base"

#define NAME_MAP_OBJ_CLASS		"map_object_class"
#define NAME_ENTRY_OBJ_CLASS		"entry_object_class"
#define NAME_MAP_ATTR			"map_attribute"
#define NAME_ENTRY_ATTR			"entry_attribute"
#define NAME_VALUE_ATTR			"value_attribute"

#define NAME_MOUNT_NFS_DEFAULT_PROTOCOL	"mount_nfs_default_protocol"
#define NAME_APPEND_OPTIONS		"append_options"
#define NAME_MOUNT_WAIT			"mount_wait"
#define NAME_UMOUNT_WAIT		"umount_wait"
#define NAME_AUTH_CONF_FILE		"auth_conf_file"

#define NAME_MAP_HASH_TABLE_SIZE	"map_hash_table_size"

#define NAME_AMD_ARCH				"arch"
#define NAME_AMD_AUTO_ATTRCACHE			"auto_attrcache"
#define NAME_AMD_AUTO_DIR			"auto_dir"
#define NAME_AMD_AUTOFS_USE_LOFS		"autofs_use_lofs"
#define NAME_AMD_BROWSABLE_DIRS			"browsable_dirs"
#define NAME_AMD_CACHE_DURATION			"cache_duration"
#define NAME_AMD_CLUSTER			"cluster"
#define NAME_AMD_DEBUG_MTAB_FILE		"debug_mtab_file"
#define NAME_AMD_DEBUG_OPTIONS			"debug_options"
#define NAME_AMD_DISMOUNT_INTERVAL		"dismount_interval"
#define NAME_AMD_DOMAIN_STRIP			"domain_strip"
#define NAME_AMD_EXEC_MAP_TIMEOUT		"exec_map_timeout"
#define NAME_AMD_FORCED_UMOUNTS			"forced_unmounts"
#define NAME_AMD_FULLY_QUALIFIED_HOSTS		"fully_qualified_hosts"
#define NAME_AMD_FULL_OS			"full_os"
#define NAME_AMD_HESIOD_BASE			"hesiod_base"
#define NAME_AMD_KARCH				"karch"
#define NAME_AMD_LDAP_BASE			"ldap_base"
#define NAME_AMD_LDAP_CACHE_MAXMEM		"ldap_cache_maxmem"
#define NAME_AMD_LDAP_CACHE_SECONDS		"ldap_cache_seconds"
#define NAME_AMD_LDAP_HOSTPORTS			"ldap_hostports"
#define NAME_AMD_LDAP_PROTO_VERSION		"ldap_proto_version"
#define NAME_AMD_SUB_DOMAIN			"local_domain"
#define NAME_AMD_LOCALHOST_ADDRESS		"localhost_address"
#define NAME_AMD_LOG_FILE			"log_file"
#define NAME_AMD_LOG_OPTIONS			"log_options"
#define NAME_AMD_MAP_DEFAULTS			"map_defaults"
#define NAME_AMD_MAP_OPTIONS			"map_options"
#define NAME_AMD_MAP_RELOAD_INTERVAL		"map_reload_interval"
#define NAME_AMD_MAP_TYPE			"map_type"
#define NAME_AMD_MOUNT_TYPE			"mount_type"
#define NAME_AMD_PID_FILE			"pid_file"
#define NAME_AMD_PORTMAP_PROGRAM		"portmap_program"
#define NAME_AMD_PREFERRED_AMQ_PORT		"preferred_amq_port"
#define NAME_AMD_NFS_ALLOW_ANY_INTERFACE	"nfs_allow_any_interface"
#define NAME_AMD_NFS_ALLOW_INSECURE_PORT	"nfs_allow_insecure_port"
#define NAME_AMD_NFS_PROTO			"nfs_proto"
#define NAME_AMD_NFS_RETRANSMIT_COUNTER		"nfs_retransmit_counter"
#define NAME_AMD_NFS_RETRANSMIT_COUNTER_UDP	"nfs_retransmit_counter_udp"
#define NAME_AMD_NFS_RETRANSMIT_COUNTER_TCP	"nfs_retransmit_counter_tcp"
#define NAME_AMD_NFS_RETRANSMIT_COUNTER_TOPLVL	"nfs_retransmit_counter_toplvl"
#define NAME_AMD_NFS_RETRY_INTERVAL		"nfs_retry_interval"
#define NAME_AMD_NFS_RETRY_INTERVAL_UDP		"nfs_retry_interval_udp"
#define NAME_AMD_NFS_RETRY_INTERVAL_TCP		"nfs_retry_interval_tcp"
#define NAME_AMD_NFS_RETRY_INTERVAL_TOPLVL	"nfs_retry_interval_toplvl"
#define NAME_AMD_NFS_VERS			"nfs_vers"
#define NAME_AMD_NFS_VERS_PING			"nfs_vers_ping"
#define NAME_AMD_NIS_DOMAIN			"nis_domain"
#define NAME_AMD_NORMALIZE_HOSTNAMES		"normalize_hostnames"
#define NAME_AMD_NORMALIZE_SLASHES		"normalize_slashes"
#define NAME_AMD_OS				"os"
#define NAME_AMD_OSVER				"osver"
#define NAME_AMD_PLOCK				"plock"
#define NAME_AMD_PRINT_PID			"print_pid"
#define NAME_AMD_PRINT_VERSION			"print_version"
#define NAME_AMD_RESTART_MOUNTS			"restart_mounts"
#define NAME_AMD_SEARCH_PATH			"search_path"
#define NAME_AMD_SELECTORS_ON_DEFAULT		"selectors_on_default"
#define NAME_AMD_SELECTORS_IN_DEFAULTS		"selectors_in_defaults"
#define NAME_AMD_SHOW_STATFS_ENTRIES		"show_statfs_entries"
#define NAME_AMD_SUN_MAP_SYNTAX			"sun_map_syntax"
#define NAME_AMD_TRUNCATE_LOG			"truncate_log"
#define NAME_AMD_UMOUNT_ON_EXIT			"unmount_on_exit"
#define NAME_AMD_USE_TCPWRAPPERS		"use_tcpwrappers"
#define NAME_AMD_VENDOR				"vendor"
#define NAME_AMD_LINUX_UFS_MOUNT_TYPE		"linux_ufs_mount_type"

/* Status returns */
#define CFG_OK		0x0000
#define CFG_FAIL	0x0001
#define CFG_EXISTS	0x0002
#define CFG_NOTFOUND	0x0004

#define CFG_TABLE_SIZE	128

static const char *default_master_map_name = DEFAULT_MASTER_MAP_NAME;
static const char *default_auth_conf_file  = DEFAULT_AUTH_CONF_FILE;
static const char *autofs_gbl_sec	   = AUTOFS_GLOBAL_SECTION;
static const char *amd_gbl_sec		   = AMD_GLOBAL_SECTION;

struct conf_option {
	char *section;
	char *name;
	char *value;
	unsigned long flags;
	struct conf_option *next;
};

struct conf_cache {
	struct conf_option **hash;
	time_t modified;
};
static pthread_mutex_t conf_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct conf_cache *config = NULL;

static int conf_load_autofs_defaults(void);
static int conf_update(const char *, const char *, const char *, unsigned long);
static void conf_delete(const char *, const char *);
static struct conf_option *conf_lookup(const char *, const char *);

static void defaults_mutex_lock(void)
{
	int status = pthread_mutex_lock(&conf_mutex);
	if (status)
		fatal(status);
}

static void defaults_mutex_unlock(void)
{
	int status = pthread_mutex_unlock(&conf_mutex);
	if (status)
		fatal(status);
}

static void message(unsigned int to_syslog, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	if (to_syslog)
		vsyslog(LOG_CRIT, msg, ap);
	else {
		vfprintf(stderr, msg, ap);
		fputc('\n', stderr);
	}
	va_end(ap);

	return;
}

static int conf_init(void)
{
	struct conf_cache *cc;
	unsigned int size = CFG_TABLE_SIZE;
	unsigned int i;

	cc = malloc(sizeof(struct conf_cache));
	if (!cc)
		return CFG_FAIL;
	cc->modified = 0;

	cc->hash = malloc(size * sizeof(struct conf_option *));
	if (!cc->hash) {
		free(cc);
		return CFG_FAIL;
	}

	for (i = 0; i < size; i++) {
		cc->hash[i] = NULL;
	}

	config = cc;

	return CFG_OK;
}

static void __conf_release(void)
{
	struct conf_cache *cc = config;
	unsigned int size = CFG_TABLE_SIZE;
	struct conf_option *co, *next;
	unsigned int i;

	for (i = 0; i < size; i++) {
		co = cc->hash[i];
		if (co == NULL)
			continue;
		next = co->next;
		free(co->section);
		free(co->name);
		if (co->value)
			free(co->value);
		free(co);

		while (next) {
			co = next;
			next = co->next;
			free(co->section);
			free(co->name);
			if (co->value)
				free(co->value);
			free(co);
		}
		cc->hash[i] = NULL;
	}

	free(cc->hash);
	free(cc);
	config = NULL;

	return;
}

void defaults_conf_release(void)
{
	defaults_mutex_lock();
	__conf_release();
	defaults_mutex_unlock();
	return;
}

static int conf_load_autofs_defaults(void)
{
	struct conf_option *co;
	const char *sec = autofs_gbl_sec;
	int ret;

	ret = conf_update(sec, NAME_TIMEOUT,
			  DEFAULT_TIMEOUT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_NEGATIVE_TIMEOUT,
			  DEFAULT_NEGATIVE_TIMEOUT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_BROWSE_MODE,
			  DEFAULT_BROWSE_MODE, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_LOGGING,
			  DEFAULT_LOGGING, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_LDAP_TIMEOUT,
			  DEFAULT_LDAP_TIMEOUT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_LDAP_NETWORK_TIMEOUT,
			  DEFAULT_LDAP_NETWORK_TIMEOUT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_APPEND_OPTIONS,
			  DEFAULT_APPEND_OPTIONS, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_MOUNT_WAIT,
			  DEFAULT_MOUNT_WAIT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_UMOUNT_WAIT,
			  DEFAULT_UMOUNT_WAIT, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AUTH_CONF_FILE,
			  DEFAULT_AUTH_CONF_FILE, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_MOUNT_NFS_DEFAULT_PROTOCOL,
			  DEFAULT_MOUNT_NFS_DEFAULT_PROTOCOL, CONF_ENV);
	if (ret == CFG_FAIL)
		goto error;

	/* LDAP_URI and SEARCH_BASE can occur multiple times */
	while ((co = conf_lookup(sec, NAME_LDAP_URI)))
		conf_delete(co->section, co->name);

	while ((co = conf_lookup(sec, NAME_SEARCH_BASE)))
		conf_delete(co->section, co->name);

	return 1;

error:
	return 0;
}

static int conf_load_amd_defaults(void)
{
	struct utsname uts;
	const char *sec = amd_gbl_sec;
	char *host_os_name, *host_os_version, *host_arch;
	int ret;

	if (uname(&uts)) {
		host_os_name = uts.sysname;
		host_os_version = uts.release;
		host_arch = uts.machine;
	} else {
		host_os_name = NULL;
		host_os_version = NULL;
		host_arch = NULL;
	}

	ret = conf_update(sec, NAME_AMD_ARCH, host_arch, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_KARCH, host_arch, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_OS, host_os_name, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_OSVER, host_os_version, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_AUTO_DIR,
			  DEFAULT_AMD_AUTO_DIR, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_AUTOFS_USE_LOFS,
			  DEFAULT_AMD_AUTO_DIR, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_BROWSABLE_DIRS,
			  DEFAULT_AMD_BROWSABLE_DIRS, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_CLUSTER,
			  DEFAULT_AMD_CLUSTER, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	/*
	 * DISMOUNT_INTERVAL defers to the autofs default so we
	 * don't set an amd default in the configuration.
	 */
	/*ret = conf_update(sec, NAME_AMD_DISMOUNT_INTERVAL,
			  DEFAULT_AMD_DISMOUNT_INTERVAL, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;*/

	ret = conf_update(sec, NAME_AMD_DOMAIN_STRIP,
			  DEFAULT_AMD_DOMAIN_STRIP, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_EXEC_MAP_TIMEOUT,
			  DEFAULT_AMD_EXEC_MAP_TIMEOUT, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_FORCED_UMOUNTS,
			  DEFAULT_AMD_FORCED_UMOUNTS, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_FULLY_QUALIFIED_HOSTS,
			  DEFAULT_AMD_FULLY_QUALIFIED_HOSTS, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_FULL_OS,
			  DEFAULT_AMD_FULL_OS, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_HESIOD_BASE,
			  DEFAULT_AMD_HESIOD_BASE, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_KARCH, host_arch, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_LDAP_BASE,
			  DEFAULT_AMD_LDAP_BASE, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_LDAP_HOSTPORTS,
			  DEFAULT_AMD_LDAP_HOSTPORTS, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_SUB_DOMAIN,
			  DEFAULT_AMD_SUB_DOMAIN, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_LOCALHOST_ADDRESS,
			  DEFAULT_AMD_LOCALHOST_ADDRESS, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_LOG_OPTIONS,
			  DEFAULT_AMD_LOG_OPTIONS, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_MAP_DEFAULTS,
			  DEFAULT_AMD_MAP_DEFAULTS, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_MAP_TYPE,
			  DEFAULT_AMD_MAP_TYPE, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_NIS_DOMAIN,
			  DEFAULT_AMD_NIS_DOMAIN, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_NORMALIZE_HOSTNAMES,
			  DEFAULT_AMD_NORMALIZE_HOSTNAMES, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_NORMALIZE_SLASHES,
			  DEFAULT_AMD_NORMALIZE_SLASHES, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_OS, host_os_name, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_RESTART_MOUNTS,
			  DEFAULT_AMD_RESTART_MOUNTS, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_SEARCH_PATH,
			  DEFAULT_AMD_SEARCH_PATH, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	/* selectors_on_default is depricated, use selectors_in_defaults */
	ret = conf_update(sec, NAME_AMD_SELECTORS_ON_DEFAULT,
			  DEFAULT_AMD_SELECTORS_IN_DEFAULTS, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_SELECTORS_IN_DEFAULTS,
			  DEFAULT_AMD_SELECTORS_IN_DEFAULTS, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_UMOUNT_ON_EXIT,
			  DEFAULT_AMD_UMOUNT_ON_EXIT, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_VENDOR,
			  DEFAULT_AMD_VENDOR, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;

	ret = conf_update(sec, NAME_AMD_LINUX_UFS_MOUNT_TYPE,
			  DEFAULT_AMD_LINUX_UFS_MOUNT_TYPE, CONF_NONE);
	if (ret == CFG_FAIL)
		goto error;
	return 1;

error:
	return 0;
}

static u_int32_t get_hash(const char *key, unsigned int size)
{
	const char *pkey = key;
	char lkey[PATH_MAX + 1];
	char *plkey = &lkey[0];

	while (*pkey)
		*plkey++ = tolower(*pkey++);
	*plkey = '\0';
	return hash(lkey, size);
}

static int conf_add(const char *section, const char *key, const char *value, unsigned long flags)
{
	struct conf_option *co;
	char *sec, *name, *val, *tmp;
	unsigned int size = CFG_TABLE_SIZE;
	u_int32_t key_hash;
	int ret = CFG_FAIL;

	sec = name = val = tmp = NULL;

	/* Environment overrides file value */
	if (((flags & CONF_ENV) && (tmp = getenv(key))) || value) {
		if (tmp)
			val = strdup(tmp);
		else {
			if (value)
				val = strdup(value);
		}
		if (!val)
			goto error;
	}

	name = strdup(key);
	if (!key)
		goto error;

	sec = strdup(section);
	if (!sec)
		goto error;

	co = malloc(sizeof(struct conf_option));
	if (!co)
		goto error;

	co->section = sec;
	co->name = name;
	co->value = val;
	co->flags = flags;
	co->next = NULL;

	/* Don't change user set values in the environment */
	if (flags & CONF_ENV && value)
		setenv(name, value, 0);

	key_hash = get_hash(key, size);
	if (!config->hash[key_hash])
		config->hash[key_hash] = co;
	else {
		struct conf_option *last = NULL, *next;
		next = config->hash[key_hash];
		while (next) {
			last = next;
			next = last->next;
		}
		last->next = co;
	}

	return CFG_OK;

error:
	if (name)
		free(name);
	if (val)
		free(val);
	if (sec)
		free(sec);

	return ret;
}

static void conf_delete(const char *section, const char *key)
{
	struct conf_option *co, *last;
	unsigned int size = CFG_TABLE_SIZE;
	u_int32_t key_hash;

	last = NULL;
	key_hash = get_hash(key, size);
	for (co = config->hash[key_hash]; co != NULL; co = co->next) {
		if (strcasecmp(section, co->section))
			continue;
		if (!strcasecmp(key, co->name))
			break;
		last = co;
	}

	if (!co)
		return;

	if (last)
		last->next = co->next;
	else
		config->hash[key_hash] = co->next;

	free(co->section);
	free(co->name);
	if (co->value)
		free(co->value);
	free(co);
}

static int conf_update(const char *section,
			const char *key, const char *value,
			unsigned long flags)
{
	struct conf_option *co = NULL;
	int ret;

	ret = CFG_FAIL;
	co = conf_lookup(section, key);
	if (!co)
		return conf_add(section, key, value, flags);
	else {
		char *val = NULL, *tmp = NULL;
		/* Environment overrides file value */
		if (((flags & CONF_ENV) && (tmp = getenv(key))) || value) {
			if (tmp)
				val = strdup(tmp);
			else {
				if (value)
					val = strdup(value);
			}
			if (!val)
				goto error;
		}
		if (co->value)
			free(co->value);
		co->value = val;
		if (flags)
			co->flags = flags;
		/* Don't change user set values in the environment */
		if (flags & CONF_ENV && value)
			setenv(key, value, 0);
	}

	return CFG_OK;

error:
	return ret;
}

static struct conf_option *conf_lookup_key(const char *section, const char *key)
{
	struct conf_option *co;
	u_int32_t key_hash;
	unsigned int size = CFG_TABLE_SIZE;

	key_hash = get_hash(key, size);
	for (co = config->hash[key_hash]; co != NULL; co = co->next) {
		if (strcasecmp(section, co->section))
			continue;
		if (!strcasecmp(key, co->name))
			break;
	}

	return co;
}

static struct conf_option *conf_lookup(const char *section, const char *key)
{
	struct conf_option *co;

	if (!key || !section)
		return NULL;

	if (strlen(key) > PATH_MAX)
		return NULL;

	co = conf_lookup_key(section, key);
	if (!co) {
		/*
		 * Strip "DEFAULT_" and look for config entry for
		 * backward compatibility with old style config names.
		 * Perhaps this should be a case sensitive compare?
		 */
		if (strlen(key) > 8 && !strncasecmp("DEFAULT_", key, 8))
			co = conf_lookup_key(section, key + 8);
	}

	return co;
}

static unsigned int conf_section_exists(const char *section)
{
	struct conf_option *co;
	int ret;

	if (!section)
		return 0;

	ret = 0;
	defaults_mutex_lock();
	co = conf_lookup(section, section);
	if (co)
		ret = 1;
	defaults_mutex_unlock();

	return ret;
}

/*
 * We've changed the key names so we need to check for the
 * config key and it's old name for backward conpatibility.
*/
static int check_set_config_value(const char *section,
				  const char *res, const char *value)
{
	const char *sec;
	int ret;

	if (section)
		sec = section;
	else
		sec = autofs_gbl_sec;

	if (!strcasecmp(res, NAME_LDAP_URI))
		ret = conf_add(sec, res, value, 0);
	else if (!strcasecmp(res, NAME_SEARCH_BASE))
		ret = conf_add(sec, res, value, 0);
	else
		ret = conf_update(sec, res, value, 0);

	return ret;
}

static int parse_line(char *line, char **sec, char **res, char **value)
{
	char *key, *val, *trailer;
	char *tmp;
	int len;

	key = line;

	if (*key == '#' || (*key != '[' && !isalpha(*key)))
		return 0;

	while (*key && isblank(*key))
		key++;

	if (!*key)
		return 0;

	if (*key == '[') {
		char *tmp;
		while (*key && (*key == '[' || isblank(*key)))
			key++;
		tmp = strchr(key, ']');
		if (!tmp)
			return 0;
		*tmp = ' ';
		while (*tmp && isblank(*tmp)) {
			*tmp = '\0';
			tmp--;
		}
		*sec = key;
		*res = NULL;
		*value = NULL;
		return 1;
	}

	if (!(val = strchr(key, '=')))
		return 0;

	tmp = val;

	*val++ = '\0';

	while (isblank(*(--tmp)))
		*tmp = '\0';

	while (*val && (*val == '"' || isblank(*val)))
		val++;

	len = strlen(val);

	if (val[len - 1] == '\n') {
		val[len - 1] = '\0';
		len--;
	}

	trailer = strchr(val, '#');
	if (!trailer)
		trailer = val + len - 1;
	else
		trailer--;

	while (*trailer && (*trailer == '"' || isblank(*trailer)))
		*(trailer--) = '\0';;

	*sec = NULL;
	*res = key;
	*value = val;

	return 1;
}

static int read_config(unsigned int to_syslog, FILE *f, const char *name)
{
	char buf[MAX_LINE_LEN + 2];
	char secbuf[MAX_SECTION_NAME];
	char *new_sec;
	char *res;

	new_sec = NULL;
	while ((res = fgets(buf, MAX_LINE_LEN, f))) {
		char *sec, *key, *value;

		if (strlen(res) > MAX_LINE_LEN) {
			message(to_syslog, "%s was truncated, ignored", res);
			continue;
		}

		sec = key = value = NULL;
		if (!parse_line(res, &sec, &key, &value))
			continue;
		if (sec) {
			strcpy(secbuf, sec);
			new_sec = &secbuf[0];
			conf_update(sec, sec, NULL, 0);
			continue;
		}
		if (!strcasecmp(res, NAME_AMD_MOUNT_TYPE)) {
			message(to_syslog,
				"%s is always autofs, ignored", res);
			continue;
		}
		if (!strcasecmp(res, NAME_AMD_PID_FILE)) {
			message(to_syslog,
				"%s must be specified as a command line"
				" option, ignored", res);
			continue;
		}
		if (!strcasecmp(res, NAME_AMD_RESTART_MOUNTS)) {
			message(to_syslog,
				"%s is always done by autofs, ignored", res);
			continue;
		}
		if (!strcasecmp(res, NAME_AMD_USE_TCPWRAPPERS) ||
		    !strcasecmp(res, NAME_AMD_AUTO_ATTRCACHE) ||
		    !strcasecmp(res, NAME_AMD_PRINT_PID) ||
		    !strcasecmp(res, NAME_AMD_PRINT_VERSION) ||
		    !strcasecmp(res, NAME_AMD_LOG_FILE) ||
		    !strcasecmp(res, NAME_AMD_PREFERRED_AMQ_PORT) ||
		    !strcasecmp(res, NAME_AMD_TRUNCATE_LOG) ||
		    !strcasecmp(res, NAME_AMD_DEBUG_MTAB_FILE) ||
		    !strcasecmp(res, NAME_AMD_DEBUG_OPTIONS) ||
		    !strcasecmp(res, NAME_AMD_SUN_MAP_SYNTAX) ||
		    !strcasecmp(res, NAME_AMD_PORTMAP_PROGRAM) ||
		    !strcasecmp(res, NAME_AMD_NFS_VERS) ||
		    !strcasecmp(res, NAME_AMD_NFS_VERS_PING) ||
		    !strcasecmp(res, NAME_AMD_NFS_PROTO) ||
		    !strcasecmp(res, NAME_AMD_NFS_ALLOW_ANY_INTERFACE) ||
		    !strcasecmp(res, NAME_AMD_NFS_ALLOW_INSECURE_PORT) ||
		    !strcasecmp(res, NAME_AMD_NFS_RETRANSMIT_COUNTER) ||
		    !strcasecmp(res, NAME_AMD_NFS_RETRANSMIT_COUNTER_UDP) ||
		    !strcasecmp(res, NAME_AMD_NFS_RETRANSMIT_COUNTER_TCP) ||
		    !strcasecmp(res, NAME_AMD_NFS_RETRANSMIT_COUNTER_TOPLVL) ||
		    !strcasecmp(res, NAME_AMD_NFS_RETRY_INTERVAL) ||
		    !strcasecmp(res, NAME_AMD_NFS_RETRY_INTERVAL_UDP) ||
		    !strcasecmp(res, NAME_AMD_NFS_RETRY_INTERVAL_TCP) ||
		    !strcasecmp(res, NAME_AMD_NFS_RETRY_INTERVAL_TOPLVL) ||
		    !strcasecmp(res, NAME_AMD_LDAP_CACHE_MAXMEM) ||
		    !strcasecmp(res, NAME_AMD_LDAP_CACHE_SECONDS) ||
		    !strcasecmp(res, NAME_AMD_LDAP_PROTO_VERSION) ||
		    !strcasecmp(res, NAME_AMD_SHOW_STATFS_ENTRIES) ||
		    !strcasecmp(res, NAME_AMD_CACHE_DURATION) ||
		    !strcasecmp(res, NAME_AMD_MAP_RELOAD_INTERVAL) ||
		    !strcasecmp(res, NAME_AMD_MAP_OPTIONS) ||
		    !strcasecmp(res, NAME_AMD_PLOCK)) {
			message(to_syslog,
				"%s is not used by autofs, ignored", res);
			continue;
		}
		check_set_config_value(new_sec, key, value);
	}

	if (!feof(f) || ferror(f)) {
		message(to_syslog,
			"fgets returned error %d while reading config %s",
			ferror(f), name);
		return 0;
	}

	return 0;
}

struct conf_option *save_ldap_option_list(const char *key)
{
	struct conf_option *co, *head, *this, *last;
	unsigned int size = CFG_TABLE_SIZE;
	u_int32_t key_hash;

	key_hash = get_hash(key, size);
	co = config->hash[key_hash];
	if (!co)
		return NULL;
	last = co;

	head = this = NULL;
	while (co) {
		if (strcasecmp(autofs_gbl_sec, co->section)) {
			last = co;
			goto next;
		}

		if (!strcasecmp(co->name, key)) {
			/* Unlink from old */
			if (co == config->hash[key_hash])
				config->hash[key_hash] = co->next;
			else
				last->next = co->next;
			last = co->next;
			co->next = NULL;
			/* Add to new */
			if (this)
				this->next = co;
			this = co;
			/* If none have been found yet */
			if (!head)
				head = co;
			co = last;
			continue;
		}
next:
		co = co->next;
	}

	return head;
}

void restore_ldap_option_list(struct conf_option *list)
{
	struct conf_option *co, *this, *last;
	unsigned int size = CFG_TABLE_SIZE;
	u_int32_t key_hash;

	if (!list)
		return;

	this = list;
	while (this) {
		last = this;
		this = this->next;
	}

	key_hash = get_hash(list->name, size);
	co = config->hash[key_hash];
	config->hash[key_hash] = list;
	if (co)
		last->next = co;

	return;
}

void free_ldap_option_list(struct conf_option *list)
{
	struct conf_option *next, *this;

	if (!list)
		return;

	this = list;
	while (this) {
		next = this->next;
		free(this->section);
		free(this->name);
		free(this->value);
		free(this);
		this = next;
	}

	return;
}

static void clean_ldap_multi_option(const char *key)
{
	const char *sec = autofs_gbl_sec;
	struct conf_option *co;

	while ((co = conf_lookup(sec, key)))
		conf_delete(co->section, co->name);

	return;
}

static int reset_defaults(unsigned int to_syslog)
{
	int ret;

	ret = conf_load_autofs_defaults();
	if (!ret) {
		message(to_syslog, "failed to reset autofs default config");
		return 0;
	}

	ret = conf_load_amd_defaults();
	if (!ret) {
		message(to_syslog, "failed to reset amd default config");
		return 0;
	}

	return 1;
}

/*
 * Read config env variables and check they have been set.
 *
 * This simple minded routine assumes the config file
 * is valid bourne shell script without spaces around "="
 * and that it has valid values.
 */
unsigned int defaults_read_config(unsigned int to_syslog)
{
	FILE *conf, *oldconf;
	struct stat stb, oldstb;
	int ret, stat, oldstat;

	ret = 1;

	conf = oldconf = NULL;

	defaults_mutex_lock();
	if (!config) {
		if (conf_init()) {
			message(to_syslog, "failed to init config");
			ret = 0;
			goto out;
		}
	}

	conf = open_fopen_r(DEFAULT_CONFIG_FILE);
	if (!conf)
		message(to_syslog, "failed to to open config %s",
			DEFAULT_CONFIG_FILE);

	oldconf = open_fopen_r(OLD_CONFIG_FILE);
	if (!oldconf)
		message(to_syslog, "failed to to open old config %s",
			OLD_CONFIG_FILE);

	/* Neither config has been updated */
	stat = oldstat = -1;
	if (conf && oldconf &&
	    (stat = fstat(fileno(conf), &stb) != -1) &&
	    stb.st_mtime <= config->modified &&
	    (oldstat = fstat(fileno(oldconf), &oldstb) == -1) &&
	    oldstb.st_mtime <= config->modified) {
		goto out;
	}

	if (conf || oldconf) {
		if (!reset_defaults(to_syslog)) {
			ret = 0;
			goto out;
		}
	}

	/* Update last modified */
	if (stat != -1) {
		if (oldstat == -1)
			config->modified = stb.st_mtime;
		else {
			if (oldstb.st_mtime < stb.st_mtime)
				config->modified = oldstb.st_mtime;
			else
				config->modified = stb.st_mtime;
		}
	}

	if (conf)
		read_config(to_syslog, conf, DEFAULT_CONFIG_FILE);

	/*
	 * Read the old config file and override the installed
	 * defaults in case user has a stale config following
	 * updating to the new config file location.
	 */
	if (oldconf) {
		struct conf_option *ldap_search_base, *ldap_uris;
		const char *sec = amd_gbl_sec;
		struct conf_option *co;

		ldap_search_base = save_ldap_option_list(NAME_SEARCH_BASE);
		if (ldap_search_base)
			clean_ldap_multi_option(NAME_SEARCH_BASE);

		ldap_uris = save_ldap_option_list(NAME_LDAP_URI);
		if (ldap_uris)
			clean_ldap_multi_option(NAME_LDAP_URI);

		read_config(to_syslog, oldconf, OLD_CONFIG_FILE);

		if (ldap_search_base) {
			co = conf_lookup(sec, NAME_SEARCH_BASE);
			if (co)
				free_ldap_option_list(ldap_search_base);
			else
				restore_ldap_option_list(ldap_search_base);
		}

		if (ldap_uris) {
			co = conf_lookup(sec, NAME_LDAP_URI);
			if (co)
				free_ldap_option_list(ldap_uris);
			else
				restore_ldap_option_list(ldap_uris);
		}
	}
out:
	if (conf)
		fclose(conf);
	if (oldconf)
		fclose(oldconf);
	defaults_mutex_unlock();
	return ret;
}

static char *conf_get_string(const char *section, const char *name)
{
	struct conf_option *co;
	char *val = NULL;

	defaults_mutex_lock();
	co = conf_lookup(section, name);
	if (co && co->value)
		val = strdup(co->value);
	defaults_mutex_unlock();
	return val;
}

static long conf_get_number(const char *section, const char *name)
{
	struct conf_option *co;
	long val = -1;

	defaults_mutex_lock();
	co = conf_lookup(section, name);
	if (co && co->value)
		val = atol(co->value);
	defaults_mutex_unlock();
	return val;
}

static int conf_get_yesno(const char *section, const char *name)
{
	struct conf_option *co;
	int val = -1;

	defaults_mutex_lock();
	co = conf_lookup(section, name);
	if (co && co->value) {
		if (isdigit(*co->value))
			val = atoi(co->value);
		else if (!strcasecmp(co->value, "yes"))
			val = 1;
		else if (!strcasecmp(co->value, "no"))
			val = 0;
	}
	defaults_mutex_unlock();
	return val;
}

#ifdef WITH_LDAP
void defaults_free_uris(struct list_head *list)
{
	struct list_head *next;
	struct ldap_uri *uri;

	if (list_empty(list)) {
		free(list);
		return;
	}

	next = list->next;
	while (next != list) {
		uri = list_entry(next, struct ldap_uri, list);
		next = next->next;
		list_del(&uri->list);
		free(uri->uri);
		free(uri);
	}
	free(list);

	return;
}

static unsigned int add_uris(char *value, struct list_head *list)
{
	char *str, *tok, *ptr = NULL;
	size_t len = strlen(value) + 1;

	str = malloc(len);
	if (!str)
		return 0;
	strcpy(str, value);

	tok = strtok_r(str, " ", &ptr);
	while (tok) {
		struct ldap_uri *new;
		char *uri;

		new = malloc(sizeof(struct ldap_uri));
		if (!new)
			continue;

		uri = strdup(tok);
		if (!uri)
			free(new);
		else {
			new->uri = uri;
			list_add_tail(&new->list, list);
		}

		tok = strtok_r(NULL, " ", &ptr);
	}
	free(str);

	return 1;
}

struct list_head *defaults_get_uris(void)
{
	struct conf_option *co;
	struct list_head *list;

	list = malloc(sizeof(struct list_head));
	if (!list)
		return NULL;
	INIT_LIST_HEAD(list);

	if (!defaults_read_config(0)) {
		free(list);
		return NULL;
	}

	defaults_mutex_lock();
	co = conf_lookup(autofs_gbl_sec, NAME_LDAP_URI);
	if (!co) {
		defaults_mutex_unlock();
		free(list);
		return NULL;
	}

	while (co) {
		if (!strcasecmp(co->name, NAME_LDAP_URI))
			if (co->value)
				add_uris(co->value, list);
		co = co->next;
	}
	defaults_mutex_unlock();

	if (list_empty(list)) {
		free(list);
		list = NULL;
	}

	return list;
}

struct ldap_schema *defaults_get_default_schema(void)
{
	struct ldap_schema *schema;
	char *mc, *ma, *ec, *ea, *va;

	mc = strdup(DEFAULT_MAP_OBJ_CLASS);
	if (!mc)
		return NULL;

	ma = strdup(DEFAULT_MAP_ATTR);
	if (!ma) {
		free(mc);
		return NULL;
	}

	ec = strdup(DEFAULT_ENTRY_OBJ_CLASS);
	if (!ec) {
		free(mc);
		free(ma);
		return NULL;
	}

	ea = strdup(DEFAULT_ENTRY_ATTR);
	if (!ea) {
		free(mc);
		free(ma);
		free(ec);
		return NULL;
	}

	va = strdup(DEFAULT_VALUE_ATTR);
	if (!va) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		return NULL;
	}

	schema = malloc(sizeof(struct ldap_schema));
	if (!schema) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		free(va);
		return NULL;
	}

	schema->map_class = mc;
	schema->map_attr = ma;
	schema->entry_class = ec;
	schema->entry_attr = ea;
	schema->value_attr = va;

	return schema;
}

static struct ldap_searchdn *alloc_searchdn(const char *value)
{
	struct ldap_searchdn *sdn;
	char *val;

	sdn = malloc(sizeof(struct ldap_searchdn));
	if (!sdn)
		return NULL;

	val = strdup(value);
	if (!val) {
		free(sdn);
		return NULL;
	}

	sdn->basedn = val;
	sdn->next = NULL;

	return sdn;
}

void defaults_free_searchdns(struct ldap_searchdn *sdn)
{
	struct ldap_searchdn *this = sdn;
	struct ldap_searchdn *next;

	while (this) {
		next = this->next;
		free(this->basedn);
		free(this);
		this = next;
	}

	return;
}

struct ldap_searchdn *defaults_get_searchdns(void)
{
	struct conf_option *co;
	struct ldap_searchdn *sdn, *last;

	if (!defaults_read_config(0))
		return NULL;

	defaults_mutex_lock();
	co = conf_lookup(autofs_gbl_sec, NAME_SEARCH_BASE);
	if (!co) {
		defaults_mutex_unlock();
		return NULL;
	}

	sdn = last = NULL;

	while (co) {
		struct ldap_searchdn *new;

		if (!co->value || strcasecmp(co->name, NAME_SEARCH_BASE) ) {
			co = co->next;
			continue;
		}

		new = alloc_searchdn(co->value);
		if (!new) {
			defaults_mutex_unlock();
			defaults_free_searchdns(sdn);
			return NULL;
		}

		if (!last)
			last = new;
		else {
			last->next = new;
			last = new;
		}

		if (!sdn)
			sdn = new;

		co = co->next;
	}
	defaults_mutex_unlock();

	return sdn;
}

struct ldap_schema *defaults_get_schema(void)
{
	struct ldap_schema *schema;
	char *mc, *ma, *ec, *ea, *va;
	const char *sec = autofs_gbl_sec;

	mc = conf_get_string(sec, NAME_MAP_OBJ_CLASS);
	if (!mc)
		return NULL;

	ma = conf_get_string(sec, NAME_MAP_ATTR);
	if (!ma) {
		free(mc);
		return NULL;
	}

	ec = conf_get_string(sec, NAME_ENTRY_OBJ_CLASS);
	if (!ec) {
		free(mc);
		free(ma);
		return NULL;
	}

	ea = conf_get_string(sec, NAME_ENTRY_ATTR);
	if (!ea) {
		free(mc);
		free(ma);
		free(ec);
		return NULL;
	}

	va = conf_get_string(sec, NAME_VALUE_ATTR);
	if (!va) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		return NULL;
	}

	schema = malloc(sizeof(struct ldap_schema));
	if (!schema) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		free(va);
		return NULL;
	}

	schema->map_class = mc;
	schema->map_attr = ma;
	schema->entry_class = ec;
	schema->entry_attr = ea;
	schema->value_attr = va;

	return schema;
}
#endif

const char *defaults_get_master_map(void)
{
	char *master = conf_get_string(autofs_gbl_sec, NAME_MASTER_MAP);
	if (!master)
		return strdup(default_master_map_name);

	return (const char *) master;
}

int defaults_master_set(void)
{
	struct conf_option *co;

	defaults_mutex_lock();
	co = conf_lookup(autofs_gbl_sec, NAME_MASTER_MAP);
	defaults_mutex_unlock();
	if (co)
		return 1;
	return 0;
}

unsigned int defaults_get_timeout(void)
{
	long timeout;

	timeout = conf_get_number(autofs_gbl_sec, NAME_TIMEOUT);
	if (timeout < 0)
		timeout = atol(DEFAULT_TIMEOUT);

	return (unsigned int) timeout;
}

unsigned int defaults_get_negative_timeout(void)
{
	long n_timeout;

	n_timeout = conf_get_number(autofs_gbl_sec, NAME_NEGATIVE_TIMEOUT);
	if (n_timeout <= 0)
		n_timeout = atol(DEFAULT_NEGATIVE_TIMEOUT);

	return (unsigned int) n_timeout;
}

unsigned int defaults_get_browse_mode(void)
{
	int res;

	res = conf_get_yesno(autofs_gbl_sec, NAME_BROWSE_MODE);
	if (res < 0)
		res = atoi(DEFAULT_BROWSE_MODE);

	return res;
}

unsigned int defaults_get_logging(void)
{
	char *res;
	unsigned int logging = LOGOPT_NONE;

	res = conf_get_string(autofs_gbl_sec, NAME_LOGGING);
	if (!res)
		return logging;

	if (!strcasecmp(res, "none"))
		logging = LOGOPT_NONE;
	else {
		if (!strcasecmp(res, "verbose"))
			logging |= LOGOPT_VERBOSE;

		if (!strcasecmp(res, "debug"))
			logging |= LOGOPT_DEBUG;
	}

	free(res);

	return logging;
}

unsigned int defaults_force_std_prog_map_env(void)
{
	int res;

	res = conf_get_yesno(autofs_gbl_sec, NAME_FORCE_STD_PROG_MAP_ENV);
	if (res < 0)
		res = atoi(DEFAULT_FORCE_STD_PROG_MAP_ENV);

	return res;
}

unsigned int defaults_get_ldap_timeout(void)
{
	int res;

	res = conf_get_number(autofs_gbl_sec, NAME_LDAP_TIMEOUT);
	if (res < 0)
		res = atoi(DEFAULT_LDAP_TIMEOUT);

	return res;
}

unsigned int defaults_get_ldap_network_timeout(void)
{
	int res;

	res = conf_get_number(autofs_gbl_sec, NAME_LDAP_NETWORK_TIMEOUT);
	if (res < 0)
		res = atoi(DEFAULT_LDAP_NETWORK_TIMEOUT);

	return res;
}

unsigned int defaults_get_mount_nfs_default_proto(void)
{
	int proto;

	proto = conf_get_number(autofs_gbl_sec, NAME_MOUNT_NFS_DEFAULT_PROTOCOL);
	if (proto < 2 || proto > 4)
		proto = atoi(DEFAULT_MOUNT_NFS_DEFAULT_PROTOCOL);

	return (unsigned int) proto;
}

unsigned int defaults_get_append_options(void)
{
	int res;

	res = conf_get_yesno(autofs_gbl_sec, NAME_APPEND_OPTIONS);
	if (res < 0)
		res = atoi(DEFAULT_APPEND_OPTIONS);

	return res;
}

unsigned int defaults_get_mount_wait(void)
{
	long wait;

	wait = conf_get_number(autofs_gbl_sec, NAME_MOUNT_WAIT);
	if (wait < 0)
		wait = atoi(DEFAULT_MOUNT_WAIT);

	return (unsigned int) wait;
}

unsigned int defaults_get_umount_wait(void)
{
	long wait;

	wait = conf_get_number(autofs_gbl_sec, NAME_UMOUNT_WAIT);
	if (wait < 0)
		wait = atoi(DEFAULT_UMOUNT_WAIT);

	return (unsigned int) wait;
}

const char *defaults_get_auth_conf_file(void)
{
	char *cf;

	cf = conf_get_string(autofs_gbl_sec, NAME_AUTH_CONF_FILE);
	if (!cf)
		return strdup(default_auth_conf_file);

	return (const char *) cf;
}

unsigned int defaults_get_map_hash_table_size(void)
{
	long size;

	size = conf_get_number(autofs_gbl_sec, NAME_MAP_HASH_TABLE_SIZE);
	if (size < 0)
		size = atoi(DEFAULT_MAP_HASH_TABLE_SIZE);

	return (unsigned int) size;
}

unsigned int conf_amd_mount_section_exists(const char *section)
{
	return conf_section_exists(section);
}

char *conf_amd_get_arch(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_ARCH);
}

char *conf_amd_get_karch(void)
{
	char *tmp = conf_get_string(amd_gbl_sec, NAME_AMD_KARCH);
	if (!tmp)
		tmp = conf_amd_get_arch();

	return tmp;
}

char *conf_amd_get_os(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_OS);
}

char *conf_amd_get_os_ver(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_OSVER);
}

char *conf_amd_get_vendor(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_VENDOR);
}

char *conf_amd_get_full_os(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_FULL_OS);
}

char *conf_amd_get_auto_dir(void)
{
	char *tmp = conf_get_string(amd_gbl_sec, NAME_AMD_AUTO_DIR);
	if (!tmp)
		return strdup(DEFAULT_AMD_AUTO_DIR);

	return tmp;
}

char *conf_amd_get_cluster(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_CLUSTER);
}

unsigned int conf_amd_get_exec_map_timeout(void)
{
	long tmp = conf_get_number(amd_gbl_sec, NAME_AMD_EXEC_MAP_TIMEOUT);
	if (tmp == -1)
		tmp = atoi(DEFAULT_AMD_EXEC_MAP_TIMEOUT);

	return (unsigned int) tmp;
}

char *conf_amd_get_hesiod_base(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_HESIOD_BASE);
}

char *conf_amd_get_ldap_base(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_LDAP_BASE);
}

char *conf_amd_get_ldap_hostports(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_LDAP_HOSTPORTS);
}

unsigned int conf_amd_get_ldap_proto_version(void)
{
	long tmp = conf_get_number(amd_gbl_sec, NAME_AMD_LDAP_PROTO_VERSION);
	if (tmp == -1)
		tmp = atoi(DEFAULT_AMD_LDAP_PROTO_VERSION);

	return (unsigned int) tmp;
}

char *conf_amd_get_sub_domain(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_SUB_DOMAIN);
}

char *conf_amd_get_localhost_address(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_LOCALHOST_ADDRESS);
}

unsigned int conf_amd_get_log_options(void)
{
	int log_level = -1;
	char *tmp = conf_get_string(amd_gbl_sec, NAME_AMD_LOG_OPTIONS);
	if (tmp) {
		if (strstr(tmp, "debug") || strstr(tmp, "all")) {
			if (log_level < LOG_DEBUG)
				log_level = LOG_DEBUG;
		}
		if (strstr(tmp, "info") ||
		    strstr(tmp, "user") ||
		    strcmp(tmp, "defaults")) {
			if (log_level < LOG_INFO)
				log_level = LOG_INFO;
		}
		if (strstr(tmp, "notice")) {
			if (log_level < LOG_NOTICE)
				log_level = LOG_NOTICE;
		}
		if (strstr(tmp, "warn") ||
		    strstr(tmp, "map") ||
		    strstr(tmp, "stats") ||
		    strstr(tmp, "warning")) {
			if (log_level < LOG_WARNING)
				log_level = LOG_WARNING;
		}
		if (strstr(tmp, "error")) {
			if (log_level < LOG_ERR)
				log_level = LOG_ERR;
		}
		if (strstr(tmp, "fatal")) {
			if (log_level < LOG_CRIT)
				log_level = LOG_CRIT;
		}
		free(tmp);
	}

	if (log_level == -1)
		log_level = LOG_ERR;

	return (unsigned int) log_level;
}

char *conf_amd_get_nis_domain(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_NIS_DOMAIN);
}

unsigned int conf_amd_set_nis_domain(const char *domain)
{
	int ret;
	ret = conf_update(amd_gbl_sec, NAME_AMD_NIS_DOMAIN, domain, CONF_NONE);

	return (unsigned int) ret;
}

char *conf_amd_get_map_defaults(const char *section)
{
	char *tmp = NULL;
	if (section)
		tmp = conf_get_string(section, NAME_AMD_MAP_DEFAULTS);
	if (!tmp)
		tmp = conf_get_string(amd_gbl_sec, NAME_AMD_MAP_DEFAULTS);

	return tmp;
}

char *conf_amd_get_map_type(const char *section)
{
	char *tmp = NULL;
	if (section)
		tmp = conf_get_string(section, NAME_AMD_MAP_TYPE);
	if (!tmp)
		tmp = conf_get_string(amd_gbl_sec, NAME_AMD_MAP_TYPE);

	return tmp;
}

char *conf_amd_get_search_path(const char *section)
{
	char *tmp = NULL;
	if (section)
		tmp = conf_get_string(section, NAME_AMD_SEARCH_PATH);
	if (!tmp)
		tmp = conf_get_string(amd_gbl_sec, NAME_AMD_SEARCH_PATH);

	return tmp;
}

unsigned int conf_amd_get_dismount_interval(const char *section)
{
	long tmp = -1;
	if (section)
		tmp = conf_get_number(section, NAME_AMD_DISMOUNT_INTERVAL);
	if (tmp == -1)
		tmp = conf_get_number(amd_gbl_sec, NAME_AMD_DISMOUNT_INTERVAL);
	if (tmp == -1)
		tmp = defaults_get_timeout();
	/*
	 * This won't happen as defaults_get_timeout() will return
	 * the autofs setting which is used if no other setting is
	 * found.
	 */
	if (tmp == -1)
		tmp = atoi(DEFAULT_TIMEOUT);

	return (unsigned int) tmp;
}

char *conf_amd_get_linux_ufs_mount_type(void)
{
	return conf_get_string(amd_gbl_sec, NAME_AMD_LINUX_UFS_MOUNT_TYPE);
}

unsigned long conf_amd_get_flags(const char *section)
{
	const char *amd = amd_gbl_sec;
	unsigned long flags, tmp;

	/* Always true for us */
	flags = CONF_MOUNT_TYPE_AUTOFS;

	tmp = -1;
	if (section)
		tmp = conf_get_yesno(section, NAME_AMD_BROWSABLE_DIRS);
	if (tmp == -1)
		tmp = conf_get_yesno(amd, NAME_AMD_BROWSABLE_DIRS);
	if (tmp)
		flags |= CONF_BROWSABLE_DIRS;

	tmp = -1;
	if (section)
		tmp = conf_get_yesno(section, NAME_AMD_SELECTORS_IN_DEFAULTS);
	if (tmp == -1)
		tmp = conf_get_yesno(amd, NAME_AMD_SELECTORS_IN_DEFAULTS);
	if (tmp)
		flags |= CONF_SELECTORS_IN_DEFAULTS;

	tmp = conf_get_yesno(amd, NAME_AMD_NORMALIZE_HOSTNAMES);
	if (tmp)
		flags |= CONF_NORMALIZE_HOSTNAMES;

	tmp = conf_get_yesno(amd, NAME_AMD_RESTART_MOUNTS);
	if (tmp)
		flags |= CONF_RESTART_EXISTING_MOUNTS;

	tmp = conf_get_yesno(amd, NAME_AMD_FULLY_QUALIFIED_HOSTS);
	if (tmp)
		flags |= CONF_FULLY_QUALIFIED_HOSTS;

	tmp = conf_get_yesno(amd, NAME_AMD_UMOUNT_ON_EXIT);
	if (tmp)
		flags |= CONF_UNMOUNT_ON_EXIT;

	tmp = -1;
	if (section)
		tmp = conf_get_yesno(section, NAME_AMD_AUTOFS_USE_LOFS);
	if (tmp == -1)
		tmp = conf_get_yesno(amd, NAME_AMD_AUTOFS_USE_LOFS);
	if (tmp)
		flags |= CONF_AUTOFS_USE_LOFS;

	tmp = conf_get_yesno(amd, NAME_AMD_DOMAIN_STRIP);
	if (tmp)
		flags |= CONF_DOMAIN_STRIP;

	tmp = conf_get_yesno(amd, NAME_AMD_NORMALIZE_SLASHES);
	if (tmp)
		flags |= CONF_NORMALIZE_SLASHES;

	tmp = conf_get_yesno(amd, NAME_AMD_FORCED_UMOUNTS);
	if (tmp)
		flags |= CONF_FORCED_UNMOUNTS;

	return flags;
}
