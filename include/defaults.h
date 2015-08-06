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
 *   version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

#ifndef DEFAULTS_H
#define DEFAULTS_H

#define DEFAULT_MASTER_MAP_NAME	"auto.master"

#define DEFAULT_TIMEOUT			"600"
#define DEFAULT_NEGATIVE_TIMEOUT	"60"
#define DEFAULT_MOUNT_WAIT		"-1"
#define DEFAULT_UMOUNT_WAIT		"12"
#define DEFAULT_BROWSE_MODE		"1"
#define DEFAULT_LOGGING			"none"
#define DEFAULT_FORCE_STD_PROG_MAP_ENV	"0"

#define DEFAULT_LDAP_TIMEOUT		"-1"
#define DEFAULT_LDAP_NETWORK_TIMEOUT	"8"

#define DEFAULT_MAP_OBJ_CLASS		"nisMap"
#define DEFAULT_ENTRY_OBJ_CLASS		"nisObject"
#define DEFAULT_MAP_ATTR		"nisMapName"
#define DEFAULT_ENTRY_ATTR		"cn"
#define DEFAULT_VALUE_ATTR		"nisMapEntry"

#define DEFAULT_MOUNT_NFS_DEFAULT_PROTOCOL	"3"
#define DEFAULT_APPEND_OPTIONS		"1"
#define DEFAULT_AUTH_CONF_FILE		AUTOFS_MAP_DIR "/autofs_ldap_auth.conf"

#define DEFAULT_MAP_HASH_TABLE_SIZE	"1024"

/* Config entry flags */
#define CONF_NONE			0x00000000
#define CONF_ENV			0x00000001
#define CONF_NOTUSED			0x00000002
#define CONF_NOTSUP			0x00000004
#define CONF_BROWSABLE_DIRS		0x00000008
#define CONF_MOUNT_TYPE_AUTOFS		0x00000010
#define CONF_SELECTORS_IN_DEFAULTS	0x00000020
#define CONF_NORMALIZE_HOSTNAMES	0x00000040
#define CONF_PROCESS_LOCK		0x00000080
#define CONF_RESTART_EXISTING_MOUNTS	0x00000100
#define CONF_SHOW_STATFS_ENTRIES	0x00000200
#define CONF_FULLY_QUALIFIED_HOSTS	0x00000400
#define CONF_UNMOUNT_ON_EXIT		0x00000800
#define CONF_AUTOFS_USE_LOFS		0x00001000
#define CONF_DOMAIN_STRIP		0x00002000
#define CONF_NORMALIZE_SLASHES		0x00004000
#define CONF_FORCED_UNMOUNTS 		0x00008000

#define DEFAULT_AMD_NULL_VALUE			NULL

#define DEFAULT_AMD_AUTO_ATTRCACHE		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_AUTO_DIR			"/a"
#define DEFAULT_AMD_AUTOFS_USE_LOFS		"yes"
#define DEFAULT_AMD_BROWSABLE_DIRS		"no"
#define DEFAULT_AMD_CACHE_DURATION		"300"
#define DEFAULT_AMD_CLUSTER			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_DEBUG_MTAB_FILE		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_DEBUG_OPTIONS		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_DISMOUNT_INTERVAL		DEFAULT_TIMEOUT
#define DEFAULT_AMD_DOMAIN_STRIP		"yes"
#define DEFAULT_AMD_EXEC_MAP_TIMEOUT		"10"
#define DEFAULT_AMD_FORCED_UMOUNTS		"no"
#define DEFAULT_AMD_FULLY_QUALIFIED_HOSTS	"no"
#define DEFAULT_AMD_FULL_OS			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_HESIOD_BASE			"automount"
#define DEFAULT_AMD_KARCH			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_LDAP_BASE			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_LDAP_CACHE_MAXMEM		"131072"
#define DEFAULT_AMD_LDAP_CACHE_SECONDS		"0"
#define DEFAULT_AMD_LDAP_HOSTPORTS		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_LDAP_PROTO_VERSION		"2"
#define DEFAULT_AMD_SUB_DOMAIN			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_LOCALHOST_ADDRESS		"localhost"
#define DEFAULT_AMD_LOG_FILE			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_LOG_OPTIONS			"defaults"
#define DEFAULT_AMD_MAP_DEFAULTS		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_MAP_OPTIONS			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_MAP_RELOAD_INTERVAL		"3600"
#define DEFAULT_AMD_MAP_TYPE			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_MOUNT_TYPE			"autofs"
#define DEFAULT_AMD_PID_FILE			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_PORTMAP_PROGRAM		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_PREFERRED_AMQ_PORT		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_ALLOW_ANY_INTERFACE	DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_ALLOW_INSECURE_PORT	DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_PROTO			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_RETRANSMIT_COUNTER	DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_RETRANSMIT_COUNTER_UDP	DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_RETRANSMIT_COUNTER_TCP	DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_RETRANSMIT_COUNTER_TOPLVL DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_RETRY_INTERVAL		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_RETRY_INTERVAL_UDP	DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_RETRY_INTERVAL_TCP	DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_RETRY_INTERVAL_TOPLVL	DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_VERS			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NFS_VERS_PING		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NIS_DOMAIN			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_NORMALIZE_HOSTNAMES		"no"
#define DEFAULT_AMD_NORMALIZE_SLASHES		"yes"
#define DEFAULT_AMD_OS				DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_OSVER			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_PLOCK			"yes"
#define DEFAULT_AMD_PRINT_PID			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_PRINT_VERSION		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_RESTART_MOUNTS		"no"
#define DEFAULT_AMD_SEARCH_PATH			DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_SELECTORS_IN_DEFAULTS	"no"
#define DEFAULT_AMD_SHOW_STATFS_ENTRIES		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_SUN_MAP_SYNTAX		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_TRUNCATE_LOG		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_UMOUNT_ON_EXIT		"yes"
#define DEFAULT_AMD_USE_TCPWRAPPERS		DEFAULT_AMD_NULL_VALUE
#define DEFAULT_AMD_VENDOR			"unknown"
#define DEFAULT_AMD_LINUX_UFS_MOUNT_TYPE	"ext3"

#ifdef WITH_LDAP
struct ldap_schema;
struct ldap_searchdn;
void defaults_free_uris(struct list_head *);
struct list_head *defaults_get_uris(void);
struct ldap_schema *defaults_get_default_schema(void);
void defaults_free_searchdns(struct ldap_searchdn *);
struct ldap_searchdn *defaults_get_searchdns(void);
struct ldap_schema *defaults_get_schema(void);
#endif

unsigned int defaults_read_config(unsigned int);
void defaults_conf_release(void);
const char *defaults_get_master_map(void);
int defaults_master_set(void);
unsigned int defaults_get_timeout(void);
unsigned int defaults_get_negative_timeout(void);
unsigned int defaults_get_browse_mode(void);
unsigned int defaults_get_logging(void);
unsigned int defaults_force_std_prog_map_env(void);
const char *defaults_get_ldap_server(void);
unsigned int defaults_get_ldap_timeout(void);
unsigned int defaults_get_ldap_network_timeout(void);
unsigned int defaults_get_mount_nfs_default_proto(void);
unsigned int defaults_get_append_options(void);
unsigned int defaults_get_mount_wait(void);
unsigned int defaults_get_umount_wait(void);
const char *defaults_get_auth_conf_file(void);
unsigned int defaults_get_map_hash_table_size(void);

unsigned int conf_amd_mount_section_exists(const char *);
char *conf_amd_get_arch(void);
char *conf_amd_get_karch(void);
char *conf_amd_get_os(void);
char *conf_amd_get_os_ver(void);
char *conf_amd_get_vendor(void);
char *conf_amd_get_full_os(void);
char *conf_amd_get_auto_dir(void);
char *conf_amd_get_cluster(void);
unsigned int conf_amd_get_exec_map_timeout(void);
char *conf_amd_get_hesiod_base(void);
char *conf_amd_get_karch(void);
char *conf_amd_get_ldap_base(void);
char *conf_amd_get_ldap_hostports(void);
char *conf_amd_get_sub_domain(void);
char *conf_amd_get_localhost_address(void);
unsigned int conf_amd_get_log_options(void);
char *conf_amd_get_nfs_proto(void);
char *conf_amd_get_nis_domain(void);
unsigned int conf_amd_set_nis_domain(const char *);
char *conf_amd_get_map_defaults(const char *);
char *conf_amd_get_map_type(const char *);
char *conf_amd_get_search_path(const char *);
unsigned int conf_amd_get_dismount_interval(const char *);
char *conf_amd_get_linux_ufs_mount_type(void);
unsigned long conf_amd_get_flags(const char *);

#endif

