%{
/* ----------------------------------------------------------------------- *
 *   
 *  master_parser.y - master map buffer parser.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/ioctl.h>

#include "automount.h"
#include "master.h"

#define MAX_ERR_LEN	512

extern struct master *master_list;

char **add_argv(int, char **, char *);
const char **copy_argv(int, const char **);
int free_argv(int, const char **);

extern FILE *master_in;
extern char *master_text;
extern int master_lex(void);
extern int master_lineno;
extern void master_set_scan_buffer(const char *);

static char *master_strdup(char *);
static void local_init_vars(void);
static void local_free_vars(void);
static void trim_maptype(char *);
static int add_multi_mapstr(void);

static int master_error(const char *s);
static int master_notify(const char *s);
static int master_msg(const char *s);
 
static char *path;
static char *type;
static char *format;
static long timeout;
static long negative_timeout;
static unsigned symlnk;
static unsigned nobind;
static unsigned ghost;
extern unsigned global_selection_options;
static unsigned random_selection;
static unsigned use_weight;
static char **tmp_argv;
static int tmp_argc;
static char **local_argv;
static int local_argc;

static char errstr[MAX_ERR_LEN];

static unsigned int verbose;
static unsigned int debug;

static int lineno;

#define YYDEBUG 0

#ifndef YYENABLE_NLS
#define YYENABLE_NLS 0
#endif
#ifndef YYLTYPE_IS_TRIVIAL
#define YYLTYPE_IS_TRIVIAL 0
#endif

#if YYDEBUG
static int master_fprintf(FILE *, char *, ...);
#undef YYFPRINTF
#define YYFPRINTF master_fprintf
#endif

%}

%union {
	char strtype[2048];
	int inttype;
	long longtype;
}

%token COMMENT
%token MAP
%token OPT_TIMEOUT OPT_NTIMEOUT OPT_NOBIND OPT_NOGHOST OPT_GHOST OPT_VERBOSE
%token OPT_DEBUG OPT_RANDOM OPT_USE_WEIGHT OPT_SYMLINK
%token COLON COMMA NL DDASH
%type <strtype> map
%type <strtype> options
%type <strtype> dn
%type <strtype> dnattrs
%type <strtype> dnattr
%type <strtype> option
%type <strtype> daemon_option
%type <strtype> mount_option
%token <strtype> PATH
%token <strtype> QUOTE
%token <strtype> NILL
%token <strtype> SPACE
%token <strtype> EQUAL
%token <strtype> MULTITYPE
%token <strtype> MAPTYPE
%token <strtype> DNSERVER
%token <strtype> DNATTR
%token <strtype> DNNAME
%token <strtype> MAPHOSTS
%token <strtype> MAPNULL
%token <strtype> MAPXFN
%token <strtype> MAPNAME
%token <longtype> NUMBER
%token <strtype> OPTION

%start file

%%

file: {
		master_lineno = 0;
#if YYDEBUG != 0
		master_debug = YYDEBUG;
#endif
	} line
	;

line:
	| PATH mapspec
	{
		path = master_strdup($1);
		if (!path) {
			local_free_vars();
			YYABORT;
		}
	}
	| PATH MULTITYPE maplist
	{
		char *tmp = NULL;

		trim_maptype($2);

		path = master_strdup($1);
		if (!path) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}

		if ((tmp = strchr($2, ',')))
			*tmp++ = '\0';

		type = master_strdup($2);
		if (!type) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (tmp) {
			format = master_strdup(tmp);
			if (!format) {
				master_error("memory allocation error");
				local_free_vars();
				YYABORT;
			}
		}
	}
	| PATH COLON { master_notify($1); YYABORT; }
	| PATH OPTION { master_notify($2); YYABORT; }
	| PATH NILL { master_notify($2); YYABORT; }
	| PATH OPT_RANDOM { master_notify($1); YYABORT; }
	| PATH OPT_USE_WEIGHT { master_notify($1); YYABORT; }
	| PATH OPT_DEBUG { master_notify($1); YYABORT; }
	| PATH OPT_TIMEOUT { master_notify($1); YYABORT; }
	| PATH OPT_SYMLINK { master_notify($1); YYABORT; }
	| PATH OPT_NOBIND { master_notify($1); YYABORT; }
	| PATH OPT_GHOST { master_notify($1); YYABORT; }
	| PATH OPT_NOGHOST { master_notify($1); YYABORT; }
	| PATH OPT_VERBOSE { master_notify($1); YYABORT; }
	| PATH { master_notify($1); YYABORT; }
	| QUOTE { master_notify($1); YYABORT; }
	| OPTION { master_notify($1); YYABORT; }
	| NILL { master_notify($1); YYABORT; }
	| COMMENT { YYABORT; }
	;

mapspec: map
	{
		local_argc = tmp_argc;
		local_argv = tmp_argv;
		tmp_argc = 0;
		tmp_argv = NULL;
	}
	| map options
	{
		local_argc = tmp_argc;
		local_argv = tmp_argv;
		tmp_argc = 0;
		tmp_argv = NULL;
	}
	;

maplist: map
	{
		if (!add_multi_mapstr()) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| map options
	{
		if (!add_multi_mapstr()) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| maplist DDASH map
	{
		local_argc++;
		local_argv = add_argv(local_argc, local_argv, "--");
		if (!local_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (!add_multi_mapstr()) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| maplist DDASH map options
	{
		local_argc++;
		local_argv = add_argv(local_argc, local_argv, "--");
		if (!local_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (!add_multi_mapstr()) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	;

map:	PATH
	{
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, $1);
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| MAPNAME
	{
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, $1);
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| MAPHOSTS
	{
		type = master_strdup($1 + 1);
		if (!type) {
			local_free_vars();
			YYABORT;
		}
	}
	| MAPXFN
	{
		master_notify($1);
		master_msg("X/Open Federated Naming service not supported");
		YYABORT;
	}
	| MAPNULL
	{
		type = master_strdup($1 + 1);
		if (!type) {
			local_free_vars();
			YYABORT;
		}
	}
	| dnattrs
	{
		type = master_strdup("ldap");
		if (!type) {
			local_free_vars();
			YYABORT;
		}
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, $1);
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| MAPTYPE PATH
	{
		char *tmp = NULL;

		trim_maptype($1);

		if ((tmp = strchr($1, ',')))
			*tmp++ = '\0';

		if (strcmp($1, "exec"))
			type = master_strdup($1);
		else
			type = master_strdup("program");
		if (!type) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (tmp) {
			format = master_strdup(tmp);
			if (!format) {
				master_error("memory allocation error");
				local_free_vars();
				YYABORT;
			}
		}
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, $2);
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| MAPTYPE MAPNAME
	{
		char *tmp = NULL;

		trim_maptype($1);

		if ((tmp = strchr($1, ',')))
			*tmp++ = '\0';

		if (strcmp($1, "exec"))
			type = master_strdup($1);
		else
			type = master_strdup("program");
		if (!type) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (tmp) {
			format = master_strdup(tmp);
			if (!format) {
				master_error("memory allocation error");
				local_free_vars();
				YYABORT;
			}
		}
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, $2);
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	| MAPTYPE dn
	{
		char *tmp = NULL;

		trim_maptype($1);

		if ((tmp = strchr($1, ',')))
			*tmp++ = '\0';

		if (strcmp($1, "exec"))
			type = master_strdup($1);
		else
			type = master_strdup("program");
		if (!type) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		if (tmp) {
			format = master_strdup(tmp);
			if (!format) {
				master_error("memory allocation error");
				local_free_vars();
				YYABORT;
			}
		}
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, $2);
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
		/* Add back the type for lookup_ldap.c to handle ldaps */
		if (*tmp_argv[0]) {
			tmp = malloc(strlen(type) + strlen(tmp_argv[0]) + 2);
			if (!tmp) {
				master_error("memory allocation error");
				local_free_vars();
				YYABORT;
			}
			strcpy(tmp, type);
			strcat(tmp, ":");
			strcat(tmp, tmp_argv[0]);
			free(tmp_argv[0]);
			tmp_argv[0] = tmp;
		}
	}
	;

dn:	DNSERVER dnattrs
	{
		strcpy($$, $1);
		strcat($$, $2);
	}
	| dnattrs
	{
		strcpy($$, $1);
	}
	|
	{
		master_notify("syntax error in dn");
		YYABORT;
	}
	;

dnattrs: DNATTR EQUAL DNNAME
	{
		if (strcasecmp($1, "cn") &&
		    strcasecmp($1, "ou") &&
		    strcasecmp($1, "automountMapName") &&
		    strcasecmp($1, "nisMapName")) {
			strcpy(errstr, $1);
			strcat(errstr, "=");
			strcat(errstr, $3);
			master_notify(errstr);
			YYABORT;
		}
		strcpy($$, $1);
		strcat($$, "=");
		strcat($$, $3);
	}
	| DNATTR EQUAL DNNAME COMMA dnattr
	{
		if (strcasecmp($1, "cn") &&
		    strcasecmp($1, "ou") &&
		    strcasecmp($1, "automountMapName") &&
		    strcasecmp($1, "nisMapName")) {
			strcpy(errstr, $1);
			strcat(errstr, "=");
			strcat(errstr, $3);
			master_notify(errstr);
			YYABORT;
		}
		strcpy($$, $1);
		strcat($$, "=");
		strcat($$, $3);
		strcat($$, ",");
		strcat($$, $5);
	}
	| DNNAME
	{
		/* Matches map in old style syntax ldap:server:map */
		strcpy($$, $1);
	}
	| DNATTR
	{
		master_notify($1);
		YYABORT;
	}
	;

dnattr: DNATTR EQUAL DNNAME
	{
		if (!strcasecmp($1, "automountMapName") ||
		    !strcasecmp($1, "nisMapName")) {
			strcpy(errstr, $1);
			strcat(errstr, "=");
			strcat(errstr, $3);
			master_notify(errstr);
			YYABORT;
		}
		strcpy($$, $1);
		strcat($$, "=");
		strcat($$, $3);
	}
	| DNATTR EQUAL DNNAME COMMA dnattr
	{
		if (!strcasecmp($1, "automountMapName") ||
		    !strcasecmp($1, "nisMapName")) {
			strcpy(errstr, $1);
			strcat(errstr, "=");
			strcat(errstr, $3);
			master_notify(errstr);
			YYABORT;
		}
		strcpy($$, $1);
		strcat($$, "=");
		strcat($$, $3);
		strcat($$, ",");
		strcat($$, $5);
	}
	| DNATTR
	{
		master_notify($1);
		YYABORT;
	}
	| DNNAME
	{
		master_notify($1);
		YYABORT;
	}
	;

options: option {}
	| options COMMA option {}
	| options option {}
	| options COMMA COMMA option
	{
		master_notify($1);
		YYABORT;
	}
	| options EQUAL
	{
		master_notify($1);
		YYABORT;
	}
	;

option: daemon_option
	| mount_option {}
	| error
	{
		master_notify("bogus option");
		YYABORT;
	}
	;

daemon_option: OPT_TIMEOUT NUMBER { timeout = $2; }
	| OPT_NTIMEOUT NUMBER { negative_timeout = $2; }
	| OPT_SYMLINK	{ symlnk = 1; }
	| OPT_NOBIND	{ nobind = 1; }
	| OPT_NOGHOST	{ ghost = 0; }
	| OPT_GHOST	{ ghost = 1; }
	| OPT_VERBOSE	{ verbose = 1; }
	| OPT_DEBUG	{ debug = 1; }
	| OPT_RANDOM	{ random_selection = 1; }
	| OPT_USE_WEIGHT { use_weight = 1; }
	;

mount_option: OPTION
	{
		tmp_argc++;
		tmp_argv = add_argv(tmp_argc, tmp_argv, $1);
		if (!tmp_argv) {
			master_error("memory allocation error");
			local_free_vars();
			YYABORT;
		}
	}
	;
%%

#if YYDEBUG
static int master_fprintf(FILE *f, char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_DEBUG, msg, ap);
	va_end(ap);
	return 1;
}
#endif

static char *master_strdup(char *str)
{
	char *tmp;

	tmp = strdup(str);
	if (!tmp)
		master_error("memory allocation error");
	return tmp;
}

static int master_error(const char *s)
{
	logmsg("%s while parsing map.", s);
	return 0;
}

static int master_notify(const char *s)
{
	logmsg("syntax error in map near [ %s ]", s);
	return(0);
}

static int master_msg(const char *s)
{
	logmsg("%s", s);
	return 0;
}

static void local_init_vars(void)
{
	path = NULL;
	type = NULL;
	format = NULL;
	verbose = 0;
	debug = 0;
	timeout = -1;
	negative_timeout = 0;
	symlnk = 0;
	nobind = 0;
	ghost = defaults_get_browse_mode();
	random_selection = global_selection_options & MOUNT_FLAG_RANDOM_SELECT;
	use_weight = 0;
	tmp_argv = NULL;
	tmp_argc = 0;
	local_argv = NULL;
	local_argc = 0;
}

static void local_free_vars(void)
{
	if (path)
		free(path);

	if (type)
		free(type);

	if (format)
		free(format);

	if (local_argv) {
		free_argv(local_argc, (const char **) local_argv);
		local_argv = NULL;
		local_argc = 0;
	}

	if (tmp_argv) {
		free_argv(tmp_argc, (const char **) tmp_argv);
		tmp_argv = NULL;
		tmp_argc = 0;
	}
}

static void trim_maptype(char *type)
{
	char *tmp;

	tmp = strchr(type, ':');
	if (tmp)
		*tmp = '\0';
	else {
		int len = strlen(type);
		while (len-- && isblank(type[len]))
			type[len] = '\0';
	}
	return;
}

static int add_multi_mapstr(void)
{
	if (type) {
		/* If type given and format is non-null add it back */
		if (format) {
			int len = strlen(type) + strlen(format) + 2;
			char *tmp = realloc(type, len);
			if (!tmp)
				return 0;
			type = tmp;
			strcat(type, ",");
			strcat(type, format);
			free(format);
			format = NULL;
		}

		local_argc++;
		local_argv = add_argv(local_argc, local_argv, type);
		if (!local_argv) {
			free(type);
			type = NULL;
			return 0;
		}

		free(type);
		type = NULL;
	}

	local_argv = append_argv(local_argc, local_argv, tmp_argc, tmp_argv);
	if (!local_argv) {
		free(type);
		type = NULL;
		return 0;
	}
	local_argc += tmp_argc;

	tmp_argc = 0;
	tmp_argv = NULL;

	return 1;
}

void master_init_scan(void)
{
	lineno = 0;
}

int master_parse_entry(const char *buffer, unsigned int default_timeout, unsigned int logging, time_t age)
{
	struct master *master = master_list;
	struct mapent_cache *nc;
	struct master_mapent *entry, *new;
	struct map_source *source;
	unsigned int logopt = logging;
	unsigned int m_logopt = master->logopt;
	int ret;

	local_init_vars();

	lineno++;

	master_set_scan_buffer(buffer);

	ret = master_parse();
	if (ret != 0) {
		local_free_vars();
		return 0;
	}

	nc = master->nc;

	/* Add null map entries to the null map cache */
	if (type && !strcmp(type, "null")) {
		cache_update(nc, NULL, path, NULL, lineno);
		local_free_vars();
		return 1;
	}

	/* Ignore all subsequent matching nulled entries */
	if (cache_lookup_distinct(nc, path)) {
		local_free_vars();
		return 1;
	}

	if (debug || verbose) {
		logopt = (debug ? LOGOPT_DEBUG : 0);
		logopt |= (verbose ? LOGOPT_VERBOSE : 0);
	}

	new = NULL;
	entry = master_find_mapent(master, path);
	if (!entry) {
		new = master_new_mapent(master, path, age);
		if (!new) {
			local_free_vars();
			return 0;
		}
		entry = new;
	} else {
		if (entry->age && entry->age == age) {
			if (strcmp(path, "/-")) {
				info(m_logopt,
				    "ignoring duplicate indirect mount %s",
				     path);
				local_free_vars();
				return 0;
			}
		}
	}

	if (!format) {
		if (conf_amd_mount_section_exists(path))
			format = strdup("amd");
	}

	if (format && !strcmp(format, "amd")) {
		unsigned int loglevel = conf_amd_get_log_options();
		if (loglevel <= LOG_DEBUG && loglevel > LOG_INFO)
			logopt = LOGOPT_DEBUG;
		else if (loglevel <= LOG_INFO && loglevel > LOG_ERR)
			logopt = LOGOPT_VERBOSE;
		/* amd mounts don't support browse mode */
		ghost = 0;
	}


	if (timeout < 0) {
		/*
		 * If no timeout is given get the timout from the
		 * first map (if it exists) or the config for amd
		 * maps.
		 */
		if (format && !strcmp(format, "amd"))
			timeout = conf_amd_get_dismount_interval(path);
		else if (entry->maps)
			timeout = entry->maps->exp_timeout;
		else
			timeout = default_timeout;
	}

	if (!entry->ap) {
		ret = master_add_autofs_point(entry, logopt, nobind, ghost, 0);
		if (!ret) {
			error(m_logopt, "failed to add autofs_point");
			if (new)
				master_free_mapent(new);
			local_free_vars();
			return 0;
		}
	}
	if (random_selection)
		entry->ap->flags |= MOUNT_FLAG_RANDOM_SELECT;
	if (use_weight)
		entry->ap->flags |= MOUNT_FLAG_USE_WEIGHT_ONLY;
	if (symlnk)
		entry->ap->flags |= MOUNT_FLAG_SYMLINK;
	if (negative_timeout)
		entry->ap->negative_timeout = negative_timeout;

/*
	source = master_find_map_source(entry, type, format,
					local_argc, (const char **) local_argv); 
	if (!source)
		source = master_add_map_source(entry, type, format, age, 
					local_argc, (const char **) local_argv);
	else
		source->age = age;
*/
	source = master_add_map_source(entry, type, format, age, 
					local_argc, (const char **) local_argv);
	if (!source) {
		error(m_logopt, "failed to add source");
		if (new)
			master_free_mapent(new);
		local_free_vars();
		return 0;
	}
	source->exp_timeout = timeout;
	source->master_line = lineno;

	entry->age = age;
	entry->current = NULL;

	if (new)
		master_add_mapent(master, entry);

	local_free_vars();

	return 1;
}

