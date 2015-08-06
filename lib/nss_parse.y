%{
/* ----------------------------------------------------------------------- *
 *   
 *  nss_parser.y - nsswitch parser.
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
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <limits.h>

#include "automount.h"
#include "nsswitch.h"
#include "nss_parse.tab.h"

static pthread_mutex_t parse_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct list_head *nss_list;
static struct nss_source *src;
struct nss_action act[NSS_STATUS_MAX];

#define YYDEBUG 0

#ifndef YYENABLE_NLS
#define YYENABLE_NLS 0
#endif
#ifndef YYLTYPE_IS_TRIVIAL
#define YYLTYPE_IS_TRIVIAL 0
#endif

unsigned int nss_automount_found;

extern int nss_lineno;
extern int nss_lex(void);
extern FILE *nss_in;

static int nss_ignore(const char *s);
static int nss_error(const char *s);

%}

%union {
char strval[128];
}

%token LBRACKET RBRACKET EQUAL BANG NL
%token <strval> SOURCE
%token <strval> STATUS
%token <strval> ACTION

%start file

%%

file: {
#if YYDEBUG != 0
		nss_debug = YYDEBUG;
#endif
	} sources NL
	| /* empty */
	;

sources: nss_source
	| nss_source sources
	;

nss_source: SOURCE
{
	if (!strcmp($1, "files") || !strcmp($1, "yp") ||
	    !strcmp($1, "nis") || !strcmp($1, "ldap") ||
	    !strcmp($1, "nisplus") || !strcmp($1, "hesiod") ||
	    !strcmp($1, "sss"))
		src = add_source(nss_list, $1);
	else
		nss_ignore($1);
} | SOURCE LBRACKET status_exp_list RBRACKET
{
	enum nsswitch_status a;

	if (!strcmp($1, "files") || !strcmp($1, "yp") ||
	    !strcmp($1, "nis") || !strcmp($1, "ldap") ||
	    !strcmp($1, "nisplus") || !strcmp($1, "hesiod") ||
	    !strcmp($1, "sss")) {
		src = add_source(nss_list, $1);
		for (a = 0; a < NSS_STATUS_MAX; a++) {
			if (act[a].action != NSS_ACTION_UNKNOWN) {
				src->action[a].action = act[a].action;
				src->action[a].negated = act[a].negated;
			}
		}
	} else
		nss_ignore($1);
} | SOURCE LBRACKET status_exp_list SOURCE { nss_error("missing close bracket"); YYABORT; }
  | SOURCE LBRACKET status_exp_list NL { nss_error("missing close bracket"); YYABORT; }
  | SOURCE LBRACKET SOURCE { nss_error($3); YYABORT; }
  | error SOURCE { nss_error($2); YYABORT; };

status_exp_list: status_exp
		| status_exp status_exp_list

status_exp: STATUS EQUAL ACTION
{
	set_action(act, $1, $3, 0);
} | BANG STATUS EQUAL ACTION
{
	set_action(act, $2, $4, 1);
} | STATUS EQUAL SOURCE {nss_error($3); YYABORT; }
  | STATUS SOURCE {nss_error($2); YYABORT; }
  | BANG STATUS EQUAL SOURCE {nss_error($4); YYABORT; }
  | BANG STATUS SOURCE {nss_error($3); YYABORT; }
  | BANG SOURCE {nss_error($2); YYABORT; };

%%

static int nss_ignore(const char *s)
{
	logmsg("ignored unsupported autofs nsswitch source \"%s\"", s);
	return(0);
}

static int nss_error(const char *s)
{
	logmsg("syntax error in nsswitch config near [ %s ]\n", s);
	return(0);
}

static void parse_mutex_lock(void)
{
	int status = pthread_mutex_lock(&parse_mutex);
	if (status)
		fatal(status);
	return;
}

static void parse_mutex_unlock(void *arg)
{
	int status = pthread_mutex_unlock(&parse_mutex);
	if (status)
		fatal(status);
	return;
}

static void parse_close_nsswitch(void *arg)
{
	FILE *nsswitch = (FILE *) arg;
	fclose(nsswitch);
	return;
}

int nsswitch_parse(struct list_head *list)
{
	FILE *nsswitch;
	int status;

	nsswitch = open_fopen_r(NSSWITCH_FILE);
	if (!nsswitch) {
		logerr("couldn't open %s\n", NSSWITCH_FILE);
		return 1;
	}

	pthread_cleanup_push(parse_close_nsswitch, nsswitch);

	parse_mutex_lock();
	pthread_cleanup_push(parse_mutex_unlock, NULL);

	nss_in = nsswitch;

	nss_automount_found = 0;
	nss_list = list;
	status = nss_parse();
	nss_list = NULL;

	/* No "automount" nsswitch entry, use "files" */
	if (!nss_automount_found)
		if (add_source(list, "files"))
			status = 0;

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	if (status)
		return 1;

	return 0;
}
