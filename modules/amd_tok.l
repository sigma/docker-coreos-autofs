/* ----------------------------------------------------------------------- *
 *
 *  Copyright 2013 Ian Kent <raven@themaw.net>
 *  Copyright 2013 Red Hat, Inc.
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *  USA; either version 2 of the License, or (at your option) any later
 *  version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

%s START MAPOPTVAL FSOPTVAL MNTOPTVAL SELOPTVAL SELARGVAL

%{

static int reset_start_state = 0;

#ifdef ECHO
# undef ECHO
#endif
static void amd_echo(void);	/* forward definition */
static void amd_copy_buffer(void);
#define ECHO amd_echo()
int amd_wrap(void);

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "amd_parse.tab.h"

int amd_lex(void);
int mad_wrap(void);

#define YY_SKIP_YYWRAP

#ifndef YY_STACK_USED
#define YY_STACK_USED 0
#endif
#ifndef YY_ALWAYS_INTERACTIVE
#define YY_ALWAYS_INTERACTIVE 0
#endif
#ifndef YY_NEVER_INTERACTIVE
#define YY_NEVER_INTERACTIVE 0
#endif
#ifndef YY_MAIN
#define YY_MAIN 0
#endif

void amd_set_scan_buffer(const char *);
static const char *line = NULL;

#ifdef FLEX_SCANNER
static const char *line_pos = NULL;
static const char *line_lim = NULL;
int amd_yyinput(char *, int);

#undef YY_INPUT
#define YY_INPUT(b, r, ms) (r = amd_yyinput(b, ms))
#else
#undef input
#undef unput
#define input()  (*(char *) line++)
#define unput(c) (*(char *) --line = c)
#endif

%}

%option nounput

NL		\r?\n
OPTWS		[[:blank:]]*
OTHR		[^!;:=/|\- \t\r\n#]*

V4NUM		([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])

MACRO		(\$\{([[:alpha:]_/]([[:alnum:]_\-])([[:alnum:]_\-/])*)\})
QSTR		(\"([^"\\]|\\.)*\")
OSTR		([[:alpha:]]([[:alnum:]_\-])+)
FSTR		([[:alnum:]_/\.]([[:alnum:]_\-/\+\.]|(\\.))*)
VSTR		(([[:alnum:]_\-\:/\.])+)
SSTR		([[:alpha:]]([[:alnum:]\-\.])+)
IP4ADDR		({V4NUM}\.((({V4NUM}\.){0,2}){V4NUM}?))
V4MASK		({IP4ADDR}|([1-2][0-9]|3[0-2]|[1-9]))
IP6ADDR		((([A-Fa-f0-9]{1,4}\:\:?){1,7}[A-Fa-f0-9]{1,4})|(\:\:1))
V6MASK		(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[1-9])

FOPT		(({QSTR}|{FSTR}|{MACRO})+)
OPTS		({OSTR}(=({VSTR}|{QSTR}|{MACRO})+)?)
SOPT		(({SSTR}|{QSTR}|{MACRO})+)
NOPT		({SSTR}|(({IP4ADDR}(\/{V4MASK})?)|({IP6ADDR}(\/{V6MASK})?)))

MAPOPT		(fs|type|maptype|pref|sublink|cache)
MNTOPT		(opts|addopts|remopts)
FSOPTS		(rhost|rfs|dev|cachedir|mount|unmount|umount|delay)
CHEOPT		(mapdefault|none|inc|re|regexp|all)
MAPTYPE		(file|nis|nisplus|ldap|hesiod|exec|ndbm|passwd|union)
FSTYPE_LOCAL	(link|linkx|lofs|ufs|ext2|ext3|ext4|xfs|jfs|cdfs|cachefs)
FSTYPE_NET	(nfs|nfsx|nfsl|host)
FSTYPE		(auto|program|direct|lustre|{FSTYPE_LOCAL}|{FSTYPE_NET})

OSSEL		(arch|karch|os|osver|full_os|vendor)
HSTSEL		(host|hostd|domain|byte|cluster)
NETSEL		(netnumber|network|wire|in_network)
USRSEL		(uid|gid)
MAPSEL		(key|map|path)
OTRSEL		(autodir|dollar)
BOLSEL		(true|false)

SELOPT		({OSSEL}|{HSTSEL}|{USRSEL}|{MAPSEL}|{OTRSEL})
SEL1ARG		(xhost|exists|{NETSEL}|{BOLSEL})
SEL2ARG		(netgrp|netgrpd)

CUTSEP		(\|\||\/)

%%

%{
	if (reset_start_state) {
		BEGIN START;
		reset_start_state = 0;
	}
%}

<START>{
	{NL} |
	\x00 { }

	{MAPOPT} {
		BEGIN(MAPOPTVAL);
		amd_copy_buffer();
		return MAP_OPTION;

	}

	{FSOPTS} {
		BEGIN(FSOPTVAL);
		amd_copy_buffer();
		return FS_OPTION;
	}

	{MNTOPT} {
		BEGIN(MNTOPTVAL);
		amd_copy_buffer();
		return MNT_OPTION;
	}

	{SELOPT} {
		BEGIN(SELOPTVAL);
		amd_copy_buffer();
		return SELECTOR;
	}

	"!"/({SEL1ARG}|{SEL2ARG}) { return NOT; }

	{SEL1ARG} {
		BEGIN(SELARGVAL);
		amd_copy_buffer();
		return SELECTOR;
	}

	{SEL2ARG} {
		BEGIN(SELARGVAL);
		amd_copy_buffer();
		return SELECTOR;
	}

	{CUTSEP} { return CUT; }

	"-" { return HYPHEN; }

	{OPTWS} { return SPACE; }

	#.*  { return COMMENT; }

	{OTHR} {
		amd_copy_buffer();
		return OTHER;
	}
}

<MAPOPTVAL>{
	{NL} {
		BEGIN(START);
		yyless(1);
	}

	\x00 {
		BEGIN(START);
		return SEPERATOR;
		yyless(1);
	}

	";" {
		BEGIN(START);
		return SEPERATOR;
	}

	{OPTWS} {
		BEGIN(START);
		return SPACE;
	}

	":=" { return OPTION_ASSIGN; }

	{FSTYPE} {
		amd_copy_buffer();
		return FS_TYPE;
	}

	{MAPTYPE} {
		amd_copy_buffer();
		return MAP_TYPE;
	}

	{CHEOPT} {
		amd_copy_buffer();
		return CACHE_OPTION;
	}

	{FOPT} {
		amd_copy_buffer();
		return FS_OPT_VALUE;
	}
}

<FSOPTVAL>{
	{NL} {
		BEGIN(START);
		yyless(1);
	}

	\x00 {
		BEGIN(START);
		return SEPERATOR;
		yyless(1);
	}

	";" {
		BEGIN(START);
		return SEPERATOR;
	}

	{OPTWS} {
		BEGIN(START);
		return SPACE;
	}

	":=" { return OPTION_ASSIGN; }

	{FOPT} {
		amd_copy_buffer();
		return FS_OPT_VALUE;
	}
}

<MNTOPTVAL>{
	{NL} {
		BEGIN(START);
		yyless(1);
	}

	\x00 {
		BEGIN(START);
		return SEPERATOR;
		yyless(1);
	}

	";" {
		BEGIN(START);
		return SEPERATOR;
	}

	{OPTWS} {
		BEGIN(START);
		return SPACE;
	}

	(:=)(,+)? { return OPTION_ASSIGN; }

	,+ { return COMMA; }

	{OPTS} {
		amd_copy_buffer();
		return OPTION;
	}
}

<SELOPTVAL>{
	{NL} {
		BEGIN(START);
		yyless(1);
	}

	\x00 {
		BEGIN(START);
		return SEPERATOR;
		yyless(1);
	}

	";" {
		BEGIN(START);
		return SEPERATOR;
	}

	{OPTWS} {
		BEGIN(START);
		return SPACE;
	}

	"==" { return IS_EQUAL; }

	"!=" { return NOT_EQUAL; }

	{SOPT} {
		amd_copy_buffer();
		return SELECTOR_VALUE;
	}
}

<SELARGVAL>{
	{NL} {
		BEGIN(START);
		yyless(1);
	}

	\x00 {
		BEGIN(START);
		return SEPERATOR;
		yyless(1);
	}

	";" {
		BEGIN(START);
		return SEPERATOR;
	}

	"(" { return LBRACKET; }

	{NOPT} {
		amd_copy_buffer();
		return SEL_ARG_VALUE;
	}

	{SOPT}/"," {
		amd_copy_buffer();
		return SEL_ARG_VALUE;
	}

	"," { return COMMA; }

	{SOPT} {
		amd_copy_buffer();
		return SEL_ARG_VALUE;
	}

	{FOPT} {
		amd_copy_buffer();
		return SEL_ARG_VALUE;
	}

	")" { return RBRACKET; }
}

%%

#include "automount.h"

int amd_wrap(void)
{
	return 1;
}

static void amd_copy_buffer(void)
{
	if (amd_leng < 2048)
		strcpy(amd_lval.strtype, amd_text);
	else {
		strncpy(amd_lval.strtype, amd_text, 2047);
		amd_lval.strtype[2047] = '\0';
		logmsg("warning: truncated option near %s\n",
			&amd_lval.strtype[2030]);
	}
}

static void amd_echo(void)
{
	logmsg("%s\n", amd_text);
	return;
}

#ifdef FLEX_SCANNER

void amd_set_scan_buffer(const char *buffer)
{
	YY_FLUSH_BUFFER;
	reset_start_state = 1;

	line = buffer;
	line_pos = &line[0];
	/*
	 * Ensure buffer is 1 greater than string and is zeroed before
	 * the parse so we can fit the extra NULL which allows us to
	 * explicitly match an end of line within the buffer (ie. the
	 * need for 2 NULLS when parsing in memeory buffers).
	 */
	line_lim = line + strlen(buffer) + 1;
}

#define amd_min(a,b) (((a) < (b)) ? (a) : (b))

int amd_yyinput(char *buffer, int max_size)
{
	int n = amd_min(max_size, line_lim - line_pos);

	if (n > 0) {
		memcpy(buffer, line_pos, n);
		line_pos += n;
	}
	return n;
}

#else

void amd_set_scan_buffer(const char *buffer)
{
	line = buffer;
}

#endif
