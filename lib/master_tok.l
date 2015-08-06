%{
/* ----------------------------------------------------------------------- *
 *   
 *  master_tok.l - master map tokenizer.
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

#ifdef ECHO
# undef ECHO
#endif /* ECHO */
static void master_echo(void);	/* forward definition */
#define ECHO master_echo()

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "master_parse.tab.h"

/*
 * There are some things that need to be defined only if useing GNU flex.
 * These must not be defined if using standard lex
 */
#ifdef FLEX_SCANNER
int master_lineno;
#endif

int master_lex(void);
int master_wrap(void);

/* no need for yywrap() */
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

void master_set_scan_buffer(const char *);
const char *line = NULL;

#ifdef FLEX_SCANNER
const char *line_pos = NULL;
const char *line_lim = NULL;
int my_yyinput(char *, int);

#undef YY_INPUT
#define YY_INPUT(b, r, ms) (r = my_yyinput(b, ms))
#else
#undef input
#undef unput
#define input()  (*(char *) line++)
#define unput(c) (*(char *) --line = c)
#endif

#define BUFF_LEN	1024
char buff[BUFF_LEN];
char *bptr;
char *optr = buff;
unsigned int tlen;

%}

%option nounput

%x PATHSTR MAPSTR DNSTR OPTSTR

WS		[[:blank:]]+
OPTWS		[[:blank:]]*
NL		\r?\n
CONT		\\\n{OPTWS}

OPTIONSTR	([\-]?([[:alpha:]_]([[:alnum:]_\-])*(=(\"?([[:alnum:]_\-\:])+\"?))?)+)
MACROSTR	(-D{OPTWS}([[:alpha:]_]([[:alnum:]_\-\.])*)=([[:alnum:]_\-\.])+)
SLASHIFYSTR	(--(no-)?slashify-colons)
NUMBER		[0-9]+

DNSERVSTR1	([[:alpha:]][[:alnum:]\-.]*(:[0-9]+)?:)
DNSERVSTR2	(\[([[:xdigit:]]:.)+\](:[0-9]+)?:)
DNSERVSTR3	(\/\/[[:alpha:]][[:alnum:]\-.]*(:[0-9]+)?\/)
DNSERVSTR4	(\/\/\[([[:xdigit:]]:.)+\](:[0-9]+)?\/)
DNSERVSTR5	(([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}(:[0-9]+)?:)
DNSERVSTR6	(\/\/([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}(:[0-9]+)?\/)
DNSERVERSTR	({DNSERVSTR1}|{DNSERVSTR2}|{DNSERVSTR3}|{DNSERVSTR4}|{DNSERVSTR5}|{DNSERVSTR6})

AT_CN		([cC][[nN])
AT_NMN		([nN][iI][sS][Mm][aA][pP][Nn][aA][mM][eE])
AT_AMN		([aA][uU][tT][oO][mM][oO][uU][nN][tT][Mm][aA][pP][Nn][aA][mM][eE])
AT_OU		([oO][[uU])
AT_DC		([dD][[cC])
AT_O		([oO])
AT_C		([cC])
AT_L		([lL])
DNATTRSTR	({AT_CN}|{AT_NMN}|{AT_AMN}|{AT_OU}|{AT_DC}|{AT_O}|{AT_C}|{AT_L})
DNNAMESTR1	([[:alnum:]_.\- ]+)
DNNAMESTR2	([[:alnum:]_.\-]+)

INTMAP		(-hosts|-null)
MULTI		((multi)(,(sun|hesiod))?(:{OPTWS}|{WS}))
MULTISEP	([\-]{2}[[:blank:]]+)
MTYPE		((file|program|exec|sss|yp|nis|nisplus|ldap|ldaps|hesiod|userdir)(,(sun|hesiod|amd))?(:{OPTWS}|{WS}))


OPTTOUT		(-t{OPTWS}|-t{OPTWS}={OPTWS}|--timeout{OPTWS}|--timeout{OPTWS}={OPTWS})
OPTNTOUT	(-n{OPTWS}|-n{OPTWS}={OPTWS}|--negative-timeout{OPTWS}|--negative-timeout{OPTWS}={OPTWS})

%%

<INITIAL>{
	{NL} | 
	\x00 {
		if (optr != buff) {
			*optr = '\0';
			strcpy(master_lval.strtype, buff);
			return NILL;
		}
	}

	#.*  { return COMMENT; }

	"/" {
		if (optr != buff) {
			*optr = '\0';
			strcpy(master_lval.strtype, buff);
			return NILL;
		}
		BEGIN(PATHSTR);
		bptr = buff;
		yyless(0);
	}

	.    { *optr++ = *master_text; }
}

<PATHSTR>{
	\x00 {
		BEGIN(INITIAL);
		*bptr++ = *master_text;
		strcpy(master_lval.strtype, buff);
		return NILL;
	}

	\\.  { *bptr++ = *(master_text + 1); }
	\"   {
		BEGIN(INITIAL);
		*bptr++ = *master_text;
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		return QUOTE;
	}

	{WS} {
		BEGIN(MAPSTR);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		bptr = buff;
		memset(buff, 0, BUFF_LEN);
		return(PATH);
	}

	<<EOF>> {
		BEGIN(INITIAL);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		return(PATH);
	}

	{NL} {
		BEGIN(INITIAL);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		return PATH;
	}

	.    { *bptr++ = *master_text; }
}

<MAPSTR>{
	{OPTWS}\\\n{OPTWS} {}

	{MULTI} {
		tlen = master_leng - 1;
		if (bptr != buff && isblank(master_text[tlen])) {
			/*
			 * We can't handle unescaped white space in map names
			 * so just eat the white space. We always have the
			 * "multi" at the beginning of the string so the while
			 * will not fall off the end.
			 */
			while (isblank(master_text[tlen - 1]))
				tlen--;
			strncat(buff, master_text, tlen);
			bptr += tlen;
			yyless(tlen);
		} else {
			strcpy(master_lval.strtype, master_text);
			return(MULTITYPE);
		}
	}

	{MTYPE} |
	{MTYPE}/{DNSERVERSTR}{DNATTRSTR}= |
	{MTYPE}/{DNATTRSTR}= {
		tlen = master_leng - 1;
		if (bptr != buff && isblank(master_text[tlen])) {
			/*
			 * We can't handle unescaped white space in map names
			 * so just eat the white space. We always have the
			 * maptype keyword at the beginning of the string so
			 * the while will not fall off the end.
			 */
			while (isblank(master_text[tlen - 1]))
				tlen--;
			strncat(buff, master_text, tlen);
			bptr += tlen;
			yyless(tlen);
		} else {
			strcpy(master_lval.strtype, master_text);
			return(MAPTYPE);
		}
	}

	{MULTISEP} { return(DDASH); }

	":"	{ return(COLON); }

	"-hosts" {
		BEGIN(OPTSTR);
		strcpy(master_lval.strtype, master_text);
		return MAPHOSTS;
	}

	"-null" {
		BEGIN(OPTSTR);
		strcpy(master_lval.strtype, master_text);
		return MAPNULL;
	}

	"-xfn" {
		/*
		 * The X/Open Federated Naming service isn't supported
		 * and the parser will call YYABORT() when it sees the
		 * MAPXFN token so we must set the start state to the
		 * INITIAL state here for the next yylex() call.
		 */
		BEGIN(INITIAL);
		strcpy(master_lval.strtype, master_text);
		return MAPXFN;
	}

	"//" {
		BEGIN(DNSTR);
		yyless(0);
	}

	{DNSERVERSTR}{DNATTRSTR}= {
		BEGIN(DNSTR);
		yyless(0);
	}

	{DNATTRSTR}= {
		BEGIN(DNSTR);
		yyless(0);
	}

	{OPTWS}/{NL} {
		BEGIN(INITIAL);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		bptr = buff;
		return(MAPNAME);
	}

	\\. { *bptr++ = *(master_text + 1); }

	{WS} {
		BEGIN(OPTSTR);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		bptr = buff;
		return(MAPNAME);
	}

	{NL} |
	\x00 {
		BEGIN(INITIAL);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		return(MAPNAME);
	}

	<<EOF>> {
		BEGIN(INITIAL);
		*bptr = '\0';
		strcpy(master_lval.strtype, buff);
		return(MAPNAME);
	}

	.	{ *bptr++ = *master_text; }
}

<DNSTR>{
	{OPTWS}\\\n{OPTWS} {}

	{DNSERVERSTR} {
		strcpy(master_lval.strtype, master_text);
		return DNSERVER;
	}

	{DNATTRSTR}/"=" {
		strcpy(master_lval.strtype, master_text);
		return DNATTR;
	}

	"=" {
		return EQUAL;
	}

	{DNNAMESTR1}/","{DNATTRSTR}"=" {
		strcpy(master_lval.strtype, master_text);
		return DNNAME;
	}

	{DNNAMESTR2} {
		strcpy(master_lval.strtype, master_text);
		return DNNAME;
	}

	{OPTWS}","{OPTWS} {
		return COMMA;
	}

	{WS}"=" |
	"="{WS} {
		BEGIN(INITIAL);
		strcpy(master_lval.strtype, master_text);
		return SPACE;
	}

	{WS}    { BEGIN(OPTSTR); }

	{NL} |
	\x00	{ BEGIN(INITIAL); }

	<<EOF>> { BEGIN(INITIAL); }
}

<OPTSTR>{
	{OPTWS}\\\n{OPTWS} {}

	{MULTISEP} {
		BEGIN(MAPSTR);
		return(DDASH);
	}

	{OPTTOUT}/{NUMBER} { return(OPT_TIMEOUT); }

	{OPTNTOUT}/{NUMBER} { return(OPT_NTIMEOUT); }

	{NUMBER} {
		master_lval.longtype = atol(master_text);
		return(NUMBER);
	}

	-?symlink		{ return(OPT_SYMLINK); }
	-?nobind		{ return(OPT_NOBIND); }
	-?nobrowse		{ return(OPT_NOGHOST); }
	-g|--ghost|-?browse	{ return(OPT_GHOST); }
	-v|--verbose		{ return(OPT_VERBOSE); }
	-d|--debug		{ return(OPT_DEBUG); }
	-w|--use-weight-only	{ return(OPT_USE_WEIGHT); }
	-r|--random-multimount-selection { return(OPT_RANDOM); }

	{OPTWS}","{OPTWS}	{ return(COMMA); }

	{OPTWS} {}

	{SLASHIFYSTR} {
		strcpy(master_lval.strtype, master_text);
		return(OPTION);
	}

	{MACROSTR} {
		strcpy(master_lval.strtype, master_text);
		return(OPTION);
	}

	{OPTIONSTR} {
		strcpy(master_lval.strtype, master_text);
		return(OPTION);
	}

	"="	{
		strcpy(master_lval.strtype, master_text);
		return(EQUAL);
	}

	{WS}	{}
	{NL} |
	\x00 { BEGIN(INITIAL); }

	<<EOF>> { BEGIN(INITIAL); }
}

%%

#include "automount.h"

int master_wrap(void)
{
	return 1;
}

static void master_echo(void)
{
	logmsg("%s", master_text);
	return;
}

#ifdef FLEX_SCANNER

void master_set_scan_buffer(const char *buffer)
{
	memset(buff, 0, sizeof(buff));
	optr = buff;

	YY_FLUSH_BUFFER;

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

#define min(a,b) (((a) < (b)) ? (a) : (b))

int my_yyinput(char *buffer, int max_size)
{
	int n = min(max_size, line_lim - line_pos);

	if (n > 0) {
		memcpy(buffer, line_pos, n);
		line_pos += n;
	}
	return n;
}

#else

void master_set_scan_buffer(const char *buffer)
{
	line = buffer;
}

#endif
