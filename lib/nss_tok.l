%{
/* ----------------------------------------------------------------------- *
 *   
 *  nss_tok.l - nsswitch tokenizer.
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
static void nss_echo(void);	/* forward definition */
#define ECHO nss_echo()

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nss_parse.tab.h"

/*
 * There are some things that need to be defined only if useing GNU flex.
 * These must not be defined if using standard lex
 */
#ifdef FLEX_SCANNER
int nss_lineno;
#endif

int nss_lex(void);
#ifndef nss_wrap
int nss_wrap(void);
#endif
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

extern unsigned int nss_automount_found;

%}

%option nounput

%x AUTOMOUNT ACTIONSTR

WS		[[:blank:]]+

automount	([Aa][Uu][Tt][Oo][Mm][Oo][Uu][Nn][Tt])

source		[[:alnum:]@$%^&*()-+_":;?,<>./'{}~`]+

success		([Ss][Uu][Cc][Cc][Ee][Ss][Ss])
notfound	([Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd])
unavail		([Uu][Nn][Aa][Vv][Aa][Ii][Ll])
tryagain	([Tt][Rr][Yy][Aa][Gg][Aa][Ii][Nn])

status		({success}|{notfound}|{unavail}|{tryagain})

continue	([Cc][Oo][Nn][Tt][Ii][Nn][Uu][Ee])
return		([Rr][Ee][Tt][Uu][Rr][Nn])

action		({continue}|{return})

%%

^{automount}: {
	nss_automount_found = 1;
	BEGIN(AUTOMOUNT);
}

\n|.	{}

<AUTOMOUNT>{
	{WS}	{ }

	{source} {
		strcpy(nss_lval.strval, nss_text);
		return SOURCE;
	}

	"["	{ BEGIN(ACTIONSTR); yyless(0); }

	\n	{ BEGIN(INITIAL); return NL; }
}

<ACTIONSTR>{
	{WS}	{ }

	{status} {
		strcpy(nss_lval.strval, nss_text);
		return STATUS;
	}

	{action} {
		strcpy(nss_lval.strval, nss_text);
		return ACTION;
	}

	"["	{ return LBRACKET; }
	"]"	{ BEGIN(AUTOMOUNT); return RBRACKET; }
	"="	{ return EQUAL; }
	"!"	{ return BANG; }

	.	{ BEGIN(AUTOMOUNT); yyless(0); }
	\n	{ BEGIN(INITIAL); return NL; }
}

%%

#include "automount.h"

int nss_wrap(void)
{
	return 1;
}

static void nss_echo(void)
{
	logmsg("%s", nss_text);
	return;
}
