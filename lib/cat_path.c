/* ----------------------------------------------------------------------- *
 *
 *  cat_path.c - boundary aware buffer management routines
 *
 *   Copyright 2002-2003 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <string.h>
#include <limits.h>
#include <ctype.h>
#include "automount.h"
/*
 * sum = "dir/base" with attention to buffer overflows, and multiple
 * slashes at the joint are avoided.
 */
int cat_path(char *buf, size_t len, const char *dir, const char *base)
{
	char *d = (char *) dir;
	char *b = (char *) base;
	char *s = buf;
	size_t left = len;

	if ((*s = *d))
		while ((*++s = *++d) && --left) ;
	
	if (!left) {
		*s = '\0';
		return 0;
	}

	/* Now we have at least 1 left in output buffer */

	while (*--s == '/' && (left++ < len))
		*s = '\0';

	*++s = '/';
	left--;

	if (*b == '/') 
		while (*++b == '/');

	while (--left && (*++s = *b++)) ;

	if (!left) {
		*s = '\0';
		return 0;
	}

	return 1;
}

size_t _strlen(const char *str, size_t max)
{
	const char *s = str;
	size_t len = 0;

	while (*s++ && len < max)
		len++;

	return len;
}

/* 
 * sum = "dir/base" with attention to buffer overflows, and multiple
 * slashes at the joint are avoided.  The length of base is specified
 * explicitly.
 */
int ncat_path(char *buf, size_t len,
	      const char *dir, const char *base, size_t blen)
{
	char name[PATH_MAX+1];
	size_t alen = _strlen(base, blen);

	if (blen > PATH_MAX || !alen)
		return 0;
	
	strncpy(name, base, alen);
	name[alen] = '\0';

	return cat_path(buf, len, dir, name);
}

/* Compare first n bytes of s1 and s2 and that n == strlen(s1) */
int _strncmp(const char *s1, const char *s2, size_t n)
{
	size_t len = strlen(s1);

	if (n && n != len)
		return n - len;
	return strncmp(s1, s2, n);
}
