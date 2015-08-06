/* ----------------------------------------------------------------------- *
 *   
 *  macros.h - header file for module to handle macro substitution
 *		variables for map entries.
 * 
 *   Copyright 2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#ifndef MACROS_H
#define MACROS_H

#define MAX_MACRO_STRING	128

struct substvar {
	char *def;		/* Define variable */
	char *val;		/* Value to replace with */
	unsigned int readonly;	/* System vars are readonly */
	struct substvar *next;
};

void macro_init(void);
int macro_is_systemvar(const char *str, int len);
int macro_global_addvar(const char *str, int len, const char *value);
int macro_parse_globalvar(const char *define);
void macro_lock(void);
void macro_unlock(void);
struct substvar *
macro_addvar(struct substvar *table, const char *str, int len, const char *value);
void macro_global_removevar(const char *str, int len);
struct substvar *
macro_removevar(struct substvar *table, const char *str, int len);
void macro_free_global_table(void);
void macro_free_table(struct substvar *table);
const struct substvar *
macro_findvar(const struct substvar *table, const char *str, int len);
void macro_setenv(struct substvar *table);

#endif
