/* ----------------------------------------------------------------------- *
 *   
 *  parse_subs.c - misc parser subroutines
 *                automounter map
 * 
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *   Copyright 2004-2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#ifndef PARSE_SUBS_H
#define PARSE_SUBS_H

#define PROXIMITY_ERROR		0x0000
#define PROXIMITY_LOCAL         0x0001
#define PROXIMITY_SUBNET        0x0002
#define PROXIMITY_NET           0x0004
#define PROXIMITY_OTHER         0x0008
#define PROXIMITY_UNSUPPORTED   0x0010

#define SEL_ARCH		0x00000001
#define SEL_KARCH		0x00000002
#define SEL_OS			0x00000004
#define SEL_OSVER		0x00000008
#define SEL_FULL_OS		0x00000010
#define SEL_VENDOR		0x00000020
#define SEL_HOST		0x00000040
#define SEL_HOSTD		0x00000080
#define SEL_XHOST		0x00000100
#define SEL_DOMAIN		0x00000200
#define SEL_BYTE		0x00000400
#define SEL_CLUSTER		0x00000800
#define SEL_NETGRP		0x00001000
#define SEL_NETGRPD		0x00002000
#define SEL_IN_NETWORK		0x00004000
#define SEL_UID			0x00008000
#define SEL_GID			0x00010000
#define SEL_KEY			0x00020000
#define SEL_MAP			0x00040000
#define SEL_PATH		0x00080000
#define SEL_EXISTS		0x00100000
#define SEL_AUTODIR		0x00200000
#define SEL_DOLLAR		0x00400000
#define SEL_TRUE		0x00800000
#define SEL_FALSE		0x01000000

#define SEL_COMP_NONE		0x0000
#define SEL_COMP_EQUAL		0x0001
#define SEL_COMP_NOTEQUAL	0x0002
#define SEL_COMP_NOT		0x0004

#define SEL_FLAG_MACRO		0x0001
#define SEL_FLAG_FUNC1		0x0002
#define SEL_FLAG_FUNC2		0x0004
#define SEL_FLAG_STR		0x0100
#define SEL_FLAG_NUM		0x0200
#define SEL_FLAG_BOOL		0x0400

#define SEL_FLAGS_TYPE_MASK	0x00FF
#define SEL_FLAGS_VALUE_MASK	0xFF00
#define SEL_FREE_VALUE_MASK	(SEL_FLAG_MACRO|SEL_FLAG_STR|SEL_FLAG_NUM)
#define SEL_FREE_ARG1_MASK	(SEL_FLAG_FUNC1)
#define SEL_FREE_ARG2_MASK	(SEL_FLAG_FUNC2)

struct type_compare {
	char	*value;
};

struct type_function {
	char *arg1;
	char *arg2;
};

struct sel {
	unsigned long selector;
	const char *name;
	unsigned int flags;
	struct sel *next;
};

struct selector {
	struct sel *sel;
	unsigned int compare;

	union {
		struct type_compare	comp;
		struct type_function	func;
	};

	struct selector *next;
};

void sel_hash_init(void);
struct sel *sel_lookup(const char *);
struct selector *get_selector(char *);
void free_selector(struct selector *);

struct mapent;

struct map_type_info {
	char *type;
	char *format;
	char *map;
};

unsigned int get_proximity(struct sockaddr *);
unsigned int get_network_proximity(const char *);
unsigned int in_network(char *);
struct mapent *match_cached_key(struct autofs_point *, const char *,
				struct map_source *, const char *);
const char *skipspace(const char *);
int check_colon(const char *);
int chunklen(const char *, int);
int strmcmp(const char *, const char *, int);
char *dequote(const char *, int, unsigned int);
int span_space(const char *, unsigned int);
char *sanitize_path(const char *, int, unsigned int, unsigned int);
char *merge_options(const char *, const char *);
int expandamdent(const char *, char *, const struct substvar *);
int expand_selectors(struct autofs_point *, const char *, char **, struct substvar *);
void free_map_type_info(struct map_type_info *);
struct map_type_info *parse_map_type_info(const char *);

#endif
