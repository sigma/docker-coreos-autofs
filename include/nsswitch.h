/* ----------------------------------------------------------------------- *
 *
 *  nsswitch.h - header file for module to call parser for nsswitch
 *		 config and store result into a struct.
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

#ifndef __NSSWITCH_H
#define __NSSWITCH_H

#include <netdb.h>
#include "list.h"

#define NSSWITCH_FILE _PATH_NSSWITCH_CONF

enum nsswitch_status {
	NSS_STATUS_UNKNOWN = -1,
	NSS_STATUS_SUCCESS,
	NSS_STATUS_NOTFOUND,
	NSS_STATUS_UNAVAIL,
	NSS_STATUS_TRYAGAIN,
	NSS_STATUS_MAX
};

/* Internal NSS STATUS for map inclusion lookups */
#define NSS_STATUS_COMPLETED    NSS_STATUS_MAX

enum nsswitch_action {
	NSS_ACTION_UNKNOWN = 0,
	NSS_ACTION_CONTINUE,
	NSS_ACTION_RETURN
};

struct nss_action {
	enum nsswitch_action action;
	int negated;
};

struct nss_source {
	char *source;
	struct nss_action action[NSS_STATUS_MAX];
	struct list_head list;
}; 

int set_action(struct nss_action *a, char *status, char *action, int negated);
struct nss_source *add_source(struct list_head *head, char *source);
int free_sources(struct list_head *list);

int nsswitch_parse(struct list_head *list);

#endif
