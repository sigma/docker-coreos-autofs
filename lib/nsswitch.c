/* ----------------------------------------------------------------------- *
 *   
 *  nsswitch.c - module to call parser for nsswitch config and store
 *		result into a struct.
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

int set_action(struct nss_action *act, char *status, char *action, int negated)
{
	enum nsswitch_action a;

	if (!strcasecmp(action, "continue"))
		a = NSS_ACTION_CONTINUE;
	else if (!strcasecmp(action, "return"))
		a = NSS_ACTION_RETURN;
	else
		return 0;

	if (!strcasecmp(status, "SUCCESS")) {
		act[NSS_STATUS_SUCCESS].action = a;
		act[NSS_STATUS_SUCCESS].negated = negated;
	} else if (!strcasecmp(status, "NOTFOUND")) {
		act[NSS_STATUS_NOTFOUND].action = a;
		act[NSS_STATUS_NOTFOUND].negated = negated;
	} else if (!strcasecmp(status, "UNAVAIL")) {
		act[NSS_STATUS_UNAVAIL].action = a;
		act[NSS_STATUS_UNAVAIL].negated = negated;
	} else if (!strcasecmp(status, "TRYAGAIN")) {
		act[NSS_STATUS_TRYAGAIN].action = a;
		act[NSS_STATUS_TRYAGAIN].negated = negated;
	} else
		return 0;

	return 1;
}

struct nss_source *add_source(struct list_head *head, char *source)
{
	struct nss_source *s;
	char *tmp;
	enum nsswitch_status status;

	s = malloc(sizeof(struct nss_source));
	if (!s)
		return NULL;

	memset(s, 0, sizeof(struct nss_source));
	INIT_LIST_HEAD(&s->list);

	tmp = strdup(source);
	if (!tmp) {
		free(s);
		return NULL;
	}
	s->source = tmp;

	for (status = 0; status < NSS_STATUS_MAX; status++)
		s->action[status].action = NSS_ACTION_UNKNOWN;

	list_add_tail(&s->list, head);

	return s;
}

int free_sources(struct list_head *list)
{
	struct nss_source *this;
	struct list_head *head, *next;

	if (list_empty(list))
		return 0;

	head = list;
	next = list->next;
	while (next != head) {
		this = list_entry(next, struct nss_source, list);
		next = next->next;

		list_del(&this->list);
		if (this->source)
			free(this->source);
		free(this);
	}
	return 1;
}

/*
int main(void)
{
	struct nss_source *this;
	struct list_head list;
	struct list_head *head, *next;
	int status;


	status = nsswitch_parse(&list);
	if (status) {
		printf("error exit from nss_parse\n");
		free_sources(&list);
		exit(1);
	}

	head = &list;
	next = head->next;
	while (next != head) {
		this = list_entry(next, struct nss_source, list);
		next = next->next;

		printf("list->source = %s", this->source);
		for (status = 0; status < NSS_STATUS_MAX; status++) {
			if (this->action[status].action != NSS_ACTION_UNKNOWN)
				printf(" .");
		}
		printf("\n");
	}
	free_sources(&list);

	exit(0);
}
*/
