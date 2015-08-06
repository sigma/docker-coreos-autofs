/* ----------------------------------------------------------------------- *
 *
 *  alarm.c - alarm queue handling module.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include "automount.h"

struct alarm {
	time_t time;
	unsigned int cancel;
	struct autofs_point *ap;
	struct list_head list;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static LIST_HEAD(alarms);

#define alarm_lock() \
do { \
	int _alm_lock = pthread_mutex_lock(&mutex); \
	if (_alm_lock) \
		fatal(_alm_lock); \
} while (0)

#define alarm_unlock() \
do { \
	int _alm_unlock = pthread_mutex_unlock(&mutex); \
	if (_alm_unlock) \
		fatal(_alm_unlock); \
} while (0)

/* Insert alarm entry on ordered list. */
int alarm_add(struct autofs_point *ap, time_t seconds)
{
	struct list_head *head;
	struct list_head *p;
	struct alarm *new;
	time_t now = time(NULL);
	time_t next_alarm = 0;
	unsigned int empty = 1;
	int status;

	if (!seconds)
		return 1;

	new = malloc(sizeof(struct alarm));
	if (!new)
		return 0;

	new->ap = ap;
	new->cancel = 0;
	new->time = now + seconds;

	alarm_lock();

	head = &alarms;

	/* Check if we have a pending alarm */
	if (!list_empty(head)) {
		struct alarm *current;
		current = list_entry(head->next, struct alarm, list);
		next_alarm = current->time;
		empty = 0;
	}

	list_for_each(p, head) {
		struct alarm *this;

		this = list_entry(p, struct alarm, list);
		if (this->time >= new->time) {
			list_add_tail(&new->list, p);
			break;
		}
	}
	if (p == head)
		list_add_tail(&new->list, p);

	/*
	 * Wake the alarm thread if it is not busy (ie. if the
	 * alarms list was empty) or if the new alarm comes before
	 * the alarm we are currently waiting on.
	 */
	if (empty || new->time < next_alarm) {
        	status = pthread_cond_signal(&cond);
		if (status)
			fatal(status);
	}

	alarm_unlock();

	return 1;
}

void alarm_delete(struct autofs_point *ap)
{
	struct list_head *head;
	struct list_head *p;
	struct alarm *current;
	unsigned int signal_cancel = 0;
	int status;

	alarm_lock();

	head = &alarms;

	if (list_empty(head)) {
		alarm_unlock();
		return;
	}

	current = list_entry(head->next, struct alarm, list);

	p = head->next;
	while (p != head) {
		struct alarm *this;

		this = list_entry(p, struct alarm, list);
		p = p->next;

		if (ap == this->ap) {
			if (current != this) {
				list_del_init(&this->list);
				free(this);
				continue;
			}
			/* Mark as canceled */
			this->cancel = 1;
			this->time = 0;
			signal_cancel = 1;
		}
	}

	if (signal_cancel) {
        	status = pthread_cond_signal(&cond);
		if (status)
			fatal(status);
	}

	alarm_unlock();

	return;
}

static void *alarm_handler(void *arg)
{
	struct list_head *head;
	struct timespec expire;
	struct alarm *first;
	time_t now;
	int status;

	alarm_lock();

	head = &alarms;

	while (1) {
		if (list_empty(head)) {
			/* No alarms, wait for one to be added */
			status = pthread_cond_wait(&cond, &mutex);
			if (status)
				fatal(status);
			continue;
		}

		first = list_entry(head->next, struct alarm, list);

		now = time(NULL);

		if (first->time > now) {
			struct timeval usecs;
			/* 
			 * Wait for alarm to trigger or a new alarm 
			 * to be added.
			 */
			gettimeofday(&usecs, NULL);
			expire.tv_sec = first->time;
			expire.tv_nsec = usecs.tv_usec * 1000;

			status = pthread_cond_timedwait(&cond, &mutex, &expire);
			if (status && status != ETIMEDOUT)
				fatal(status);
		} else {
			/* First alarm has triggered, run it */

			list_del(&first->list);

			if (!first->cancel) {
				struct autofs_point *ap = first->ap;
				alarm_unlock(); 
				st_add_task(ap, ST_EXPIRE);
				alarm_lock();
			}
			free(first);
		}
	}
	/* Will never come here, so alarm_unlock is not necessary */
}

int alarm_start_handler(void)
{
	pthread_t thid;
	pthread_attr_t attrs;
	pthread_attr_t *pattrs = &attrs;
	int status;

	status = pthread_attr_init(pattrs);
	if (status)
		pattrs = NULL;
	else {
		pthread_attr_setdetachstate(pattrs, PTHREAD_CREATE_DETACHED);
#ifdef _POSIX_THREAD_ATTR_STACKSIZE
		pthread_attr_setstacksize(pattrs, PTHREAD_STACK_MIN*4);
#endif
	}

	status = pthread_create(&thid, pattrs, alarm_handler, NULL);

	if (pattrs)
		pthread_attr_destroy(pattrs);

	return !status;
}

