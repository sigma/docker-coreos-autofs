/* ----------------------------------------------------------------------- *
 *
 * flag.c - autofs flag file management
 *
 * Copyright 2008 Red Hat, Inc. All rights reserved.
 * Copyright 2008 Ian Kent <raven@themaw.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 * USA; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

#include "automount.h"

#define MAX_PIDSIZE	20
#define FLAG_FILE	AUTOFS_FLAG_DIR "/autofs-running"

/* Flag for already existing flag file. */
static int we_created_flagfile = 0;

/* file descriptor of flag file */
static int fd = -1;

static int flag_is_owned(int fd)
{
	int pid = 0, tries = 3;

	while (tries--) {
		char pidbuf[MAX_PIDSIZE + 1];
		int got;

		lseek(fd, 0, SEEK_SET);
		got = read(fd, pidbuf, MAX_PIDSIZE);
		/*
		 * We add a terminator to the pid to verify write complete.
		 * If the write isn't finished in 300 milliseconds then it's
		 * probably a stale lock file.
		 */
		if (got > 0 && pidbuf[got - 1] == '\n') {
			sscanf(pidbuf, "%d", &pid);
			break;
		} else {
			struct timespec t = { 0, 100000000 };
			struct timespec r;

			while (nanosleep(&t, &r) == -1 && errno == EINTR)
				memcpy(&t, &r, sizeof(struct timespec));

			continue;
		}
	}

	/* Stale flagfile */
	if (!tries)
		return 0;

	if (pid) {
		int ret;

		ret = kill(pid, 0);
		/*
		 * If lock file exists but is not owned by a process
		 * we return unowned status so we can get rid of it
		 * and continue.
		 */
		if (ret == -1 && errno == ESRCH)
			return 0;
	} else {
		/*
		 * Odd, no pid in file - so what should we do?
		 * Assume something bad happened to owner and
		 * return unowned status.
		 */
		return 0;
	}

	return 1;
}

/* Remove flag file. */
void release_flag_file(void)
{
	if (fd > 0) {
		close(fd);
		fd = -1;
	}

	if (we_created_flagfile) {
		unlink(FLAG_FILE);
		we_created_flagfile = 0;
	}
}

/* * Try to create flag file */
int aquire_flag_file(void)
{
	char linkf[PATH_MAX];
	size_t len;

	len = snprintf(linkf, sizeof(linkf), "%s.%d", FLAG_FILE, getpid());
	if (len >= sizeof(linkf))
		/* Didn't acquire it */
		return 0;

	/*
	 * Repeat until it was us who made the link or we find the
	 * flag file already exists. If an unexpected error occurs
	 * we return 0 claiming the flag file exists which may not
	 * really be the case.
	 */
	while (!we_created_flagfile) {
		int errsv, i, j;

		i = open_fd_mode(linkf, O_WRONLY|O_CREAT, 0);
		if (i < 0) {
			release_flag_file();
			return 0;
		}
		close(i);

		j = link(linkf, FLAG_FILE);
		errsv = errno;

		(void) unlink(linkf);

		if (j < 0 && errsv != EEXIST) {
			release_flag_file();
			return 0;
		}

		fd = open_fd(FLAG_FILE, O_RDWR);
		if (fd < 0) {
			/* Maybe the file was just deleted? */
			if (errno == ENOENT)
				continue;
			release_flag_file();
			return 0;
		}

		if (j == 0) {
			char pidbuf[MAX_PIDSIZE + 1];
			int pidlen;

			pidlen = sprintf(pidbuf, "%d\n", getpid());
			if (write(fd, pidbuf, pidlen) != pidlen) {
				release_flag_file();
				return 0;
			}

			we_created_flagfile = 1;
		} else {
			/*
			 * Someone else made the link.
			 * If the flag file is not owned by anyone clean
			 * it up and try again, otherwise return fail.
			 */
			if (!flag_is_owned(fd)) {
				close(fd);
				fd = -1;
				unlink(FLAG_FILE);
				continue;
			}

			release_flag_file();
			return 0;
		}

		close(fd);
		fd = -1;
	}

	return 1;
}

