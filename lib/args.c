/* ----------------------------------------------------------------------- *
 *
 *  args.c - argument vector handling.
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
#include <string.h>

#include "automount.h"

/*
 * Add entry to arg vector - argc is new arg vector size
 * NOTE: this outine will free the passed in argv vector
 *       upon success.
 */
char **add_argv(int argc, char **argv, char *str)
{
	char **vector;
	size_t vector_size;
	int i;

	vector_size = (argc + 1) * sizeof(char *);
	vector = (char **) malloc(vector_size);
	if (!vector)
		return NULL;

	for (i = 0; i < argc - 1; i++) {
		if (argv[i]) {
			vector[i] = strdup(argv[i]);
			if (!vector[i]) {
				logerr("failed to strdup arg");
				break;
			}
		} else
			vector[i] = NULL;
	}

	if (i < argc - 1) {
		free_argv(argc - 1, (const char **) vector);
		return NULL;
	}

	vector[argc - 1] = strdup(str);
	if (!vector[argc - 1]) {
		free_argv(argc - 1, (const char **) vector);
		return NULL;
	}

	vector[argc] = NULL;

	free_argv(argc - 1, (const char **) argv);

	return vector;
}

char **append_argv(int argc1, char **argv1, int argc2, char **argv2)
{
	char **vector;
	size_t vector_size;
	int len, i, j;

	len = argc1 + argc2;
	vector_size = (len + 1) * sizeof(char *);
	vector = (char **) realloc(argv1, vector_size);
	if (!vector) {
		free_argv(argc1, (const char **) argv1);
		free_argv(argc2, (const char **) argv2);
		return NULL;
	}

	for (i = argc1, j = 0; i <= len; i++, j++) {
		if (argv2[j]) {
			vector[i] = strdup(argv2[j]);
			if (!vector[i]) {
				logerr("failed to strdup arg");
				break;
			}
		} else
			vector[i] = NULL;
	}

	if (i < len) {
		free_argv(len, (const char **) vector);
		free_argv(argc2, (const char **) argv2);
		return NULL;
	}

	vector[len] = NULL;

	free_argv(argc2, (const char **) argv2);

	return vector;
}

const char **copy_argv(int argc, const char **argv)
{
	char **vector;
	size_t vector_size;
	int i;

	vector_size = (argc + 1) * sizeof(char *);
	vector = (char **) malloc(vector_size);
	if (!vector)
		return NULL;

	for (i = 0; i < argc; i++) {
		if (argv[i]) {
			vector[i] = strdup(argv[i]);
			if (!vector[i]) {
				logerr("failed to strdup arg");
				break;
			}
		} else
			vector[i] = NULL;
	}

	if (i < argc) {
		free_argv(argc, (const char **) vector);
		return NULL;
	}

	vector[argc] = NULL;

	return (const char **) vector;

}

static int compare(const char *s1, const char *s2)
{
	int res = 0;

	if (s1) {
		if (!s2)
			goto done;

		if (strcmp(s1, s2))
			goto done;
	} else if (s2)
		goto done;

	res = 1;
done:
	return res;
}

int compare_argv(int argc1, const char **argv1, int argc2, const char **argv2)
{
	int res = 1;
	int i, val;

	if (argc1 != argc2)
		return 0;

	i = 0;
	while (i < argc1) {
		val = compare(argv1[i], argv2[i]);
		if (!val) {
			res = 0;
			break;
		}
		i++;
	}
	return res;
}

int free_argv(int argc, const char **argv)
{
	char **vector = (char **) argv;
	int i;

	if (!argc) {
		if (vector)
			free(vector);
		return 1;
	}

	for (i = 0; i < argc; i++) {
		if (vector[i])
			free(vector[i]);
	}
	free(vector);

	return 1;
}

