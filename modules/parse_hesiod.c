/*
 * parse_hesiod.c
 *
 * Module for Linux automountd to parse a hesiod filesystem entry.
 */

#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#define MODULE_PARSE
#include "automount.h"

#define MODPREFIX "parse(hesiod): "

int parse_version = AUTOFS_PARSE_VERSION;	/* Required by protocol */

#define HESIOD_LEN 512

/* Break out the fields in an AFS record of the form:
   "AFS /afs/athena/mit/tytso w /mit/tytso-afs" */
static int parse_afs(struct autofs_point *ap,
		     const char *filsysline, const char *name, int name_len,
		     char *source, int source_len, char *options, int options_len)
{
	const char *p;
	int i;

	p = filsysline;

	/* Skip whitespace. */
	while (isspace(*p))
		p++;

	/* Skip the filesystem type. */
	while (!isspace(*p))
		p++;

	/* Skip whitespace. */
	while (isspace(*p))
		p++;

	/* Isolate the source for this AFS fs. */
	for (i = 0; (!isspace(p[i]) && i < source_len); i++) {
		if (!p[i]) {
			error(ap->logopt, MODPREFIX
			      "unexpeced end of input looking for AFS "
			      "source: %s", p);
			return 1;
		}
		source[i] = p[i];
	}

	source[i] = 0;
	p += i;

	/* Skip whitespace. */
	while ((*p) && (isspace(*p)))
		p++;

	/* Isolate the options for this AFS fs. */
	for (i = 0; (!isspace(p[i]) && i < options_len); i++) {
		if (!p[i]) {
			error(ap->logopt, MODPREFIX
			      "unexpeced end of input looking for AFS "
			      "options: %s", p);
			return 1;
		}
		options[i] = p[i];
	}
	options[i] = 0;

	/* Hack for "r" or "w" options. */
	if (!strcmp(options, "r"))
		strcpy(options, "ro");

	if (!strcmp(options, "w"))
		strcpy(options, "rw");

	debug(ap->logopt,
	      MODPREFIX
	      "parsing AFS record gives '%s'->'%s' with options" " '%s'",
	      name, source, options);

	return 0;
}

/*
 * Break out the fields in an NFS record of the form:
 * "NFS /export/src nelson.tx.ncsu.edu w /ncsu/tx-src"
 */
static int parse_nfs(struct autofs_point *ap,
		     const char *filsysline, const char *name,
		     int name_len, char *source, int source_len,
		     char *options, int options_len)
{
	const char *p;
	char mount[HESIOD_LEN + 1];
	int i;

	p = filsysline;

	/* Skip whitespace. */
	while (isspace(*p))
		p++;

	/* Skip the filesystem type. */
	while (!isspace(*p))
		p++;

	/* Skip whitespace. */
	while (isspace(*p))
		p++;

	/* Isolate the remote mountpoint for this NFS fs. */
	for (i = 0; (!isspace(p[i]) && i < ((int) sizeof(mount) - 1)); i++) {
		if (!p[i]) {
			error(ap->logopt, MODPREFIX
			      "unexpeced end of input looking for NFS "
			      "mountpoint: %s", p);
			return 1;
		}
		mount[i] = p[i];
	}

	mount[i] = 0;
	p += i;

	/* Skip whitespace. */
	while ((*p) && (isspace(*p)))
		p++;

	/* Isolate the remote host. */
	for (i = 0; (!isspace(p[i]) && i < source_len); i++) {
		if (!p[i]) {
			error(ap->logopt, MODPREFIX
			      "unexpeced end of input looking for NFS "
			      "host: %s", p);
			return 1;
		}
		source[i] = p[i];
	}

	source[i] = 0;
	p += i;

	if (strlen(source) + strlen(mount) + 2 > source_len) {
		error(ap->logopt, MODPREFIX "entry too log for mount source");
		return 1;
	}

	/* Append ":mountpoint" to the source to get "host:mountpoint". */
	strcat(source, ":");
	strcat(source, mount);

	/* Skip whitespace. */
	while ((*p) && (isspace(*p)))
		p++;

	/* Isolate the mount options. */
	for (i = 0; (!isspace(p[i]) && i < options_len); i++) {
		if (!p[i]) {
			error(ap->logopt, MODPREFIX
			      "unexpeced end of input looking for NFS "
			      "mount options: %s", p);
			return 1;
		}
		options[i] = p[i];
	}
	options[i] = 0;

	/* Hack for "r" or "w" options. */
	if (!strcmp(options, "r"))
		strcpy(options, "ro");

	if (!strcmp(options, "w"))
		strcpy(options, "rw");

	debug(ap->logopt,
	      MODPREFIX
	      "parsing NFS record gives '%s'->'%s' with options" "'%s'",
	      name, source, options);

	return 0;
}

/* Break out the fields in a generic record of the form:
   "UFS /dev/ra0g w /site" */
static int parse_generic(struct autofs_point *ap,
			 const char *filsysline, const char *name, int name_len,
			 char *source, int source_len, char *options, int options_len)
{
	const char *p;
	int i;

	p = filsysline;

	/* Skip whitespace. */
	while (isspace(*p))
		p++;

	/* Skip the filesystem type. */
	while (!isspace(*p))
		p++;

	/* Skip whitespace. */
	while (isspace(*p))
		p++;

	/* Isolate the source for this fs. */
	for (i = 0; (!isspace(p[i]) && i < source_len); i++) {
		if (!p[i]) {
			error(ap->logopt, MODPREFIX
			      "unexpeced end of input looking for generic "
			      "mount source: %s", p);
			return 1;
		}
		source[i] = p[i];
	}

	source[i] = 0;
	p += i;

	/* Skip whitespace. */
	while ((*p) && (isspace(*p)))
		p++;

	/* Isolate the mount options. */
	for (i = 0; (!isspace(p[i]) && i < options_len); i++) {
		if (!p[i]) {
			error(ap->logopt, MODPREFIX
			      "unexpeced end of input looking for generic "
			      "mount options: %s", p);
			return 1;
		}
		options[i] = p[i];
	}
	options[i] = 0;

	/* Hack for "r" or "w" options. */
	if (!strcmp(options, "r"))
		strcpy(options, "ro");

	if (!strcmp(options, "w"))
		strcpy(options, "rw");

	debug(ap->logopt,
	      MODPREFIX
	      "parsing generic record gives '%s'->'%s' with options '%s'",
	      name, source, options);

	return 0;
}

int parse_init(int argc, const char *const *argv, void **context)
{
	return 0;
}

int parse_done(void *context)
{
	return 0;
}

int parse_mount(struct autofs_point *ap, const char *name,
		int name_len, const char *mapent, void *context)
{
	char source[HESIOD_LEN + 1];
	char fstype[HESIOD_LEN + 1];
	char options[HESIOD_LEN + 1];
	char *q;
	const char *p;
	int ret;

	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	p = mapent;
	q = fstype;

	/* Skip any initial whitespace... */
	while (isspace(*p))
		p++;

	/* Isolate the filesystem type... */
	while (!isspace(*p)) {
		*q++ = tolower(*p++);
	}
	*q = 0;

	/* If it's an error message... */
	if (!strcasecmp(fstype, "err")) {
		error(ap->logopt, MODPREFIX "%s", mapent);
		return 1;
	/* If it's an AFS fs... */
	} else if (!strcasecmp(fstype, "afs"))
		ret = parse_afs(ap, mapent, name, name_len,
				source, sizeof(source), options,
				sizeof(options));
	/* If it's NFS... */
	else if (!strcasecmp(fstype, "nfs"))
		ret = parse_nfs(ap, mapent, name, name_len,
				source, sizeof(source), options,
				sizeof(options));
	/* Punt. */
	else
		ret = parse_generic(ap, mapent, name, name_len,
				    source, sizeof(source), options,
				    sizeof(options));

	if (ret) {
		error(ap->logopt, MODPREFIX "failed to parse entry");
		return 1;
	} else {
		debug(ap->logopt,
		      MODPREFIX "mount %s is type %s from %s",
		      name, fstype, source);
	}

	return do_mount(ap, ap->path, name, name_len, source, fstype, options);
}
