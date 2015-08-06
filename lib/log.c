/* ----------------------------------------------------------------------- *
 *
 *  log.c - applcation logging routines.
 *
 *   Copyright 2004 Denis Vlasenko <vda@port.imtp.ilyichevsk.odessa.ua>
 *				 - All Rights Reserved
 *   Copyright 2005 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 *  This module has been adapted from patches submitted by:
 *	Denis Vlasenko <vda@port.imtp.ilyichevsk.odessa.ua>
 *	Thanks Denis.
 *
 * ----------------------------------------------------------------------- */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "automount.h"

static unsigned int syslog_open = 0;
static unsigned int logging_to_syslog = 0;

/* log notification level */
static unsigned int do_verbose = 0;		/* Verbose feedback option */
static unsigned int do_debug = 0;		/* Full debug output */

void set_log_norm(void)
{
	do_verbose = 0;
	do_debug = 0;
	return;
}

void set_log_verbose(void)
{
	do_verbose = 1;
	return;
}

void set_log_debug(void)
{
	do_debug = 1;
	return;
}

void set_log_norm_ap(struct autofs_point *ap)
{
	ap->logopt = LOGOPT_ERROR;
	return;
}

void set_log_verbose_ap(struct autofs_point *ap)
{
	ap->logopt = LOGOPT_VERBOSE;
	return;
}

void set_log_debug_ap(struct autofs_point *ap)
{
	ap->logopt = LOGOPT_DEBUG;
	return;
}

void log_info(unsigned int logopt, const char *msg, ...)
{
	unsigned int opt_log = logopt & (LOGOPT_DEBUG | LOGOPT_VERBOSE);
	va_list ap;

	if (!do_debug && !do_verbose && !opt_log)
		return;

	va_start(ap, msg);
	if (logging_to_syslog)
		vsyslog(LOG_INFO, msg, ap);
	else {
		vfprintf(stderr, msg, ap);
		fputc('\n', stderr);
	}
	va_end(ap);

	return;
}

void log_notice(unsigned int logopt, const char *msg, ...)
{
	unsigned int opt_log = logopt & (LOGOPT_DEBUG | LOGOPT_VERBOSE);
	va_list ap;

	if (!do_debug && !do_verbose && !opt_log)
		return;

	va_start(ap, msg);
	if (logging_to_syslog)
		vsyslog(LOG_NOTICE, msg, ap);
	else {
		vfprintf(stderr, msg, ap);
		fputc('\n', stderr);
	}
	va_end(ap);

	return;
}

void log_warn(unsigned int logopt, const char *msg, ...)
{
	unsigned int opt_log = logopt & (LOGOPT_DEBUG | LOGOPT_VERBOSE);
	va_list ap;

	if (!do_debug && !do_verbose && !opt_log)
		return;

	va_start(ap, msg);
	if (logging_to_syslog)
		vsyslog(LOG_WARNING, msg, ap);
	else {
		vfprintf(stderr, msg, ap);
		fputc('\n', stderr);
	}
	va_end(ap);

	return;
}

void log_error(unsigned logopt, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	if (logging_to_syslog)
		vsyslog(LOG_ERR, msg, ap);
	else {
		vfprintf(stderr, msg, ap);
		fputc('\n', stderr);
	}
	va_end(ap);
	return;
}

void log_crit(unsigned logopt, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	if (logging_to_syslog)
		vsyslog(LOG_CRIT, msg, ap);
	else {
		vfprintf(stderr, msg, ap);
		fputc('\n', stderr);
	}
	va_end(ap);
	return;
}

void log_debug(unsigned int logopt, const char *msg, ...)
{
	unsigned int opt_log = logopt & LOGOPT_DEBUG;
	va_list ap;

	if (!do_debug && !opt_log)
		return;

	va_start(ap, msg);
	if (logging_to_syslog)
		vsyslog(LOG_WARNING, msg, ap);
	else {
		vfprintf(stderr, msg, ap);
		fputc('\n', stderr);
	}
	va_end(ap);

	return;
}

void logmsg(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	if (logging_to_syslog)
		vsyslog(LOG_CRIT, msg, ap);
	else {
		vfprintf(stderr, msg, ap);
		fputc('\n', stderr);
	}
	va_end(ap);
	return;
}

void open_log(void)
{
	if (!syslog_open) {
		syslog_open = 1;
		openlog("automount", LOG_PID, LOG_DAEMON);
	}

	logging_to_syslog = 1;
	return;
}

void log_to_syslog(void)
{
	char buf[MAX_ERR_BUF];
	int nullfd;

	open_log();

	/* Redirect all our file descriptors to /dev/null */
	nullfd = open("/dev/null", O_RDWR);
	if (nullfd < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		fprintf(stderr, "cannot open /dev/null: %s", estr);
		exit(1);
	}

	if (dup2(nullfd, STDIN_FILENO) < 0 ||
	    dup2(nullfd, STDOUT_FILENO) < 0 ||
	    dup2(nullfd, STDERR_FILENO) < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		fprintf(stderr,
			"redirecting file descriptors failed: %s", estr);
		exit(1);
	}

	if (nullfd > 2)
		close(nullfd);

	return;
}

void log_to_stderr(void)
{
	if (syslog_open) {
		syslog_open = 0;
		closelog();
	}

	logging_to_syslog = 0;

	return;
}
