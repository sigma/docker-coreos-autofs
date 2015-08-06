/* ----------------------------------------------------------------------- *
 *
 *  log.c - applcation logging declarations.
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
 * ----------------------------------------------------------------------- */

#ifndef LOG_H
#define LOG_H

/* Define logging functions */

#define LOGOPT_NONE	0x0000
#define LOGOPT_ERROR	0x0000
#define LOGOPT_DEBUG	0x0001
#define LOGOPT_VERBOSE	0x0002
#define LOGOPT_ANY	(LOGOPT_DEBUG | LOGOPT_VERBOSE)

struct autofs_point;

extern void set_log_norm(void);
extern void set_log_verbose(void);
extern void set_log_debug(void);
extern void set_log_norm_ap(struct autofs_point *ap);
extern void set_log_verbose_ap(struct autofs_point *ap);
extern void set_log_debug_ap(struct autofs_point *ap);
extern void set_mnt_logging(unsigned global_logopt);

extern void open_log(void);
extern void log_to_syslog(void);
extern void log_to_stderr(void);
 
extern void log_info(unsigned int, const char* msg, ...);
extern void log_notice(unsigned int, const char* msg, ...);
extern void log_warn(unsigned int, const char* msg, ...);
extern void log_error(unsigned, const char* msg, ...);
extern void log_crit(unsigned, const char* msg, ...);
extern void log_debug(unsigned int, const char* msg, ...);
extern void logmsg(const char* msg, ...);

#define debug(opt, msg, args...)	\
	do { log_debug(opt, "%s: " msg,  __FUNCTION__, ##args); } while (0)

#define info(opt, msg, args...)		\
	do { log_info(opt, msg,  ##args); } while (0)

#define notice(opt, msg, args...)	\
	do { log_notice(opt, msg, ##args); } while (0)

#define warn(opt, msg, args...)		\
	do { log_warn(opt, msg, ##args); } while (0)

#define error(opt, msg, args...)	\
	do { log_error(opt, "%s: " msg,  __FUNCTION__, ##args); } while (0)

#define crit(opt, msg, args...)	\
	do { log_crit(opt, "%s: " msg,  __FUNCTION__, ##args); } while (0)

#define logerr(msg, args...)	\
	do { logmsg("%s:%d: " msg, __FUNCTION__, __LINE__, ##args); } while (0)

#define fatal(status)						    \
	do {							    \
		if (status == EDEADLK) {			    \
			logmsg("deadlock detected "		    \
				 "at line %d in %s, dumping core.", \
				  __LINE__, __FILE__);		    \
			dump_core();				    \
		}						    \
		logmsg("unexpected pthreads error: %d at %d "	    \
			 "in %s", status, __LINE__, __FILE__);	    \
		abort();					    \
	} while(0)

#ifndef NDEBUG
#define assert(x)							\
do {									\
	if (!(x)) {							\
		logmsg(__FILE__					\
			 ":%d: assertion failed: " #x, __LINE__);	\
	}								\
} while(0)
#else
#define assert(x)	do { } while(0)
#endif

#endif

