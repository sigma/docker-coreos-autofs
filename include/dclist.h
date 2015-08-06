#ifndef __DCLIST_H
#define __DCLIST_H

#include <sys/types.h>

struct dclist {
	time_t expire;
	const char *uri;
};

struct dclist *get_dc_list(unsigned int logopt, const char *uri);
void free_dclist(struct dclist *dclist);

#endif
