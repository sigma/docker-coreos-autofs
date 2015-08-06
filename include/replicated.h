/* ----------------------------------------------------------------------- *
 *
 *  repl_list.h - header file for replicated mount server selection
 *
 *   Copyright 2004 Jeff Moyer <jmoyer@redaht.com> - All Rights Reserved
 *   Copyright 2004-2006 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#ifndef _REPLICATED_H
#define _REPLICATED_H

#define PROXIMITY_ERROR		0x0000
#define PROXIMITY_LOCAL         0x0001
#define PROXIMITY_SUBNET        0x0002
#define PROXIMITY_NET           0x0004
#define PROXIMITY_OTHER         0x0008
#define PROXIMITY_UNSUPPORTED   0x0010

#define NFS2_SUPPORTED		0x0010
#define NFS3_SUPPORTED		0x0020
#define NFS4_SUPPORTED		0x0040
#define NFS_VERS_MASK		(NFS2_SUPPORTED|NFS3_SUPPORTED)
#define NFS4_VERS_MASK		(NFS4_SUPPORTED)

#define NFS2_REQUESTED		NFS2_SUPPORTED
#define NFS3_REQUESTED		NFS3_SUPPORTED
#define NFS4_REQUESTED		NFS4_SUPPORTED

#define TCP_SUPPORTED		0x0001
#define UDP_SUPPORTED		0x0002
#define TCP_REQUESTED		TCP_SUPPORTED
#define UDP_REQUESTED		UDP_SUPPORTED
#define NFS_PROTO_MASK		(TCP_SUPPORTED|UDP_SUPPORTED)

#define NFS2_TCP_SUPPORTED	NFS2_SUPPORTED
#define NFS3_TCP_SUPPORTED	NFS3_SUPPORTED
#define NFS4_TCP_SUPPORTED	NFS4_SUPPORTED
#define NFS2_UDP_SUPPORTED	(NFS2_SUPPORTED << 8)
#define NFS3_UDP_SUPPORTED	(NFS3_SUPPORTED << 8)
#define NFS4_UDP_SUPPORTED	(NFS4_SUPPORTED << 8)
#define TCP_SELECTED_MASK	0x00FF
#define UDP_SELECTED_MASK	0xFF00

#define IS_ERR(supported)	(0x8000 & supported)
#define ERR(supported)		(IS_ERR(supported) ? (~supported + 1) : supported)

#define RPC_TIMEOUT		5

struct host {
	char *name;
	struct sockaddr *addr;
	size_t addr_len;
	unsigned int rr;
	char *path;
	unsigned int version;
	unsigned int options;
	unsigned int proximity;
	unsigned int weight;
	unsigned long cost;
	struct host *next;
};

void seed_random(void);
struct host *new_host(const char *, struct sockaddr *, size_t,
		      unsigned int, unsigned int, unsigned int);
void free_host_list(struct host **);
int parse_location(unsigned, struct host **, const char *, unsigned int);
int prune_host_list(unsigned, struct host **, unsigned int, int);
void dump_host_list(struct host *);

#endif

