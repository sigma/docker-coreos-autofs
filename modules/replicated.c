/* ----------------------------------------------------------------------- *
 *
 *  repl_list.h - routines for replicated mount server selection
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
 * A priority ordered list of hosts is created by using the following
 * selection rules.
 *
 *   1) Highest priority in selection is proximity.
 *      Proximity, in order of precedence is:
 *        - PROXIMITY_LOCAL, host corresponds to a local interface.
 *        - PROXIMITY_SUBNET, host is located in a subnet reachable
 *          through a local interface.
 *        - PROXIMITY_NETWORK, host is located in a network reachable
 *          through a local interface.
 *        - PROXIMITY_OTHER, host is on a network not directlty
 *          reachable through a local interface.
 *
 *   2) NFS version and protocol is selected by caclculating the largest
 *      number of hosts supporting an NFS version and protocol that
 *      have the closest proximity. These hosts are added to the list
 *      in response time order. Hosts may have a corresponding weight
 *      which essentially increaes response time and so influences the
 *      host order.
 *
 *   3) Hosts at further proximity that support the selected NFS version
 *      and protocol are also added to the list in response time order as
 *      in 2 above.
 *
 * ----------------------------------------------------------------------- */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "rpc_subs.h"
#include "replicated.h"
#include "automount.h"

#ifndef MAX_ERR_BUF
#define MAX_ERR_BUF		512
#endif

#define mymax(x, y)	(x >= y ? x : y)
#define mmax(x, y, z)	(mymax(x, y) == x ? mymax(x, z) : mymax(y, z))

void seed_random(void)
{
	int fd;
	unsigned int seed;

	fd = open_fd("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		srandom(time(NULL));
		return;
	}

	if (read(fd, &seed, sizeof(seed)) != -1)
		srandom(seed);
	else
		srandom(time(NULL));

	close(fd);

	return;
}

struct host *new_host(const char *name,
		      struct sockaddr *addr, size_t addr_len,
		      unsigned int proximity, unsigned int weight,
		      unsigned int options)
{
	struct host *new;
	struct sockaddr *tmp2;
	char *tmp1;

	if (!name || !addr)
		return NULL;

	tmp1 = strdup(name);
	if (!tmp1)
		return NULL;

	tmp2 = malloc(addr_len);
	if (!tmp2) {
		free(tmp1);
		return NULL;
	}
	memcpy(tmp2, addr, addr_len);

	new = malloc(sizeof(struct host));
	if (!new) {
		free(tmp1);
		free(tmp2);
		return NULL;
	}

	memset(new, 0, sizeof(struct host));

	new->name = tmp1;
	new->addr_len = addr_len;
	new->addr = tmp2;
	new->proximity = proximity;
	new->weight = weight;
	new->options = options;

	return new;
}

static int add_host(struct host **list, struct host *host)
{
	struct host *this, *last;

	if (!*list) {
		*list = host;
		return 1;
	}

	this = *list;
	last = this;
	while (this) {
		if (this->proximity >= host->proximity)
			break;
		last = this;
		this = this->next;
	}

	if (host->cost) {
		while (this) {
			if (this->proximity != host->proximity)
				break;
			if (this->cost >= host->cost)
				break;
			last = this;
			this = this->next;
		}
	}

	if (last == this) {
		host->next = last;
		*list = host;
		return 1;
	}

	last->next = host;
	host->next = this;

	return 1;
}

static void free_host(struct host *host)
{
	free(host->name);
	free(host->addr);
	free(host->path);
	free(host);
}

static void remove_host(struct host **hosts, struct host *host)
{
	struct host *last, *this;

	if (host == *hosts) {
		*hosts = (*hosts)->next;
		host->next = NULL;
		return;
	}

	this = *hosts;
	last = NULL;
	while (this) {
		if (this == host)
			break;
		last = this;
		this = this->next;
	}

	if (!last || !this)
		return;

	last->next = this->next;
	host->next = NULL;

	return;
}

static void delete_host(struct host **hosts, struct host *host)
{
	remove_host(hosts, host);
	free_host(host);
	return;
}

void free_host_list(struct host **list)
{
	struct host *this;

	this = *list;
	while (this) {
		struct host *next = this->next;
		free_host(this);
		this = next;
	}
	*list = NULL;
}

static unsigned int get_nfs_info(unsigned logopt, struct host *host,
			 struct conn_info *pm_info, struct conn_info *rpc_info,
			 int proto, unsigned int version, int port)
{
	unsigned int random_selection = host->options & MOUNT_FLAG_RANDOM_SELECT;
	unsigned int use_weight_only = host->options & MOUNT_FLAG_USE_WEIGHT_ONLY;
	socklen_t len = INET6_ADDRSTRLEN;
	char buf[len + 1];
	struct pmap parms;
	struct timeval start, end;
	struct timezone tz;
	unsigned int supported = 0;
	double taken = 0;
	int status, count = 0;

	if (host->addr)
		debug(logopt, "called with host %s(%s) proto %d version 0x%x",
		      host->name, get_addr_string(host->addr, buf, len),
		      proto, version);
	else
		debug(logopt,
		      "called for host %s proto %d version 0x%x",
		      host->name, proto, version);

	rpc_info->proto = proto;
	if (port < 0) {
		if (version & NFS4_REQUESTED)
			rpc_info->port = NFS_PORT;
		else
			port = 0;
	} else if (port > 0)
		rpc_info->port = port;

	memset(&parms, 0, sizeof(struct pmap));
	parms.pm_prog = NFS_PROGRAM;
	parms.pm_prot = proto;

	if (!(version & NFS4_REQUESTED))
		goto v3_ver;

	if (!port) {
		status = rpc_portmap_getclient(pm_info,
				host->name, host->addr, host->addr_len,
				proto, RPC_CLOSE_DEFAULT);
		if (status == -EHOSTUNREACH) {
			supported = status;
			goto done_ver;
		} else if (status)
			goto done_ver;
		parms.pm_vers = NFS4_VERSION;
		status = rpc_portmap_getport(pm_info, &parms, &rpc_info->port);
		if (status == -EHOSTUNREACH || status == -ETIMEDOUT) {
			supported = status;
			goto done_ver;
		} else if (status < 0) {
			if (version & NFS_VERS_MASK)
				goto v3_ver; /* MOUNT_NFS_DEFAULT_PROTOCOL=4 */
			else
				goto done_ver;
		}
	}

	if (rpc_info->proto == IPPROTO_UDP)
		status = rpc_udp_getclient(rpc_info, NFS_PROGRAM, NFS4_VERSION);
	else
		status = rpc_tcp_getclient(rpc_info, NFS_PROGRAM, NFS4_VERSION);
	if (status == -EHOSTUNREACH) {
		supported = status;
		goto done_ver;
	} else if (!status) {
		gettimeofday(&start, &tz);
		status = rpc_ping_proto(rpc_info);
		gettimeofday(&end, &tz);
		if (status == -ETIMEDOUT) {
			supported = status;
			goto done_ver;
		} else if (status > 0) {
			double reply;
			if (random_selection) {
				/* Random value between 0 and 1 */
				reply = ((float) random())/((float) RAND_MAX+1);
				debug(logopt,
				      "nfs v4 random selection time: %f", reply);
			} else {
				reply = elapsed(start, end);
				debug(logopt, "nfs v4 rpc ping time: %f", reply);
			}
			taken += reply;
			count++;
			supported = NFS4_SUPPORTED;
		}
	}

	if (!(version & NFS_VERS_MASK))
		goto done_ver;

v3_ver:
	if (!(version & NFS3_REQUESTED))
		goto v2_ver;

	if (!port && !pm_info->client) {
		status = rpc_portmap_getclient(pm_info,
				host->name, host->addr, host->addr_len,
				proto, RPC_CLOSE_DEFAULT);
		if (status == -EHOSTUNREACH) {
			supported = status;
			goto done_ver;
		} else if (status)
			goto done_ver;
	}

	if (!port) {
		parms.pm_vers = NFS3_VERSION;
		status = rpc_portmap_getport(pm_info, &parms, &rpc_info->port);
		if (status == -EHOSTUNREACH || status == -ETIMEDOUT) {
			supported = status;
			goto done_ver;
		} else if (status < 0)
			goto v2_ver;
	}

	if (rpc_info->proto == IPPROTO_UDP)
		status = rpc_udp_getclient(rpc_info, NFS_PROGRAM, NFS3_VERSION);
	else
		status = rpc_tcp_getclient(rpc_info, NFS_PROGRAM, NFS3_VERSION);
	if (status == -EHOSTUNREACH) {
		supported = status;
		goto done_ver;
	} else if (!status) {
		gettimeofday(&start, &tz);
		status = rpc_ping_proto(rpc_info);
		gettimeofday(&end, &tz);
		if (status == -ETIMEDOUT) {
			supported = status;
			goto done_ver;
		} else if (status > 0) {
			double reply;
			if (random_selection) {
				/* Random value between 0 and 1 */
				reply = ((float) random())/((float) RAND_MAX+1);
				debug(logopt,
				      "nfs v3 random selection time: %f", reply);
			} else {
				reply = elapsed(start, end);
				debug(logopt, "nfs v3 rpc ping time: %f", reply);
			}
			taken += reply;
			count++;
			supported |= NFS3_SUPPORTED;
		}
	}

v2_ver:
	if (!(version & NFS2_REQUESTED))
		goto done_ver;

	if (!port && !pm_info->client) {
		status = rpc_portmap_getclient(pm_info,
				host->name, host->addr, host->addr_len,
				proto, RPC_CLOSE_DEFAULT);
		if (status == -EHOSTUNREACH) {
			supported = status;
			goto done_ver;
		} else if (status)
			goto done_ver;
	}

	if (!port) {
		parms.pm_vers = NFS2_VERSION;
		status = rpc_portmap_getport(pm_info, &parms, &rpc_info->port);
		if (status == -EHOSTUNREACH || status == -ETIMEDOUT) {
			supported = status;
			goto done_ver;
		} else if (status < 0)
			goto done_ver;
	}

	if (rpc_info->proto == IPPROTO_UDP)
		status = rpc_udp_getclient(rpc_info, NFS_PROGRAM, NFS2_VERSION);
	else
		status = rpc_tcp_getclient(rpc_info, NFS_PROGRAM, NFS2_VERSION);
	if (status == -EHOSTUNREACH) {
		supported = status;
		goto done_ver;
	} else if (!status) {
		gettimeofday(&start, &tz);
		status = rpc_ping_proto(rpc_info);
		gettimeofday(&end, &tz);
		if (status == -ETIMEDOUT)
			supported = status;
		else if (status > 0) {
			double reply;
			if (random_selection) {
				/* Random value between 0 and 1 */
				reply = ((float) random())/((float) RAND_MAX+1);
				debug(logopt,
				      "nfs v2 random selection time: %f", reply);
			} else {
				reply = elapsed(start, end);;
				debug(logopt, "nfs v2 rpc ping time: %f", reply);
			}
			taken += reply;
			count++;
			supported |= NFS2_SUPPORTED;
		}
	}

done_ver:
	if (rpc_info->proto == IPPROTO_UDP) {
		rpc_destroy_udp_client(rpc_info);
		rpc_destroy_udp_client(pm_info);
	} else {
		rpc_destroy_tcp_client(rpc_info);
		rpc_destroy_tcp_client(pm_info);
	}

	if (count) {
		/*
		 * Average response time to 7 significant places as
		 * integral type.
		 */
		if (use_weight_only)
			host->cost = 1;
		else
			host->cost = (unsigned long) ((taken * 1000000) / count);

		/* Allow for user bias */
		if (host->weight)
			host->cost *= (host->weight + 1);

		debug(logopt, "host %s cost %ld weight %d",
		      host->name, host->cost, host->weight);
	}

	return supported;
}

static int get_vers_and_cost(unsigned logopt, struct host *host,
			     unsigned int version, int port)
{
	struct conn_info pm_info, rpc_info;
	time_t timeout = RPC_TIMEOUT;
	unsigned int supported, vers = (NFS_VERS_MASK | NFS4_VERS_MASK);
	int ret = 0;

	memset(&pm_info, 0, sizeof(struct conn_info));
	memset(&rpc_info, 0, sizeof(struct conn_info));

	if (host->proximity == PROXIMITY_NET)
		timeout = RPC_TIMEOUT * 2;
	else if (host->proximity == PROXIMITY_OTHER)
		timeout = RPC_TIMEOUT * 8;

	rpc_info.host = host->name;
	rpc_info.addr = host->addr;
	rpc_info.addr_len = host->addr_len;
	rpc_info.program = NFS_PROGRAM;
	rpc_info.timeout.tv_sec = timeout;
	rpc_info.close_option = RPC_CLOSE_DEFAULT;
	rpc_info.client = NULL;

	vers &= version;

	if (version & TCP_REQUESTED) {
		supported = get_nfs_info(logopt, host,
				   &pm_info, &rpc_info, IPPROTO_TCP, vers, port);
		if (IS_ERR(supported)) {
			if (ERR(supported) == EHOSTUNREACH ||
			    ERR(supported) == ETIMEDOUT)
				return ret;
		} else if (supported) {
			ret = 1;
			host->version |= supported;
		}
	}

	if (version & UDP_REQUESTED) {
		supported = get_nfs_info(logopt, host,
				   &pm_info, &rpc_info, IPPROTO_UDP, vers, port);
		if (IS_ERR(supported)) {
			if (!ret && ERR(supported) == ETIMEDOUT)
				return ret;
		} else if (supported) {
			ret = 1;
			host->version |= (supported << 8);
		}
	}

	return ret;
}

static int get_supported_ver_and_cost(unsigned logopt, struct host *host,
				      unsigned int version, int port)
{
	unsigned int random_selection = host->options & MOUNT_FLAG_RANDOM_SELECT;
	unsigned int use_weight_only = host->options & MOUNT_FLAG_USE_WEIGHT_ONLY;
	socklen_t len = INET6_ADDRSTRLEN;
	char buf[len + 1];
	struct conn_info pm_info, rpc_info;
	int proto;
	unsigned int vers;
	struct timeval start, end;
	struct timezone tz;
	double taken = 0;
	time_t timeout = RPC_TIMEOUT;
	int status = 0;

	if (host->addr)
		debug(logopt, "called with host %s(%s) version 0x%x",
			host->name, get_addr_string(host->addr, buf, len),
			version);
	else
		debug(logopt, "called with host %s version 0x%x",
			host->name, version);

	memset(&pm_info, 0, sizeof(struct conn_info));
	memset(&rpc_info, 0, sizeof(struct conn_info));

	if (host->proximity == PROXIMITY_NET)
		timeout = RPC_TIMEOUT * 2;
	else if (host->proximity == PROXIMITY_OTHER)
		timeout = RPC_TIMEOUT * 8;

	rpc_info.host = host->name;
	rpc_info.addr = host->addr;
	rpc_info.addr_len = host->addr_len;
	rpc_info.program = NFS_PROGRAM;
	rpc_info.timeout.tv_sec = timeout;
	rpc_info.close_option = RPC_CLOSE_DEFAULT;
	rpc_info.client = NULL;

	/*
	 *  The version passed in is the version as defined in
	 *  include/replicated.h.  However, the version we want to send
	 *  off to the rpc calls should match the program version of NFS.
	 *  So, we do the conversion here.
	 */
	if (version & UDP_SELECTED_MASK) {
		proto = IPPROTO_UDP;
		version >>= 8;
	} else
		proto = IPPROTO_TCP;

	switch (version) {
	case NFS2_SUPPORTED:
		vers = NFS2_VERSION;
		break;
	case NFS3_SUPPORTED:
		vers = NFS3_VERSION;
		break;
	case NFS4_SUPPORTED:
		vers = NFS4_VERSION;
		break;
	default:
		crit(logopt, "called with invalid version: 0x%x\n", version);
		return 0;
	}

	rpc_info.proto = proto;

	if (port > 0)
		rpc_info.port = port;
	else if (vers & NFS4_VERSION && port < 0)
		rpc_info.port = NFS_PORT;
	else {
		struct pmap parms;
		int ret = rpc_portmap_getclient(&pm_info,
				host->name, host->addr, host->addr_len,
				proto, RPC_CLOSE_DEFAULT);
		if (ret)
			return 0;

		memset(&parms, 0, sizeof(struct pmap));
		parms.pm_prog = NFS_PROGRAM;
		parms.pm_prot = rpc_info.proto;
		parms.pm_vers = vers;
		ret = rpc_portmap_getport(&pm_info, &parms, &rpc_info.port);
		if (ret < 0)
			goto done;
	}

	if (rpc_info.proto == IPPROTO_UDP)
		status = rpc_udp_getclient(&rpc_info, NFS_PROGRAM, vers);
	else
		status = rpc_tcp_getclient(&rpc_info, NFS_PROGRAM, vers);
	if (status == -EHOSTUNREACH)
		goto done;
	else if (!status) {
		gettimeofday(&start, &tz);
		status = rpc_ping_proto(&rpc_info);
		gettimeofday(&end, &tz);
		if (status > 0) {
			if (random_selection) {
				/* Random value between 0 and 1 */
				taken = ((float) random())/((float) RAND_MAX+1);
				debug(logopt, "random selection time %f", taken);
			} else {
				taken = elapsed(start, end);
				debug(logopt, "rpc ping time %f", taken);
			}
		}
	}
done:
	if (rpc_info.proto == IPPROTO_UDP) {
		rpc_destroy_udp_client(&rpc_info);
		rpc_destroy_udp_client(&pm_info);
	} else {
		rpc_destroy_tcp_client(&rpc_info);
		rpc_destroy_tcp_client(&pm_info);
	}

	if (status) {
		/* Response time to 7 significant places as integral type. */
		if (use_weight_only)
			host->cost = 1;
		else
			host->cost = (unsigned long) (taken * 1000000);

		/* Allow for user bias */
		if (host->weight)
			host->cost *= (host->weight + 1);

		debug(logopt, "cost %ld weight %d", host->cost, host->weight);

		return 1;
	}

	return 0;
}

int prune_host_list(unsigned logopt, struct host **list,
		    unsigned int vers, int port)
{
	struct host *this, *last, *first;
	struct host *new = NULL;
	unsigned int proximity, selected_version = 0;
	unsigned int v2_tcp_count, v3_tcp_count, v4_tcp_count;
	unsigned int v2_udp_count, v3_udp_count, v4_udp_count;
	unsigned int max_udp_count, max_tcp_count, max_count;
	int status;
	int kern_vers;

	if (!*list)
		return 0;

	/* Use closest hosts to choose NFS version */

	first = *list;

	/* Get proximity of first entry after local entries */
	this = first;
	while (this && this->proximity == PROXIMITY_LOCAL)
		this = this->next;
	first = this;

	/*
	 * Check for either a list containing only proximity local hosts
	 * or a single host entry whose proximity isn't local. If so
	 * return immediately as we don't want to add probe latency for
	 * the common case of a single filesystem mount request.
	 *
	 * But, if the kernel understands text nfs mount options then
	 * mount.nfs most likely bypasses its probing and lets the kernel
	 * do all the work. This can lead to long timeouts for hosts that
	 * are not available so check the kernel version and mount.nfs
	 * version and probe singleton mounts if the kernel version is
	 * greater than 2.6.22 and mount.nfs version is greater than 1.1.1.
	 * But also allow the MOUNT_WAIT configuration parameter to override
	 * the probing.
	 */
	if (nfs_mount_uses_string_options &&
	    defaults_get_mount_wait() == -1 &&
	   (kern_vers = linux_version_code()) > KERNEL_VERSION(2, 6, 22)) {
		if (!this)
			return 1;
	} else {
		if (!this || !this->next)
			return 1;
	}

	proximity = this->proximity;
	while (this) {
		struct host *next = this->next;

		if (this->proximity != proximity)
			break;

		if (this->name) {
			status = get_vers_and_cost(logopt, this, vers, port);
			if (!status) {
				if (this == first) {
					first = next;
					if (next)
						proximity = next->proximity;
				}
				delete_host(list, this);
			}
		}
		this = next;
	}

	/*
	 * The list of hosts that aren't proximity local may now
	 * be empty if we haven't been able probe any so we need
	 * to check again for a list containing only proximity
	 * local hosts.
	 */
	if (!first)
		return 1;

	last = this;

	/* Select NFS version of highest number of closest servers */

	v4_tcp_count = v3_tcp_count = v2_tcp_count = 0;
	v4_udp_count = v3_udp_count = v2_udp_count = 0;

	this = first;
	do {
		if (this->version & NFS4_TCP_SUPPORTED)
			v4_tcp_count++;

		if (this->version & NFS3_TCP_SUPPORTED)
			v3_tcp_count++;

		if (this->version & NFS2_TCP_SUPPORTED)
			v2_tcp_count++;

		if (this->version & NFS4_UDP_SUPPORTED)
			v4_udp_count++;

		if (this->version & NFS3_UDP_SUPPORTED)
			v3_udp_count++;

		if (this->version & NFS2_UDP_SUPPORTED)
			v2_udp_count++;

		this = this->next; 
	} while (this && this != last);

	max_tcp_count = mmax(v4_tcp_count, v3_tcp_count, v2_tcp_count);
	max_udp_count = mmax(v4_udp_count, v3_udp_count, v2_udp_count);
	max_count = mymax(max_tcp_count, max_udp_count);

	if (max_count == v4_tcp_count) {
		selected_version = NFS4_TCP_SUPPORTED;
		debug(logopt,
		      "selected subset of hosts that support NFS4 over TCP");
	} else if (max_count == v3_tcp_count) {
		selected_version = NFS3_TCP_SUPPORTED;
		debug(logopt,
		      "selected subset of hosts that support NFS3 over TCP");
	} else if (max_count == v2_tcp_count) {
		selected_version = NFS2_TCP_SUPPORTED;
		debug(logopt,
		      "selected subset of hosts that support NFS2 over TCP");
	} else if (max_count == v4_udp_count) {
		selected_version = NFS4_UDP_SUPPORTED;
		debug(logopt,
		      "selected subset of hosts that support NFS4 over UDP");
	} else if (max_count == v3_udp_count) {
		selected_version = NFS3_UDP_SUPPORTED;
		debug(logopt,
		      "selected subset of hosts that support NFS3 over UDP");
	} else if (max_count == v2_udp_count) {
		selected_version = NFS2_UDP_SUPPORTED;
		debug(logopt,
		      "selected subset of hosts that support NFS2 over UDP");
	}

	/* Add local and hosts with selected version to new list */
	this = *list;
	do {
		struct host *next = this->next;
		if (this->version & selected_version ||
		    this->proximity == PROXIMITY_LOCAL) {
			this->version = selected_version;
			remove_host(list, this);
			add_host(&new, this);
		}
		this = next;
	} while (this && this != last);

	/*
	 * Now go through rest of list and check for chosen version
	 * and add to new list if selected version is supported.
	 */ 

	first = last;
	this = first;
	while (this) {
		struct host *next = this->next;
		if (!this->name) {
			remove_host(list, this);
			add_host(&new, this);
		} else {
			status = get_supported_ver_and_cost(logopt, this,
						selected_version, port);
			if (status) {
				this->version = selected_version;
				remove_host(list, this);
				add_host(&new, this);
			}
		}
		this = next;
	}

	free_host_list(list);
	*list = new;

	return 1;
}

static int add_new_host(struct host **list,
			const char *host, unsigned int weight,
			struct addrinfo *host_addr,
			unsigned int rr, unsigned int options)
{
	struct host *new;
	unsigned int prx;
	int addr_len;

	prx = get_proximity(host_addr->ai_addr);

	/*
	 * If we want the weight to be the determining factor
	 * when selecting a host, or we are using random selection,
	 * then all hosts must have the same proximity. However,
	 * if this is the local machine it should always be used
	 * since it is certainly available.
	 */
	if (prx != PROXIMITY_LOCAL &&
	   (options & (MOUNT_FLAG_USE_WEIGHT_ONLY |
		       MOUNT_FLAG_RANDOM_SELECT)))
		prx = PROXIMITY_SUBNET;

	/*
	 * If we tried to add an IPv6 address and we don't have IPv6
	 * support return success in the hope of getting an IPv4
	 * address later.
	 */
	if (prx == PROXIMITY_UNSUPPORTED)
		return 1;
	if (prx == PROXIMITY_ERROR)
		return 0;

	if (host_addr->ai_addr->sa_family == AF_INET)
		addr_len = INET_ADDRSTRLEN;
	else if (host_addr->ai_addr->sa_family == AF_INET6)
		addr_len = INET6_ADDRSTRLEN;
	else
		return 0;

	new = new_host(host, host_addr->ai_addr, addr_len, prx, weight, options);
	if (!new)
		return 0;

	if (!add_host(list, new)) {
		free_host(new);
		return 0;
	}
	new->rr = rr;

	return 1;
}

static int add_host_addrs(struct host **list, const char *host,
			  unsigned int weight, unsigned int options)
{
	struct addrinfo hints, *ni, *this;
	char *n_ptr;
	char *name = n_ptr = strdup(host);
	int len;
	char buf[MAX_ERR_BUF];
	int rr = 0, rr4 = 0, rr6 = 0;
	int ret;

	if (!name) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(LOGOPT_ANY, "strdup: %s", estr);
		error(LOGOPT_ANY, "failed to add host %s", host);
		return 0;
	}
	len = strlen(name);

	if (name[0] == '[' && name[--len] == ']') {
		name[len] = '\0';
		name++;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(name, NULL, &hints, &ni);
	if (ret)
		goto try_name;

	this = ni;
	while (this) {
		ret = add_new_host(list, host, weight, this, 0, options);
		if (!ret)
			break;
		this = this->ai_next;
	}
	freeaddrinfo(ni);
	goto done;

try_name:
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(name, NULL, &hints, &ni);
	if (ret) {
		error(LOGOPT_ANY, "hostname lookup failed: %s",
		      gai_strerror(ret));
		free(name);
		return 0;
	}

	this = ni;
	while (this) {
		if (this->ai_family == AF_INET) {
			struct sockaddr_in *addr = (struct sockaddr_in *) this->ai_addr;
			if (addr->sin_addr.s_addr != INADDR_LOOPBACK)
				rr4++;
		} else if (this->ai_family == AF_INET6) {
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *) this->ai_addr;
			if (!IN6_IS_ADDR_LOOPBACK(addr->sin6_addr.s6_addr32))
				rr6++;
		}
		this = this->ai_next;
	}
	if (rr4 > 1 || rr6 > 1)
		rr++;
	this = ni;
	while (this) {
		ret = add_new_host(list, host, weight, this, rr, options);
		if (!ret)
			break;
		this = this->ai_next;
	}
	freeaddrinfo(ni);
done:
	free(n_ptr);
	return ret;
}

static int add_path(struct host *hosts, const char *path, int len)
{
	struct host *this;
	char *tmp, *tmp2;

	tmp = alloca(len + 1);
	if (!tmp)
		return 0;

	strncpy(tmp, path, len);
	tmp[len] = '\0';

	this = hosts;
	while (this) {
		if (!this->path) {
			tmp2 = strdup(tmp);
			if (!tmp2)
				return 0;
			this->path = tmp2;
		}
		this = this->next;
	}

	return 1;
}

static int add_local_path(struct host **hosts, const char *path)
{
	struct host *new;
	char *tmp;

	tmp = strdup(path);
	if (!tmp)
		return 0;

	new = malloc(sizeof(struct host));
	if (!new) {
		free(tmp);
		return 0;
	}

	memset(new, 0, sizeof(struct host));

	new->path = tmp;
	new->proximity = PROXIMITY_LOCAL;
	new->version = NFS_VERS_MASK;
	new->name = NULL;
	new->addr = NULL;
	new->weight = new->cost = 0;

	add_host(hosts, new);

	return 1;
}

static char *seek_delim(const char *s)
{
	const char *p = s;
	char *delim;

	delim = strpbrk(p, "(, \t:");
	if (delim && *delim != ':' && (delim == s || *(delim - 1) != '\\'))
		return delim;

	while (*p) {
		if (*p != ':') {
			p++;
			continue;
		}
		if (!strncmp(p, ":/", 2))
			return (char *) p;
		p++;
	}

	return NULL;
}

int parse_location(unsigned logopt, struct host **hosts,
		   const char *list, unsigned int options)
{
	char *str, *p, *delim;
	unsigned int empty = 1;

	if (!list)
		return 0;

	str = strdup(list);
	if (!str)
		return 0;

	p = str;

	while (p && *p) {
		char *next = NULL;
		int weight = 0;

		p += strspn(p, " \t,");
		delim = seek_delim(p);

		if (delim) {
			if (*delim == '(') {
				char *w = delim + 1;

				*delim = '\0';

				delim = strchr(w, ')');
				if (delim) {
					*delim = '\0';
					weight = atoi(w);
				}
				else {
					/* syntax error - Mismatched brackets */
					free_host_list(hosts);
					free(str);
					return 0;
				}
				delim++;
			}

			if (*delim == ':') {
				char *path;

				*delim = '\0';
				path = delim + 1;

				/* Oh boy - might have spaces in the path */
				next = path;
				while (*next && strncmp(next, ":/", 2))
					next++;

				/* No spaces in host names at least */
				if (*next == ':') {
					while (*next &&
					      (*next != ' ' && *next != '\t'))
						next--;
					*next++ = '\0';
				}

				if (p != delim) {
					if (!add_host_addrs(hosts, p, weight, options)) {
						if (empty) {
							p = next;
							continue;
						}
					}

					if (!add_path(*hosts, path, strlen(path))) {
						free_host_list(hosts);
						free(str);
						return 0;
					}
				} else {
					if (!add_local_path(hosts, path)) {
						p = next;
						continue;
					}
				}
			} else if (*delim != '\0') {
				*delim = '\0';
				next = delim + 1;

				if (!add_host_addrs(hosts, p, weight, options)) {
					p = next;
					continue;
				}

				empty = 0;
			}
		} else {
			/* syntax error - no mount path */
			free_host_list(hosts);
			free(str);
			return 0;
		}

		p = next;
	}

	free(str);
	return 1;
}

void dump_host_list(struct host *hosts)
{
	struct host *this;

	if (!hosts)
		return;

	this = hosts;
	while (this) {
		logmsg("name %s path %s version %x proximity %u weight %u cost %u",
		      this->name, this->path, this->version,
		      this->proximity, this->weight, this->cost);
		this = this->next;
	}
	return;
}

