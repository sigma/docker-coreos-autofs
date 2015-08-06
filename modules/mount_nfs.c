/* ----------------------------------------------------------------------- *
 *   
 * mount_nfs.c - Module for Linux automountd to mount an NFS filesystem,
 *               with fallback to symlinking if the path is local
 *
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <malloc.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <netinet/in.h>
#include <linux/nfs.h>
#include <linux/nfs2.h>
#include <ctype.h>

#define MODULE_MOUNT
#include "automount.h"
#include "replicated.h"

#define MODPREFIX "mount(nfs): "

int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

static struct mount_mod *mount_bind = NULL;
static int init_ctr = 0;

int mount_init(void **context)
{
	/* Make sure we have the local mount method available */
	if (!mount_bind) {
		if ((mount_bind = open_mount("bind", MODPREFIX)))
			init_ctr++;
	} else
		init_ctr++;

	seed_random();

	return !mount_bind;
}

int mount_mount(struct autofs_point *ap, const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options,
		void *context)
{
	char fullpath[PATH_MAX];
	char buf[MAX_ERR_BUF];
	struct host *this, *hosts = NULL;
	unsigned int mount_default_proto, vers;
	char *nfsoptions = NULL;
	const char *port_opt = NULL;
	unsigned int flags = ap->flags &
			(MOUNT_FLAG_RANDOM_SELECT | MOUNT_FLAG_USE_WEIGHT_ONLY);
	int nobind = ap->flags & MOUNT_FLAG_NOBIND;
	int len, status, err, existed = 1;
	int nosymlink = 0;
	int port = -1;
	int ro = 0;            /* Set if mount bind should be read-only */
	int rdma = 0;

	if (ap->flags & MOUNT_FLAG_REMOUNT)
		return 0;

	debug(ap->logopt,
	      MODPREFIX "root=%s name=%s what=%s, fstype=%s, options=%s",
	      root, name, what, fstype, options);

	mount_default_proto = defaults_get_mount_nfs_default_proto();
	vers = NFS_VERS_MASK | NFS_PROTO_MASK;
	if (strcmp(fstype, "nfs4") == 0)
		vers = NFS4_VERS_MASK | TCP_SUPPORTED;
	else if (mount_default_proto == 4)
		vers = vers | NFS4_VERS_MASK;

	/* Extract "nosymlink" pseudo-option which stops local filesystems
	 * from being symlinked.
	 *
	 * "nosymlink" is not used anymore. It is left for compatibility
	 * only (so we don't choke on it).
	 */
	if (options) {
		const char *comma;
		char *nfsp;
		int o_len = strlen(options) + 1;

		nfsp = nfsoptions = alloca(o_len + 1);
		if (!nfsoptions)
			return 1;

		memset(nfsoptions, '\0', o_len + 1);

		for (comma = options; *comma != '\0';) {
			const char *cp;
			const char *end;

			while (*comma == ',')
				comma++;

			/* Skip leading white space */
			while (*comma == ' ' || *comma == '\t')
				comma++;

			cp = comma;
			while (*comma != '\0' && *comma != ',')
				comma++;

			/* Skip trailing white space */
			end = comma - 1;
			while (*comma == ' ' || *comma == '\t')
				end--;

			o_len = end - cp + 1;

			if (_strncmp("proto=rdma", cp, o_len) == 0 ||
				   _strncmp("rdma", cp, o_len) == 0)
				rdma = 1;

			if (_strncmp("nosymlink", cp, o_len) == 0) {
				warn(ap->logopt, MODPREFIX
				     "the \"nosymlink\" option is depricated "
				     "and will soon be removed, "
				     "use the \"nobind\" option instead");
				nosymlink = 1;
			} else if (_strncmp("nobind", cp, o_len) == 0) {
				nobind = 1;
			} else if (_strncmp("no-use-weight-only", cp, o_len) == 0) {
				flags &= ~MOUNT_FLAG_USE_WEIGHT_ONLY;
			} else if (_strncmp("use-weight-only", cp, o_len) == 0) {
				flags |= MOUNT_FLAG_USE_WEIGHT_ONLY;
			} else {
				if (_strncmp("vers=4", cp, o_len) == 0 ||
				    _strncmp("nfsvers=4", cp, o_len) == 0)
					vers = NFS4_VERS_MASK | TCP_SUPPORTED;
				else if (_strncmp("vers=3", cp, o_len) == 0 ||
					 _strncmp("nfsvers=3", cp, o_len) == 0) {
					vers &= ~(NFS4_VERS_MASK | NFS_VERS_MASK);
					vers |= NFS3_REQUESTED;
				} else if (_strncmp("vers=2", cp, o_len) == 0 ||
					 _strncmp("nfsvers=2", cp, o_len) == 0) {
					vers &= ~(NFS4_VERS_MASK | NFS_VERS_MASK);
					vers |= NFS2_REQUESTED;
				} else if (strstr(cp, "port=") == cp &&
					 o_len - 5 < 25) {
					char optport[25];

					strncpy(optport, cp + 5, o_len - 5);
					optport[o_len - 5] = '\0';
					port = atoi(optport);
					if (port < 0)
						port = 0;
					port_opt = cp;
				} else if (_strncmp("proto=udp", cp, o_len) == 0 ||
					   _strncmp("udp", cp, o_len) == 0) {
					vers &= ~TCP_SUPPORTED;
				} else if (_strncmp("proto=tcp", cp, o_len) == 0 ||
					   _strncmp("tcp", cp, o_len) == 0) {
					vers &= ~UDP_SUPPORTED;
				}
				/* Check for options that also make sense
				   with bind mounts */
				else if (_strncmp("ro", cp, o_len) == 0)
					ro = 1;
				/* and jump over trailing white space */
				memcpy(nfsp, cp, comma - cp + 1);
				nfsp += comma - cp + 1;
			}
		}

		/* In case both tcp and udp options were given */
		if ((vers & NFS_PROTO_MASK) == 0)
			vers |= NFS_PROTO_MASK;

		debug(ap->logopt, MODPREFIX
		      "nfs options=\"%s\", nobind=%d, nosymlink=%d, ro=%d",
		      nfsoptions, nobind, nosymlink, ro);
	}

	if (!parse_location(ap->logopt, &hosts, what, flags)) {
		info(ap->logopt, MODPREFIX "no hosts available");
		return 1;
	}
	/*
	 * We can't probe protocol rdma so leave it to mount.nfs(8)
	 * and and suffer the delay if a server isn't available.
	 */
	if (rdma)
		goto dont_probe;

	/*
	 * If this is a singleton mount, and NFSv4 only hasn't been asked
	 * for, and the default NFS protocol is set to v4 in the autofs
	 * configuration only probe NFSv4 and let mount.nfs(8) do fallback
	 * to NFSv3 (if it can). If the NFSv4 probe fails then probe as
	 * normal.
	 */
	if ((hosts && !hosts->next) &&
	    mount_default_proto == 4 &&
	    (vers & NFS_VERS_MASK) != 0 &&
	    (vers & NFS4_VERS_MASK) != 0) {
		unsigned int v4_probe_ok = 0;
		struct host *tmp = new_host(hosts->name,
					    hosts->addr, hosts->addr_len,
					    hosts->proximity,
					    hosts->weight, hosts->options);
		if (tmp) {
			tmp->rr = hosts->rr;
			prune_host_list(ap->logopt, &tmp,
					NFS4_VERS_MASK|TCP_SUPPORTED, port);
			/* If probe succeeds just try the mount with host in hosts */
			if (tmp) {
				v4_probe_ok = 1;
				free_host_list(&tmp);
			}
		}
		if (!v4_probe_ok)
			prune_host_list(ap->logopt, &hosts, vers, port);
	} else {
		prune_host_list(ap->logopt, &hosts, vers, port);
	}

dont_probe:
	if (!hosts) {
		info(ap->logopt, MODPREFIX "no hosts available");
		return 1;
	}

	/* Construct and perhaps create mount point directory */

	/* Root offset of multi-mount */
	len = strlen(root);
	if (root[len - 1] == '/') {
		len = snprintf(fullpath, len, "%s", root);
	} else if (*name == '/') {
		len = sprintf(fullpath, "%s", root);
	} else {
		len = sprintf(fullpath, "%s/%s", root, name);
	}
	fullpath[len] = '\0';

	debug(ap->logopt, MODPREFIX "calling mkdir_path %s", fullpath);

	status = mkdir_path(fullpath, 0555);
	if (status && errno != EEXIST) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt,
		      MODPREFIX "mkdir_path %s failed: %s", fullpath, estr);
		return 1;
	}

	if (!status)
		existed = 0;

	/*
	 * If any *port= option is specified, then we don't want
	 * a bind mount. Use the "port" option if you want to
	 * avoid attempting a local bind mount, such as when
	 * tunneling NFS via localhost.
	 */
	if (nfsoptions && *nfsoptions && !port_opt)
		port_opt = strstr(nfsoptions, "port=");

	this = hosts;
	while (this) {
		char *loc;

		/* Port option specified, don't try to bind */
		if (!(nosymlink || nobind) &&
		    !port_opt && this->proximity == PROXIMITY_LOCAL) {
			/* Local host -- do a "bind" */
			const char *bind_options = ro ? "ro" : "";

			debug(ap->logopt,
			      MODPREFIX "%s is local, attempt bind mount",
			      name);

			err = mount_bind->mount_mount(ap, root, name, name_len,
					       this->path, "bind", bind_options,
					       mount_bind->context);

			/* Success - we're done */
			if (!err) {
				free_host_list(&hosts);
				return 0;
			}

			/* Failed to update mtab, don't try any more */
			if (err == MNT_FORCE_FAIL)
				goto forced_fail;

			/* No hostname, can't be NFS */
			if (!this->name) {
				this = this->next;
				continue;
			}
		}

		/* Not a local host - do an NFS mount */

		if (this->rr && this->addr) {
			socklen_t len = INET6_ADDRSTRLEN;
			char n_buf[len + 1];
			const char *n_addr;
			n_addr = get_addr_string(this->addr, n_buf, len);
			loc = malloc(strlen(n_addr) + strlen(this->path) + 4);
			if (!loc) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(ap->logopt, "malloc: %s", estr);
				goto forced_fail;
			}
			if (this->addr->sa_family == AF_INET6) {
				strcpy(loc, "[");
				strcat(loc, n_addr);
				strcat(loc, "]");
			} else
				strcpy(loc, n_addr);
		} else {
			char *host = this->name ? this->name : "localhost";
			loc = malloc(strlen(host) + strlen(this->path) + 2);
			if (!loc) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(ap->logopt, "malloc: %s", estr);
				goto forced_fail;
			}
			strcpy(loc, host);
		}
		strcat(loc, ":");
		strcat(loc, this->path);

		if (nfsoptions && *nfsoptions) {
			debug(ap->logopt,
			      MODPREFIX "calling mount -t %s " SLOPPY 
			      "-o %s %s %s", fstype, nfsoptions, loc, fullpath);

			err = spawn_mount(ap->logopt,
					  "-t", fstype, SLOPPYOPT "-o",
					  nfsoptions, loc, fullpath, NULL);
		} else {
			debug(ap->logopt,
			      MODPREFIX "calling mount -t %s %s %s",
			      fstype, loc, fullpath);
			err = spawn_mount(ap->logopt,
					  "-t", fstype, loc, fullpath, NULL);
		}

		if (!err) {
			debug(ap->logopt, MODPREFIX "mounted %s on %s", loc, fullpath);
			free(loc);
			free_host_list(&hosts);
			return 0;
		}

		free(loc);
		this = this->next;
	}

forced_fail:
	free_host_list(&hosts);

	/* If we get here we've failed to complete the mount */

	info(ap->logopt, MODPREFIX "nfs: mount failure %s on %s", what, fullpath);

	if (ap->type != LKP_INDIRECT)
		return 1;

	if ((!(ap->flags & MOUNT_FLAG_GHOST) && name_len) || !existed)
		rmdir_path(ap, fullpath, ap->dev);

	return 1;
}

int mount_done(void *context)
{
	int rv = 0;

	if (--init_ctr == 0) {
		rv = close_mount(mount_bind);
		mount_bind = NULL;
	}
	return rv;
}
