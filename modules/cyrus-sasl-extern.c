/*
 * cyrus-sasl-extern.c - Module for Cyrus sasl external authentication.
 *
 *   Copyright 2010 Ian Kent <raven@themaw.net>
 *   Copyright 2010 Red Hat, Inc.
 *   All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 */

#include "config.h"

#ifdef WITH_SASL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sasl/sasl.h>
#include <ldap.h>
#include <ldap_cdefs.h>
#include <lber_types.h>

#include "lookup_ldap.h"

struct values {
	char *mech;
	char *realm;
	char *authcid;
	char *authzid;
	char *password;
	char **resps;
	int nresps;
};

static int interaction(unsigned flags, sasl_interact_t *interact, void *values)
{
	const char *val = interact->defresult;
	struct values *vals = values;

	switch(interact->id) {
	case SASL_CB_GETREALM:
		if (values)
			val = vals->realm;
		break;

	case SASL_CB_AUTHNAME:
		if (values)
			val = vals->authcid;
		break;

	case SASL_CB_PASS:
		if (values)
			val = vals->password;
		break;

	case SASL_CB_USER:
		if (values)
			val = vals->authzid;
		break;

	case SASL_CB_NOECHOPROMPT:
	case SASL_CB_ECHOPROMPT:
		break;
	}

	if (val && !*val)
		val = NULL;

	if (val || interact->id == SASL_CB_USER) {
		interact->result = (val && *val) ? val : "";
		interact->len = strlen(interact->result);
	}

	return LDAP_SUCCESS;
}

int sasl_extern_interact(LDAP *ldap, unsigned flags, void *values, void *list)
{
	sasl_interact_t *interact = list;

	if (!ldap)
		return LDAP_PARAM_ERROR;

	while (interact->id != SASL_CB_LIST_END) {
		int rc = interaction(flags, interact, values);
		if (rc)
			return rc;
		interact++;
	}

	return LDAP_SUCCESS;
}

int do_sasl_extern(LDAP *ldap, struct lookup_context *ctxt)
{
	int flags = LDAP_SASL_QUIET;
	char *mech = ctxt->sasl_mech;
	struct values values;
	int rc;

	memset(&values, 0, sizeof(struct values));
	values.mech = mech;

	rc = ldap_sasl_interactive_bind_s(ldap, NULL, mech, NULL, NULL,
					  flags, sasl_extern_interact, &values);
	return rc;
}
#endif
