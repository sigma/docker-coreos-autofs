/*
   Copyright 2005 Red Hat, Inc.
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:


    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Red Hat, Inc., nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
   TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
   PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
   OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 *  cyrus-sasl.c
 *
 *  Description:
 *
 *  This file implements SASL authentication to an LDAP server for the
 *  following mechanisms:
 *    GSSAPI, EXTERNAL, ANONYMOUS, PLAIN, DIGEST-MD5, KERBEROS_V5, LOGIN
 *  The mechanism to use is specified in an external file,
 *  LDAP_AUTH_CONF_FILE.  See the samples directory in the autofs
 *  distribution for an example configuration file.
 *
 *  This file is written with the intent that it will work with both the
 *  openldap and the netscape ldap client libraries.
 *
 *  Author: Nalin Dahyabhai <nalin@redhat.com>
 *  Modified by Jeff Moyer <jmoyer@redhat.com> to adapt it to autofs.
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sasl/sasl.h>

#include "automount.h"
#include "lookup_ldap.h"

#ifndef LDAP_OPT_RESULT_CODE
#ifdef  LDAP_OPT_ERROR_NUMBER
#define LDAP_OPT_RESULT_CODE LDAP_OPT_ERROR_NUMBER
#else
#error "Could not determine the proper value for LDAP_OPT_RESULT_CODE."
#endif
#endif

#ifdef HAVE_KRB5_PRINCIPAL_GET_REALM
void _krb5_princ_realm(krb5_context context, krb5_const_principal princ,
                          const char **realm, int *len)
{
	*realm = krb5_principal_get_realm(context, princ);
	if (*realm)
		*len = strlen(*realm);
	else
		*len = 0;
	return;
}
#else
void _krb5_princ_realm(krb5_context context, krb5_const_principal princ,
                          const char **realm, int *len)
{
	const krb5_data *data;

	data = krb5_princ_realm(context, princ);
	if (data) {
		*realm = data->data;
		*len = data->length;
	} else {
		*realm = NULL;
		*len = 0;
	}
	return;
}
#endif


/*
 *  Once a krb5 credentials cache is setup, we need to set the KRB5CCNAME
 *  environment variable so that the library knows where to find it.
 */
static const char *krb5ccenv = "KRB5CCNAME";
static const char *krb5ccval = "MEMORY:_autofstkt";
static const char *default_client = "autofsclient";
static pthread_mutex_t krb5cc_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int krb5cc_in_use = 0;

static int sasl_log_func(void *, int, const char *);
static int getpass_func(sasl_conn_t *, void *, int, sasl_secret_t **);
static int getuser_func(void *, int, const char **, unsigned *);

static sasl_callback_t callbacks[] = {
	{ SASL_CB_LOG, &sasl_log_func, NULL },
	{ SASL_CB_USER, &getuser_func, NULL },
	{ SASL_CB_AUTHNAME, &getuser_func, NULL },
	{ SASL_CB_PASS, &getpass_func, NULL },
	{ SASL_CB_LIST_END, NULL, NULL },
};

static char *sasl_auth_id = NULL;
static char *sasl_auth_secret = NULL;

static int
sasl_log_func(void *context, int level, const char *message)
{
	switch (level) {
	case SASL_LOG_ERR:
	case SASL_LOG_FAIL:
		logerr("%s", message);
		break;
	case SASL_LOG_WARN:
		logmsg("%s", message);
		break;
	case SASL_LOG_NOTE:
		logmsg("%s", message);
		break;
	case SASL_LOG_DEBUG:
	case SASL_LOG_TRACE:
	case SASL_LOG_PASS:
		debug(LOGOPT_DEBUG, "%s", message);
		break;
	default:
		break;
	}

	return SASL_OK;
}

static int
getuser_func(void *context, int id, const char **result, unsigned *len)
{
	debug(LOGOPT_NONE, "called with context %p, id %d.", context, id);

	switch (id) {
	case SASL_CB_USER:
	case SASL_CB_AUTHNAME:
		*result = sasl_auth_id;
		if (len)
			*len = strlen(sasl_auth_id);
		break;
	default:
		error(LOGOPT_VERBOSE, "unknown id in request: %d", id);
		return SASL_FAIL;
	}

	return SASL_OK;
}

/*
 *  This function creates a sasl_secret_t from the credentials specified in
 *  the configuration file.  sasl_client_auth can return SASL_OK or
 *  SASL_NOMEM.  We simply propagate this return value to the caller.
 */
static int
getpass_func(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret)
{
	int len = strlen(sasl_auth_secret);

	debug(LOGOPT_NONE, "context %p, id %d", context, id);

	*psecret = (sasl_secret_t *) malloc(sizeof(sasl_secret_t) + len);
	if (!*psecret)
		return SASL_NOMEM;

	(*psecret)->len = strlen(sasl_auth_secret);
	strncpy((char *)(*psecret)->data, sasl_auth_secret, len);

	return SASL_OK;
}

/*
 *  retrieves the supportedSASLmechanisms from the LDAP server.
 *
 *  Return Value: the result of ldap_get_values on success, NULL on failure.
 *                The caller is responsible for calling ldap_value_free on
 *                the returned data.
 */
char **
get_server_SASL_mechanisms(unsigned logopt, LDAP *ld)
{
	int ret;
	const char *saslattrlist[] = {"supportedSASLmechanisms", NULL};
	LDAPMessage *results = NULL, *entry;
	char **mechanisms;

	ret = ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE, "(objectclass=*)",
				(char **)saslattrlist, 0,
				NULL, NULL,
				NULL, LDAP_NO_LIMIT, &results);
	if (ret != LDAP_SUCCESS) {
		error(logopt, "%s", ldap_err2string(ret));
		return NULL;
	}

	entry = ldap_first_entry(ld, results);
	if (entry == NULL) {
		/* No root DSE. (!) */
		ldap_msgfree(results);
		debug(logopt,
		      "a lookup of \"supportedSASLmechanisms\" returned "
		      "no results.");
		return NULL;
	}

	mechanisms = ldap_get_values(ld, entry, "supportedSASLmechanisms");
	ldap_msgfree(results);
	if (mechanisms == NULL) {
		/* Well, that was a waste of time. */
		info(logopt, "No SASL authentication mechanisms are supported"
		    " by the LDAP server.");
		return NULL;
	}

	return mechanisms;
}

/*
 *  Returns 0 upon successful connect, -1 on failure.
 */
int
do_sasl_bind(unsigned logopt, LDAP *ld, sasl_conn_t *conn, const char **clientout,
	     unsigned int *clientoutlen, const char *auth_mech, int sasl_result)
{
	int ret, msgid, bind_result = LDAP_OTHER;
	struct berval client_cred, *server_cred, temp_cred;
	LDAPMessage *results;
	int have_data, expected_data;

	do {
		/* Take whatever client data we have and send it to the
		 * server. */
		client_cred.bv_val = (char *)*clientout;
		client_cred.bv_len = *clientoutlen;
		ret = ldap_sasl_bind(ld, NULL, auth_mech,
				     (client_cred.bv_len > 0) ?
				     &client_cred : NULL,
				     NULL, NULL, &msgid);
		if (ret != LDAP_SUCCESS) {
			crit(logopt,
			     "Error sending sasl_bind request to "
			     "the server: %s", ldap_err2string(ret));
			return -1;
		}

		/* Wait for a result message for this bind request. */
		results = NULL;
		ret = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &results);
		if (ret != LDAP_RES_BIND) {
			crit(logopt,
			     "Error while waiting for response to "
			     "sasl_bind request: %s", ldap_err2string(ret));
			return -1;
		}

		/* Retrieve the result code for the bind request and
		 * any data which the server sent. */
		server_cred = NULL;
		ret = ldap_parse_sasl_bind_result(ld, results,
						  &server_cred, 0);
		ldap_msgfree(results);

		/* Okay, here's where things get tricky.  Both
		 * Mozilla's LDAP SDK and OpenLDAP store the result
		 * code which was returned by the server in the
		 * handle's ERROR_NUMBER option.  Mozilla returns
		 * LDAP_SUCCESS if the data was parsed correctly, even
		 * if the result was an error, while OpenLDAP returns
		 * the result code.  I'm leaning toward Mozilla being
		 * more correct.
		 * In either case, we stuff the result into bind_result.
		 */
		if (ret == LDAP_SUCCESS) {
			/* Mozilla? */
			ret = ldap_get_option(ld, LDAP_OPT_RESULT_CODE,
					      &bind_result);
			if (ret != LDAP_SUCCESS) {
				crit(logopt,
				     "Error retrieving response to sasl_bind "
				     "request: %s", ldap_err2string(ret));
				ret = -1;
				break;
			}
		} else {
			/* OpenLDAP? */
			switch (ret) {
			case LDAP_SASL_BIND_IN_PROGRESS:
				bind_result = ret;
				break;
			default:
				warn(logopt,
				     "Error parsing response to sasl_bind "
				     "request: %s.", ldap_err2string(ret));
				break;
			}
		}

		/*
		 * The LDAP server is supposed to send a NULL value for
		 * server_cred if there was no data.  However, *some*
		 * server implementations get this wrong, and instead send
		 * an empty string.  We check for both.
		 */
		have_data = server_cred != NULL && server_cred->bv_len > 0;

		/*
		 * If the result of the sasl_client_start is SASL_CONTINUE,
		 * then the server should have sent us more data.
		 */
		expected_data = sasl_result == SASL_CONTINUE;

		if (have_data && !expected_data) {
			warn(logopt,
			     "The LDAP server sent data in response to our "
			     "bind request, but indicated that the bind was "
			     "complete. LDAP SASL bind with mechansim %s "
			     "failed.", auth_mech);
			ret = -1;
			break;
		}
		if (expected_data && !have_data) {
			warn(logopt,
			     "The LDAP server indicated that the LDAP SASL "
			     "bind was incomplete, but did not provide the "
			     "required data to proceed. LDAP SASL bind with "
			     "mechanism %s failed.", auth_mech);
			ret = -1;
			break;
		}

		/* If we need another round trip, process whatever we
		 * received and prepare data to be transmitted back. */
		if ((sasl_result == SASL_CONTINUE) &&
		    ((bind_result == LDAP_SUCCESS) ||
		     (bind_result == LDAP_SASL_BIND_IN_PROGRESS))) {
			if (server_cred != NULL) {
				temp_cred = *server_cred;
			} else {
				temp_cred.bv_len = 0;
				temp_cred.bv_val = NULL;
			}
			sasl_result = sasl_client_step(conn,
						       temp_cred.bv_val,
						       temp_cred.bv_len,
						       NULL,
						       clientout,
						       clientoutlen);
			/* If we have data to send, then the server
			 * had better be expecting it.  (It's valid
			 * to send the server no data with a request.)
			 */
			if ((*clientoutlen > 0) &&
			    (bind_result != LDAP_SASL_BIND_IN_PROGRESS)) {
				warn(logopt,
				     "We have data for the server, "
				     "but it thinks we are done!");
				/* XXX should print out debug data here */
				ret = -1;
			}
		}

		if (server_cred && server_cred->bv_len > 0) {
			ber_bvfree(server_cred);
			server_cred = NULL;
		}

	} while ((bind_result == LDAP_SASL_BIND_IN_PROGRESS) ||
		 (sasl_result == SASL_CONTINUE));

	if (server_cred && server_cred->bv_len > 0)
		ber_bvfree(server_cred);

	return ret;
}

/*
 *  Read client credentials from the default keytab, create a credentials
 *  cache, add the TGT to that cache, and set the environment variable so
 *  that the sasl/krb5 libraries can find our credentials.
 *
 *  Returns 0 upon success.  ctxt->kinit_done and ctxt->kinit_successful
 *  are set for cleanup purposes.  The krb5 context and ccache entries in
 *  the lookup_context are also filled in.
 *
 *  Upon failure, -1 is returned.
 */
int
sasl_do_kinit(unsigned logopt, struct lookup_context *ctxt)
{
	krb5_error_code ret;
	krb5_principal tgs_princ, krb5_client_princ;
	krb5_creds my_creds;
	char *tgs_name;
	const char *realm_name;
	int status, realm_length;

	if (ctxt->kinit_done)
		return 0;
	ctxt->kinit_done = 1;

	debug(logopt,
	      "initializing kerberos ticket: client principal %s",
	      ctxt->client_princ ? ctxt->client_princ : default_client);

	ret = krb5_init_context(&ctxt->krb5ctxt);
	if (ret) {
		error(logopt, "krb5_init_context failed with %d", ret);
		return -1;
	}

	ret = krb5_cc_resolve(ctxt->krb5ctxt, krb5ccval, &ctxt->krb5_ccache);
	if (ret) {
		error(logopt, "krb5_cc_resolve failed with error %d",
		      ret);
		krb5_free_context(ctxt->krb5ctxt);
		return -1;
	}

	if (ctxt->client_princ) {
		debug(logopt,
		      "calling krb5_parse_name on client principal %s",
		      ctxt->client_princ);

		ret = krb5_parse_name(ctxt->krb5ctxt, ctxt->client_princ,
				      &krb5_client_princ);
		if (ret) {
			error(logopt,
			      "krb5_parse_name failed for "
			      "specified client principal %s",
			      ctxt->client_princ);
			goto out_cleanup_cc;
		}
	} else {
		char *tmp_name = NULL;

		debug(logopt,
		      "calling krb5_sname_to_principal using defaults");

		ret = krb5_sname_to_principal(ctxt->krb5ctxt, NULL,
					default_client, KRB5_NT_SRV_HST, 
					&krb5_client_princ);
		if (ret) {
			error(logopt,
			      "krb5_sname_to_principal failed for "
			      "%s with error %d", default_client, ret);
			goto out_cleanup_cc;
		}


		ret = krb5_unparse_name(ctxt->krb5ctxt,
					krb5_client_princ, &tmp_name);
		if (ret) {
			debug(logopt,
			      "krb5_unparse_name failed with error %d",
			      ret);
			goto out_cleanup_client_princ;
		}

		debug(logopt,
		      "principal used for authentication: %s", tmp_name);

		krb5_free_unparsed_name(ctxt->krb5ctxt, tmp_name);
	}

	/* setup a principal for the ticket granting service */
	_krb5_princ_realm(ctxt->krb5ctxt, krb5_client_princ, &realm_name, &realm_length);
	ret = krb5_build_principal_ext(ctxt->krb5ctxt, &tgs_princ,
		realm_length, realm_name,
		strlen(KRB5_TGS_NAME), KRB5_TGS_NAME,
		realm_length, realm_name,
		0);
	if (ret) {
		error(logopt,
		      "krb5_build_principal failed with error %d", ret);
		goto out_cleanup_client_princ;
	}

	ret = krb5_unparse_name(ctxt->krb5ctxt, tgs_princ, &tgs_name);
	if (ret) {
		error(logopt, "krb5_unparse_name failed with error %d",
		      ret);
		goto out_cleanup_client_princ;
	}

	debug(logopt, "Using tgs name %s", tgs_name);

	memset(&my_creds, 0, sizeof(my_creds));
	ret = krb5_get_init_creds_keytab(ctxt->krb5ctxt, &my_creds,
					 krb5_client_princ,
					 NULL /*keytab*/,
					 0 /* relative start time */,
					 tgs_name, NULL);
	if (ret) {
		error(logopt,
		      "krb5_get_init_creds_keytab failed with error %d",
		      ret);
		goto out_cleanup_unparse;
	}

	status = pthread_mutex_lock(&krb5cc_mutex);
	if (status)
		fatal(status);

	if (krb5cc_in_use++ == 0)
		/* tell the cache what the default principal is */
		ret = krb5_cc_initialize(ctxt->krb5ctxt,
				 ctxt->krb5_ccache, krb5_client_princ);

	status = pthread_mutex_unlock(&krb5cc_mutex);
	if (status)
		fatal(status);

	if (ret) {
		error(logopt,
		      "krb5_cc_initialize failed with error %d", ret);
		goto out_cleanup_creds;
	}

	/* and store credentials for that principal */
	ret = krb5_cc_store_cred(ctxt->krb5ctxt, ctxt->krb5_ccache, &my_creds);
	if (ret) {
		error(logopt,
		      "krb5_cc_store_cred failed with error %d", ret);
		goto out_cleanup_creds;
	}

	/* finally, set the environment variable to point to our
	 * credentials cache */
	if (setenv(krb5ccenv, krb5ccval, 1) != 0) {
		error(logopt, "setenv failed with %d", errno);
		goto out_cleanup_creds;
	}
	ctxt->kinit_successful = 1;

	debug(logopt, "Kerberos authentication was successful!");

	krb5_free_unparsed_name(ctxt->krb5ctxt, tgs_name);
	krb5_free_cred_contents(ctxt->krb5ctxt, &my_creds);
	krb5_free_principal(ctxt->krb5ctxt, tgs_princ);
	krb5_free_principal(ctxt->krb5ctxt, krb5_client_princ);

	return 0;

out_cleanup_creds:
	krb5cc_in_use--;
	krb5_free_cred_contents(ctxt->krb5ctxt, &my_creds);
out_cleanup_unparse:
	krb5_free_principal(ctxt->krb5ctxt, tgs_princ);
	krb5_free_unparsed_name(ctxt->krb5ctxt, tgs_name);
out_cleanup_client_princ:
	krb5_free_principal(ctxt->krb5ctxt, krb5_client_princ);
out_cleanup_cc:
	status = pthread_mutex_lock(&krb5cc_mutex);
	if (status)
		fatal(status);

	if (krb5cc_in_use)
		ret = krb5_cc_close(ctxt->krb5ctxt, ctxt->krb5_ccache);
	else
		ret = krb5_cc_destroy(ctxt->krb5ctxt, ctxt->krb5_ccache);
	if (ret)
		warn(logopt,
		     "krb5_cc_destroy failed with non-fatal error %d", ret);

	status = pthread_mutex_unlock(&krb5cc_mutex);
	if (status)
		fatal(status);

	krb5_free_context(ctxt->krb5ctxt);

	return -1;
}

/*
 *  Check a client given external credential cache.
 *
 *  Returns 0 upon success.  ctxt->kinit_done and ctxt->kinit_successful
 *  are set for cleanup purposes.  The krb5 context and ccache entries in
 *  the lookup_context are also filled in.
 *
 *  Upon failure, -1 is returned.
 */
int
sasl_do_kinit_ext_cc(unsigned logopt, struct lookup_context *ctxt)
{
	krb5_principal def_princ;
	krb5_principal krb5_client_princ;
	krb5_error_code ret;
	char *cc_princ, *client_princ;

	if (ctxt->kinit_done)
		return 0;
	ctxt->kinit_done = 1;

	debug(logopt,
	      "using external credential cache for auth: client principal %s",
	      ctxt->client_princ ? ctxt->client_princ : default_client);

	ret = krb5_init_context(&ctxt->krb5ctxt);
	if (ret) {
		error(logopt, "krb5_init_context failed with %d", ret);
		return -1;
	}

	ret = krb5_cc_resolve(ctxt->krb5ctxt, ctxt->client_cc, &ctxt->krb5_ccache);
	if (ret) {
		error(logopt, "krb5_cc_resolve failed with error %d",
		      ret);
		krb5_cc_close(ctxt->krb5ctxt, ctxt->krb5_ccache);
		krb5_free_context(ctxt->krb5ctxt);
		return -1;
	}

	ret = krb5_cc_get_principal(ctxt->krb5ctxt, ctxt->krb5_ccache, &def_princ);
	if (ret) {
		error(logopt, "krb5_cc_get_principal failed with error %d", ret);
		krb5_cc_close(ctxt->krb5ctxt, ctxt->krb5_ccache);
		krb5_free_context(ctxt->krb5ctxt);
		return -1;
	}

	ret = krb5_unparse_name(ctxt->krb5ctxt, def_princ, &cc_princ);
	if (ret) {
		error(logopt, "krb5_unparse_name failed with error %d", ret);
		krb5_free_principal(ctxt->krb5ctxt, def_princ);
		krb5_cc_close(ctxt->krb5ctxt, ctxt->krb5_ccache);
		krb5_free_context(ctxt->krb5ctxt);
		return -1;
	}

	debug(logopt, "external credential cache default principal %s", cc_princ);

	/*
	 * If the principal isn't set in the config construct the default
	 * so we can check against the default principal of the external
	 * cred cache.
	 */
	if (ctxt->client_princ)
		client_princ = ctxt->client_princ;
	else {
		debug(logopt,
		      "calling krb5_sname_to_principal using defaults");

		ret = krb5_sname_to_principal(ctxt->krb5ctxt, NULL,
					default_client, KRB5_NT_SRV_HST, 
					&krb5_client_princ);
		if (ret) {
			error(logopt,
			      "krb5_sname_to_principal failed for "
			      "%s with error %d", default_client, ret);
			krb5_free_principal(ctxt->krb5ctxt, def_princ);
			krb5_cc_close(ctxt->krb5ctxt, ctxt->krb5_ccache);
			krb5_free_context(ctxt->krb5ctxt);
			return -1;
		}


		ret = krb5_unparse_name(ctxt->krb5ctxt,
					krb5_client_princ, &client_princ);
		if (ret) {
			debug(logopt,
			      "krb5_unparse_name failed with error %d",
			      ret);
			krb5_free_principal(ctxt->krb5ctxt, krb5_client_princ);
			krb5_free_principal(ctxt->krb5ctxt, def_princ);
			krb5_cc_close(ctxt->krb5ctxt, ctxt->krb5_ccache);
			krb5_free_context(ctxt->krb5ctxt);
			return -1;
		}

		debug(logopt,
		      "principal used for authentication: %s", client_princ);

		krb5_free_principal(ctxt->krb5ctxt, krb5_client_princ);
	}

	/*
	 * Check if the principal to be used matches the default principal in
	 * the external cred cache.
	 */
	if (strcmp(cc_princ, client_princ)) {
		error(logopt,
		      "configured client principal %s ",
		      ctxt->client_princ);
		error(logopt,
		      "external credential cache default principal %s",
		      cc_princ);
		error(logopt, 
		      "cannot use credential cache, external "
		      "default principal does not match configured "
		      "principal");
		if (!ctxt->client_princ)
			krb5_free_unparsed_name(ctxt->krb5ctxt, client_princ);
		krb5_free_unparsed_name(ctxt->krb5ctxt, cc_princ);
		krb5_free_principal(ctxt->krb5ctxt, def_princ);
		krb5_cc_close(ctxt->krb5ctxt, ctxt->krb5_ccache);
		krb5_free_context(ctxt->krb5ctxt);
		return -1;
	}

	if (!ctxt->client_princ)
		krb5_free_unparsed_name(ctxt->krb5ctxt, client_princ);
	krb5_free_unparsed_name(ctxt->krb5ctxt, cc_princ);
	krb5_free_principal(ctxt->krb5ctxt, def_princ);

	/* Set the environment variable to point to the external cred cache */
	if (setenv(krb5ccenv, ctxt->client_cc, 1) != 0) {
		error(logopt, "setenv failed with %d", errno);
		krb5_cc_close(ctxt->krb5ctxt, ctxt->krb5_ccache);
		krb5_free_context(ctxt->krb5ctxt);
		return -1;
	}
	ctxt->kinit_successful = 1;

	debug(logopt, "Kerberos authentication was successful!");

	return 0;
}

/*
 *  Attempt to bind to the ldap server using a given authentication
 *  mechanism.  ldap should be a properly initialzed ldap pointer.
 *
 *  Returns a valid sasl_conn_t pointer upon success, NULL on failure.
 */
sasl_conn_t *
sasl_bind_mech(unsigned logopt, LDAP *ldap, struct lookup_context *ctxt, const char *mech)
{
	sasl_conn_t *conn;
	char *tmp, *host = NULL;
	const char *clientout;
	unsigned int clientoutlen;
	const char *chosen_mech;
	int result;

	if (!strncmp(mech, "GSSAPI", 6)) {
		if (ctxt->client_cc)
			result = sasl_do_kinit_ext_cc(logopt, ctxt);
		else
			result = sasl_do_kinit(logopt, ctxt);
		if (result != 0)
			return NULL;
	}

	debug(logopt, "Attempting sasl bind with mechanism %s", mech);

	result = ldap_get_option(ldap, LDAP_OPT_HOST_NAME, &host);
	if (result != LDAP_OPT_SUCCESS || !host) {
		debug(logopt, "failed to get hostname for connection");
		return NULL;
	}

	/*
	 * We need a host name to start the client.
	 * But the ldap library can return a list of host names so
	 * just use the first one.
	 */
	if ((tmp = strchr(host, ' ')))
		*tmp = '\0';
	if ((tmp = strrchr(host, ':'))) {
		if (*(tmp - 1) != ']') {
			*tmp = '\0';
			tmp = host;
		} else {
			*(tmp - 1) = '\0';
			tmp = host;
			if (*tmp == '[')
				tmp++;
		}
	}

	/* Create a new authentication context for the service. */
	result = sasl_client_new("ldap", tmp, NULL, NULL, NULL, 0, &conn);
	if (result != SASL_OK) {
		error(logopt, "sasl_client_new failed with error %d",
		      result);
		ldap_memfree(host);
		return NULL;
	}

	chosen_mech = NULL;
	result = sasl_client_start(conn, mech, NULL,
				&clientout, &clientoutlen, &chosen_mech);

	/* OK and CONTINUE are the only non-fatal return codes here. */
	if ((result != SASL_OK) && (result != SASL_CONTINUE)) {
		warn(logopt, "sasl_client_start failed for %s", host);
		debug(logopt, "sasl_client_start: %s", sasl_errdetail(conn));
		ldap_memfree(host);
		sasl_dispose(&conn);
		return NULL;
	}

	result = do_sasl_bind(logopt, ldap, conn,
			 &clientout, &clientoutlen, chosen_mech, result);
	if (result == 0) {
		ldap_memfree(host);
		debug(logopt, "sasl bind with mechanism %s succeeded",
		      chosen_mech);
		return conn;
	}

	info(logopt, "sasl bind with mechanism %s failed", mech);

	/* sasl bind failed */
	ldap_memfree(host);
	sasl_dispose(&conn);

	return NULL;
}

/*
 *  Returns 0 if a suitable authentication mechanism is available.  Returns
 *  -1 on error or if no mechanism is supported by both client and server.
 */
sasl_conn_t *
sasl_choose_mech(unsigned logopt, LDAP *ldap, struct lookup_context *ctxt)
{
	sasl_conn_t *conn = NULL;
	int authenticated;
	int i;
	char **mechanisms;

	mechanisms = get_server_SASL_mechanisms(logopt, ldap);
	if (!mechanisms)
		return NULL;

	/* Try each supported mechanism in turn. */
	authenticated = 0;
	for (i = 0; mechanisms[i] != NULL; i++) {
		/*
		 *  This routine is called if there is no configured
		 *  mechanism.  As such, we can skip over any auth
		 *  mechanisms that require user credentials.  These include
		 *  PLAIN, LOGIN, and DIGEST-MD5.
		 */
		if (authtype_requires_creds(mechanisms[i]))
			continue;

		conn = sasl_bind_mech(logopt, ldap, ctxt, mechanisms[i]);
		if (conn) {
			ctxt->sasl_mech = strdup(mechanisms[i]);
			if (!ctxt->sasl_mech) {
				crit(logopt, "Successfully authenticated with "
				     "mechanism %s, but failed to allocate "
				     "memory to hold the mechanism type.",
				     mechanisms[i]);
				sasl_dispose(&conn);
				ldap_value_free(mechanisms);
				return NULL;
			}
			authenticated = 1;
			break;
		}
		debug(logopt, "Failed to authenticate with mech %s",
		      mechanisms[i]);
	}

	debug(logopt, "authenticated: %d, sasl_mech: %s",
	      authenticated, ctxt->sasl_mech);

	ldap_value_free(mechanisms);
	return conn;
}

/*
 *  Routine called when unbinding an ldap connection.
 */
void
autofs_sasl_unbind(struct lookup_context *ctxt)
{
	if (ctxt->sasl_conn) {
		sasl_dispose(&ctxt->sasl_conn);
		ctxt->sasl_conn = NULL;
	}
}

/*
 *  Given a lookup context that has been initialized with any user-specified
 *  parameters, figure out which sasl mechanism to use.  Then, initialize
 *  the necessary parameters to authenticate with the chosen mechanism.
 *
 *  Return Values:
 *  0  -  Success
 * -1  -  Failure
 */
int
autofs_sasl_bind(unsigned logopt, LDAP *ldap, struct lookup_context *ctxt)
{
	sasl_conn_t *conn = NULL;

	/* If we already have a connection use it */
	if (ctxt->sasl_conn)
		return 0;

	if (ctxt->sasl_mech && !strncmp(ctxt->sasl_mech, "EXTERNAL", 8)) {
		int result;

		debug(logopt,
		      "Attempting sasl bind with mechanism %s",
		      ctxt->sasl_mech);

		result = do_sasl_extern(ldap, ctxt);
		if (result)
			debug(logopt,
			      "Failed to authenticate with mech %s",
			      ctxt->sasl_mech);
		else
			debug(logopt,
			      "sasl bind with mechanism %s succeeded",
			      ctxt->sasl_mech);

		return result;
	}

	sasl_auth_id = ctxt->user;
	sasl_auth_secret = ctxt->secret;

	if (ctxt->auth_required & LDAP_AUTH_AUTODETECT) {
		if (ctxt->sasl_mech) {
			free(ctxt->sasl_mech);
			ctxt->sasl_mech = NULL;
		}
	}

	/*
	 *  If LDAP_AUTH_AUTODETECT is set, it means that there was no
	 *  mechanism specified in the configuration file or auto
	 *  selection has been requested, so try to auto-select an
	 *  auth mechanism.
	 */
	if (ctxt->sasl_mech)
		conn = sasl_bind_mech(logopt, ldap, ctxt, ctxt->sasl_mech);
	else
		conn = sasl_choose_mech(logopt, ldap, ctxt);

	if (!conn)
		return -1;

	ctxt->sasl_conn = conn;
	return 0;
}

/*
 *  Destructor routine.  This should be called when finished with an ldap
 *  session.
 */
void autofs_sasl_dispose(struct lookup_context *ctxt)
{
	int status, ret;

	if (ctxt->sasl_conn) {
		sasl_dispose(&ctxt->sasl_conn);
		ctxt->sasl_conn = NULL;
	}

	if (ctxt->kinit_successful) {
		status = pthread_mutex_lock(&krb5cc_mutex);
		if (status)
			fatal(status);

		if (--krb5cc_in_use || ctxt->client_cc)
			ret = krb5_cc_close(ctxt->krb5ctxt, ctxt->krb5_ccache);
		else 
			ret = krb5_cc_destroy(ctxt->krb5ctxt, ctxt->krb5_ccache);
		if (ret)
			logmsg("krb5_cc_destroy failed with non-fatal error %d",
			     ret);

		status = pthread_mutex_unlock(&krb5cc_mutex);
		if (status)
			fatal(status);

		krb5_free_context(ctxt->krb5ctxt);
		if (unsetenv(krb5ccenv) != 0)
			logerr("unsetenv failed with error %d", errno);

		ctxt->krb5ctxt = NULL;
		ctxt->krb5_ccache = NULL;
		ctxt->kinit_done = 0;
		ctxt->kinit_successful = 0;
	}
}

static void *sasl_mutex_new(void)
{
	pthread_mutex_t* mutex;

	mutex = malloc(sizeof(pthread_mutex_t));
	if (!mutex)
		return 0;
		
	pthread_mutex_init(mutex, NULL);

	return (void *) mutex;
}

static int sasl_mutex_lock(void *mutex __attribute__((unused)))
{
	int rc;

	if (!mutex)
		return SASL_FAIL;

	rc = pthread_mutex_lock((pthread_mutex_t *) mutex);

	return (rc==0 ? SASL_OK : SASL_FAIL);
}

static int sasl_mutex_unlock(void *mutex __attribute__((unused)))
{
	int rc;

	if (!mutex)
		return SASL_FAIL;

	rc = pthread_mutex_unlock((pthread_mutex_t *) mutex);

	return (rc==0 ? SASL_OK : SASL_FAIL);
}

static void sasl_mutex_dispose(void *mutex __attribute__((unused)))
{
	int rc;

	if (!mutex)
		return;

	rc = pthread_mutex_destroy((pthread_mutex_t *) mutex);
	if (rc == 0)
		free(mutex);

	return;
}

/*
 * Initialize the sasl callbacks, which increments the global
 * use counter.
 */
int autofs_sasl_client_init(unsigned logopt)
{

	sasl_set_mutex(sasl_mutex_new,
		       sasl_mutex_lock,
		       sasl_mutex_unlock,
		       sasl_mutex_dispose);

	/* Start up Cyrus SASL--only needs to be done at library load. */
	if (sasl_client_init(callbacks) != SASL_OK) {
		error(logopt, "sasl_client_init failed");
		return 0;
	}
	return 1;
}

/*
 * Decrement the library reference count and free resources if
 * we are the last to close the library.
 */
void autofs_sasl_done(void)
{
	sasl_done();
	return;
}

