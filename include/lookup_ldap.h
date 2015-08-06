#ifndef LOOKUP_LDAP_H
#define LOOKUP_LDAP_H

#include <ldap.h>

#ifdef WITH_SASL
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sasl/sasl.h>
#include <krb5.h>
#endif

#include <libxml/tree.h>

#include "list.h"
#include "dclist.h"

struct ldap_schema {
	char *map_class;
	char *map_attr;
	char *entry_class;
	char *entry_attr;
	char *value_attr;
};

struct ldap_uri {
	char *uri;
	struct list_head list;
};

struct ldap_searchdn {
	char *basedn;
	struct ldap_searchdn *next;
};

struct lookup_context {
	char *mapname;
	unsigned int format;

	char *server;
	int port;
	char *base;
	char *qdn;
	unsigned int timeout;
	unsigned int network_timeout;
	unsigned long timestamp;
	unsigned int check_defaults;

	/* LDAP version 2 or 3 */
	int version;

	/* LDAP lookup configuration */
	struct ldap_schema *schema;

	/*
 	 * List of servers and base dns for searching.
 	 * uri is the list of servers to attempt connection to and is
 	 * used only if server, above, is NULL. The head of the list
 	 * is the server which we are currently connected to.
 	 * cur_host tracks chnages to connected server, triggering
 	 * a scan of basedns when it changes.
 	 * sdns is the list of basdns to check, done in the order
 	 * given in configuration.
 	 */
	pthread_mutex_t uris_mutex;
	struct list_head *uris;
	struct ldap_uri *uri;
	struct dclist *dclist;
	char *cur_host;
	struct ldap_searchdn *sdns;

	/* TLS and SASL authentication information */
	char        *auth_conf;
	unsigned     use_tls;
	unsigned     tls_required;
	unsigned     auth_required;
	char        *sasl_mech;
	char        *user;
	char        *secret;
	char        *client_princ;
	char        *client_cc;
	int          kinit_done;
	int          kinit_successful;
#ifdef WITH_SASL
	/* Kerberos */
	krb5_context krb5ctxt;
	krb5_ccache  krb5_ccache;
	sasl_conn_t  *sasl_conn;
	/* SASL external */
	char	     *extern_cert;
	char	     *extern_key;
#endif
	/* keytab file name needs to be added */

	struct parse_mod *parse;
};


#define LDAP_AUTH_CONF_FILE "test"

#define LDAP_TLS_DONT_USE	0
#define LDAP_TLS_REQUIRED	1
#define LDAP_TLS_INIT		1
#define LDAP_TLS_RELEASE	2

#define LDAP_AUTH_NOTREQUIRED	0x0001
#define LDAP_AUTH_REQUIRED	0x0002
#define LDAP_AUTH_AUTODETECT	0x0004
#define LDAP_NEED_AUTH		(LDAP_AUTH_REQUIRED|LDAP_AUTH_AUTODETECT)

#define LDAP_AUTH_USESIMPLE	0x0008

/* lookup_ldap.c */
LDAP *init_ldap_connection(unsigned logopt, const char *uri, struct lookup_context *ctxt);
int unbind_ldap_connection(unsigned logopt, LDAP *ldap, struct lookup_context *ctxt);
int authtype_requires_creds(const char *authtype);

#ifdef WITH_SASL
/* cyrus-sasl.c */
int autofs_sasl_client_init(unsigned logopt);
int autofs_sasl_init(unsigned logopt, LDAP *ldap, struct lookup_context *ctxt);
int autofs_sasl_bind(unsigned logopt, LDAP *ldap, struct lookup_context *ctxt);
void autofs_sasl_unbind(struct lookup_context *ctxt);
void autofs_sasl_dispose(struct lookup_context *ctxt);
void autofs_sasl_done(void);
/* cyrus-sasl-extern */
int do_sasl_extern(LDAP *ldap, struct lookup_context *ctxt);
#endif

#endif
