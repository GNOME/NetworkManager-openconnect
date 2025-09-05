/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Enumeration of X.509 certificates on PKCS#11 tokens (smartcards).
 */

#ifndef _OC_PKCS11_H_
#define _OC_PKCS11_H_

#include <gio/gio.h>

G_BEGIN_DECLS

typedef struct {
	char *label;       /* certificate label */
	char *token_label; /* token (smartcard) label */
	char *cert_uri;    /* pkcs11: URI of the certificate */
	char *key_uri;     /* pkcs11: URI of the matching private key */
} OcPkcs11Cert;

void oc_pkcs11_cert_free (OcPkcs11Cert *cert);

/* Runs in a worker thread; finish returns a GPtrArray of OcPkcs11Cert*. */
void        oc_pkcs11_list_certs_async  (GCancellable *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data);
GPtrArray * oc_pkcs11_list_certs_finish (GAsyncResult *result, GError **error);

G_END_DECLS

#endif
