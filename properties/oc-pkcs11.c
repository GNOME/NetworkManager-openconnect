/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Enumeration of X.509 certificates on PKCS#11 tokens (smartcards).
 */

#include "nm-default.h"

#include <glib/gi18n-lib.h>
#include <gck/gck.h>

#include "oc-pkcs11.h"

/* Values from the PKCS#11 specification */
#define OC_CKA_CLASS             0x00UL
#define OC_CKA_LABEL             0x03UL
#define OC_CKA_CERTIFICATE_TYPE  0x80UL
#define OC_CKA_ID                0x102UL
#define OC_CKO_CERTIFICATE       0x01UL
#define OC_CKO_PRIVATE_KEY       0x03UL
#define OC_CKC_X_509             0x00UL

void
oc_pkcs11_cert_free (OcPkcs11Cert *cert)
{
	if (!cert)
		return;
	g_free (cert->label);
	g_free (cert->token_label);
	g_free (cert->cert_uri);
	g_free (cert->key_uri);
	g_free (cert);
}

static char *
build_uri (GckTokenInfo *token_info, gulong klass, const GckAttribute *id, const char *label)
{
	GckUriData *data = gck_uri_data_new ();
	GckBuilder builder = GCK_BUILDER_INIT;
	char *uri;

	data->token_info = gck_token_info_copy (token_info);
	gck_builder_add_ulong (&builder, OC_CKA_CLASS, klass);
	if (id)
		gck_builder_add_attribute (&builder, id);
	if (label)
		gck_builder_add_string (&builder, OC_CKA_LABEL, label);
	data->attributes = gck_builder_end (&builder);

	uri = gck_uri_data_build (data, GCK_URI_FOR_OBJECT_ON_TOKEN);
	gck_uri_data_free (data);
	return uri;
}

static void
list_slot (GckSlot *slot, GPtrArray *result)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckTokenInfo *token_info;
	GckSession *session;
	GckAttributes *match;
	GList *objects, *l;

	token_info = gck_slot_get_token_info (slot);
	if (!token_info)
		return;

	/* Skip the system trust store (p11-kit-trust): hundreds of CA certificates, no smartcards */
	if (g_strcmp0 (token_info->manufacturer_id, "PKCS#11 Kit") == 0) {
		gck_token_info_free (token_info);
		return;
	}

	session = gck_slot_open_session (slot, GCK_SESSION_READ_ONLY, NULL, NULL, NULL);
	if (!session) {
		gck_token_info_free (token_info);
		return;
	}

	gck_builder_add_ulong (&builder, OC_CKA_CLASS, OC_CKO_CERTIFICATE);
	gck_builder_add_ulong (&builder, OC_CKA_CERTIFICATE_TYPE, OC_CKC_X_509);
	match = gck_builder_end (&builder);

	objects = gck_session_find_objects (session, match, NULL, NULL);
	for (l = objects; l; l = l->next) {
		GckAttributes *attrs;
		const GckAttribute *id;
		OcPkcs11Cert *cert;
		char *label = NULL;

		attrs = gck_object_get (GCK_OBJECT (l->data), NULL, NULL,
		                        OC_CKA_LABEL, OC_CKA_ID, GCK_INVALID);
		if (!attrs)
			continue;

		id = gck_attributes_find (attrs, OC_CKA_ID);
		gck_attributes_find_string (attrs, OC_CKA_LABEL, &label);

		cert = g_new0 (OcPkcs11Cert, 1);
		cert->label = label && *label ? label : g_strdup (_("Certificate"));
		if (cert->label != label)
			g_free (label);
		cert->token_label = g_strdup (token_info->label);
		cert->cert_uri = build_uri (token_info, OC_CKO_CERTIFICATE, id, cert->label);
		cert->key_uri = build_uri (token_info, OC_CKO_PRIVATE_KEY, id, NULL);
		g_ptr_array_add (result, cert);
		gck_attributes_unref (attrs);
	}

	g_list_free_full (objects, g_object_unref);
	gck_attributes_unref (match);
	g_object_unref (session);
	gck_token_info_free (token_info);
}

static void
list_thread (GTask *task, gpointer source, gpointer task_data, GCancellable *cancellable)
{
	GError *error = NULL;
	GList *modules, *slots, *l;
	GPtrArray *result;

	modules = gck_modules_initialize_registered (cancellable, &error);
	if (error) {
		g_task_return_error (task, error);
		return;
	}

	result = g_ptr_array_new_with_free_func ((GDestroyNotify) oc_pkcs11_cert_free);
	slots = gck_modules_get_slots (modules, TRUE);
	for (l = slots; l; l = l->next) {
		if (g_cancellable_is_cancelled (cancellable))
			break;
		list_slot (GCK_SLOT (l->data), result);
	}

	g_list_free_full (slots, g_object_unref);
	g_list_free_full (modules, g_object_unref);
	g_task_return_pointer (task, result, (GDestroyNotify) g_ptr_array_unref);
}

void
oc_pkcs11_list_certs_async (GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data)
{
	GTask *task = g_task_new (NULL, cancellable, callback, user_data);

	g_task_run_in_thread (task, list_thread);
	g_object_unref (task);
}

GPtrArray *
oc_pkcs11_list_certs_finish (GAsyncResult *result, GError **error)
{
	return g_task_propagate_pointer (G_TASK (result), error);
}
