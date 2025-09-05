/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Certificate / private key chooser built on libadwaita widgets.
 * Replacement for NmaCertChooser, which is not ported to GTK4/libadwaita.
 */

#ifndef _OC_CERT_CHOOSER_H_
#define _OC_CERT_CHOOSER_H_

#include <gtk/gtk.h>
#include <adwaita.h>

G_BEGIN_DECLS

#define OC_TYPE_CERT_CHOOSER (oc_cert_chooser_get_type ())
G_DECLARE_FINAL_TYPE (OcCertChooser, oc_cert_chooser, OC, CERT_CHOOSER, AdwPreferencesGroup)

GtkWidget  *oc_cert_chooser_new (const char *title, gboolean show_key);

/* Values are file paths or "pkcs11:" URIs. Getters return NULL if unset. */
void        oc_cert_chooser_set_cert (OcCertChooser *self, const char *value);
const char *oc_cert_chooser_get_cert (OcCertChooser *self);
void        oc_cert_chooser_set_key  (OcCertChooser *self, const char *value);
const char *oc_cert_chooser_get_key  (OcCertChooser *self);

G_END_DECLS

#endif
