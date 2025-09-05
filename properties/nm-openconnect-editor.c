/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * Copyright (C) 2005 David Zeuthen, <davidz@redhat.com>
 * Copyright (C) 2005 - 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2005 - 2021 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 **************************************************************************/

#include "nm-default.h"

#include "nm-openconnect-editor.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <adwaita.h>


#include <openconnect.h>

#include "auth-helpers.h"
#include "oc-cert-chooser.h"

/************** UI widget class **************/

static void openconnect_editor_interface_init (NMVpnEditorInterface *iface_class);

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkWindowGroup *window_group;
	gboolean window_added;
} OpenconnectEditorPrivate;

G_DEFINE_TYPE_EXTENDED (OpenconnectEditor, openconnect_editor, G_TYPE_OBJECT, 0,
                        G_ADD_PRIVATE (OpenconnectEditor)
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               openconnect_editor_interface_init))

#define OPENCONNECT_EDITOR_GET_PRIVATE(o) ((OpenconnectEditorPrivate *) openconnect_editor_get_instance_private (OPENCONNECT_EDITOR (o)))

#define COL_AUTH_NAME 0
#define COL_AUTH_PAGE 1
#define COL_AUTH_TYPE 2

/*****************************************************************************/

static gboolean
check_validity (OpenconnectEditor *self, GError **error)
{
	OpenconnectEditorPrivate *priv = OPENCONNECT_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_OPENCONNECT_KEY_GATEWAY);
		return FALSE;
	}


	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "proxy_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && str[0] &&
		strncmp(str, "socks://", 8) && strncmp(str, "http://", 7)) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_OPENCONNECT_KEY_PROXY);
		return FALSE;
	}

	if (!auth_widget_check_validity (priv->builder, error))
		return FALSE;

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (OPENCONNECT_EDITOR (user_data), "changed");
}

static void
switch_changed_cb (GtkWidget *widget, GParamSpec *pspec, gpointer user_data)
{
	stuff_changed_cb (widget, user_data);
}

/* Must match the order of the items of the "token_mode" model in the UI file */
static const struct {
	const char *pref_value;
	const char *token_type;
	gboolean secret_editable;
} token_modes[] = {
	{ "disabled", "any",      FALSE },
	{ "stokenrc", "stoken",   FALSE },
	{ "manual",   "stoken",   TRUE  },
	{ "totp",     "totp",     TRUE  },
	{ "hotp",     "hotp",     TRUE  },
	{ "yubioath", "yubioath", TRUE  },
};

/* Maps the position of each remaining combo row item to its token_modes index */
#define TOKEN_MODE_INDICES_KEY "token-mode-indices"

static int
token_mode_get_selected (AdwComboRow *token_mode)
{
	GArray *indices = g_object_get_data (G_OBJECT (token_mode), TOKEN_MODE_INDICES_KEY);
	guint selected = adw_combo_row_get_selected (token_mode);

	if (!indices || selected >= indices->len)
		return -1;
	return g_array_index (indices, int, selected);
}

static void
update_token_secret_sensitivity (OpenconnectEditorPrivate *priv)
{
	AdwComboRow *token_mode = ADW_COMBO_ROW (gtk_builder_get_object (priv->builder, "token_mode"));
	GtkWidget *secret = GTK_WIDGET (gtk_builder_get_object (priv->builder, "token_secret"));
	int mode = token_mode_get_selected (token_mode);

	gtk_widget_set_sensitive (secret, mode >= 0 && token_modes[mode].secret_editable);
}

static void
token_mode_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	OpenconnectEditor *self = OPENCONNECT_EDITOR (user_data);

	update_token_secret_sensitivity (OPENCONNECT_EDITOR_GET_PRIVATE (self));
	g_signal_emit_by_name (self, "changed");
}

static gboolean
token_mode_supported (const char *token_type)
{
	if (!strcmp (token_type, "stoken"))
		return openconnect_has_stoken_support ();
	if (!strcmp (token_type, "totp") || !strcmp (token_type, "hotp"))
		return openconnect_has_oath_support ();
	if (!strcmp (token_type, "yubioath"))
		return openconnect_has_yubioath_support ();
	return TRUE;
}

static gboolean
init_token_mode_options (AdwComboRow *token_mode)
{
	GtkStringList *list = GTK_STRING_LIST (adw_combo_row_get_model (token_mode));
	GArray *indices = g_array_new (FALSE, FALSE, sizeof (int));
	guint n = g_list_model_get_n_items (G_LIST_MODEL (list));
	guint i;
	guint pos = 0;

	g_return_val_if_fail (n == G_N_ELEMENTS (token_modes), FALSE);

	for (i = 0; i < n; i++) {
		int idx = i;

		if (token_mode_supported (token_modes[i].token_type)) {
			g_array_append_val (indices, idx);
			pos++;
		} else {
			gtk_string_list_remove (list, pos);
		}
	}

	g_object_set_data_full (G_OBJECT (token_mode), TOKEN_MODE_INDICES_KEY, indices,
	                        (GDestroyNotify) g_array_unref);

	/* if the only option is "Disabled", don't show the token section at all */
	return indices->len > 1;
}

static gboolean
init_token_ui (OpenconnectEditor *self,
               OpenconnectEditorPrivate *priv,
               NMSettingVpn *s_vpn)
{
	GtkWidget *widget;
	AdwComboRow *token_mode;
	const char *value;

	token_mode = ADW_COMBO_ROW (gtk_builder_get_object (priv->builder, "token_mode"));
	g_return_val_if_fail (token_mode, FALSE);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "sta_group"));
	g_return_val_if_fail (widget, FALSE);

	if (!init_token_mode_options (token_mode)) {
		gtk_widget_set_visible (widget, FALSE);
		return TRUE;
	}
	gtk_widget_set_visible (widget, TRUE);

	if (s_vpn) {
		GArray *indices = g_object_get_data (G_OBJECT (token_mode), TOKEN_MODE_INDICES_KEY);
		guint active_option = 0;

		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_TOKEN_MODE);
		if (value) {
			guint i;

			for (i = 0; i < indices->len; i++) {
				if (!strcmp (value, token_modes[g_array_index (indices, int, i)].pref_value))
					active_option = i;
			}
		}
		adw_combo_row_set_selected (token_mode, active_option);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "token_secret"));
	g_return_val_if_fail (widget, FALSE);

	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, NM_OPENCONNECT_KEY_TOKEN_SECRET);
		if (!value)
			value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_TOKEN_SECRET);
		if (value)
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	update_token_secret_sensitivity (priv);
	g_signal_connect (G_OBJECT (token_mode), "notify::selected", G_CALLBACK (token_mode_changed_cb), self);

	return TRUE;
}

static void
update_protocol_dependent_ui (OpenconnectEditorPrivate *priv)
{
	AdwComboRow *protocol_combo = ADW_COMBO_ROW (gtk_builder_get_object (priv->builder, "protocol_combo"));
	GtkWidget *mca = GTK_WIDGET (gtk_builder_get_object (priv->builder, "mca_cert_chooser"));
	struct oc_vpn_proto *protos;
	guint selected = adw_combo_row_get_selected (protocol_combo);
	gboolean show_mca = FALSE;
	int n;

	if (!mca)
		return;

	n = openconnect_get_supported_protocols (&protos);
	if (selected != GTK_INVALID_LIST_POSITION && selected < (guint) n)
		show_mca = !!(protos[selected].flags & OC_PROTO_AUTH_MCA);
	openconnect_free_supported_protocols (protos);

	gtk_widget_set_visible (mca, show_mca);
}

static void
protocol_changed_cb (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	OpenconnectEditor *self = OPENCONNECT_EDITOR (user_data);

	update_protocol_dependent_ui (OPENCONNECT_EDITOR_GET_PRIVATE (self));
	g_signal_emit_by_name (self, "changed");
}

static gboolean
init_protocol_combo_options (AdwComboRow *protocol_combo,
                             const char  *proto)
{
	GtkStringList *protocol_combo_list = GTK_STRING_LIST (adw_combo_row_get_model (protocol_combo));
	struct oc_vpn_proto *protos;
	int i, n;
	int pos = 0;

	n = openconnect_get_supported_protocols(&protos);
	for (i = 0; i < n; i++) {
		gtk_string_list_append (protocol_combo_list, protos[i].pretty_name);
		if (pos == 0 && g_strcmp0 (protos[i].name, proto) == 0)
			pos = i;
	}
	openconnect_free_supported_protocols(protos);

	adw_combo_row_set_selected (protocol_combo, pos);
	return TRUE;
}

static gboolean
init_protocol_ui (OpenconnectEditor *self,
				  OpenconnectEditorPrivate *priv,
				  NMSettingVpn *s_vpn)
{
	AdwComboRow *protocol_combo;
	const char *value = NULL;

	protocol_combo = ADW_COMBO_ROW (gtk_builder_get_object (priv->builder, "protocol_combo"));
	if (!protocol_combo)
		return FALSE;

	if (s_vpn)
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PROTOCOL);

	if (!init_protocol_combo_options (protocol_combo, value))
		return TRUE;

	update_protocol_dependent_ui (priv);
	g_signal_connect (G_OBJECT (protocol_combo), "notify::selected", G_CALLBACK (protocol_changed_cb), self);

	return TRUE;
}

static gboolean
init_editor_plugin (OpenconnectEditor *self, NMConnection *connection, GError **error)
{
	OpenconnectEditorPrivate *priv = OPENCONNECT_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	const char *value;

	s_vpn = nm_connection_get_setting_vpn (connection);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	g_return_val_if_fail (widget, FALSE);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_GATEWAY);
		if (value)
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "proxy_entry"));
	g_return_val_if_fail (widget, FALSE);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PROXY);
		if (value)
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_agent_entry"));
	g_return_val_if_fail (widget, FALSE);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_USERAGENT);
		if (value)
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "fsid_button"));
	g_return_val_if_fail (widget, FALSE);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID);
		if (value && !strcmp(value, "yes"))
			adw_switch_row_set_active (ADW_SWITCH_ROW (widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "notify::active", G_CALLBACK (switch_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "prevent_invalid_cert_button"));
	g_return_val_if_fail (widget, FALSE);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PREVENT_INVALID_CERT);
		if (value && !strcmp(value, "yes"))
			adw_switch_row_set_active (ADW_SWITCH_ROW (widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "notify::active", G_CALLBACK (switch_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "disable_udp_button"));
	g_return_val_if_fail (widget, FALSE);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_DISABLE_UDP);
		if (value && !strcmp(value, "yes"))
			adw_switch_row_set_active(ADW_SWITCH_ROW (widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "notify::active", G_CALLBACK (switch_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "csd_button"));
	g_return_val_if_fail (widget, FALSE);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_ENABLE);
		if (value && !strcmp(value, "yes"))
			adw_expander_row_set_enable_expansion (ADW_EXPANDER_ROW (widget), TRUE);
	}
	g_signal_connect (G_OBJECT (widget), "notify::enable-expansion", G_CALLBACK (switch_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "csd_wrapper_entry"));
	g_return_val_if_fail (widget, FALSE);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_WRAPPER);
		if (value)
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "reported_os"));
	g_return_val_if_fail (widget, FALSE);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_REPORTED_OS);
		if (value)
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	if (init_token_ui (self, priv, s_vpn) == FALSE)
		g_return_val_if_reached (FALSE);

	if (init_protocol_ui (self, priv, s_vpn) == FALSE)
		g_return_val_if_reached (FALSE);

	tls_pw_init_auth_widget (priv->builder, s_vpn, stuff_changed_cb, self);

	return TRUE;
}

static GObject *
get_widget (NMVpnEditor *iface)
{
	OpenconnectEditor *self = OPENCONNECT_EDITOR (iface);
	OpenconnectEditorPrivate *priv = OPENCONNECT_EDITOR_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static gboolean
update_connection (NMVpnEditor *iface,
                   NMConnection *connection,
                   GError **error)
{
	OpenconnectEditor *self = OPENCONNECT_EDITOR (iface);
	OpenconnectEditorPrivate *priv = OPENCONNECT_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	char *str;
	const char *auth_type = NULL;
	const char *protocol = NULL;
	guint selected;
	int mode;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		protocol = nm_setting_vpn_get_data_item (s_vpn, NM_OPENCONNECT_KEY_PROTOCOL);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_OPENCONNECT, NULL);

	if (protocol)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PROTOCOL, protocol);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "protocol_combo"));
	selected = adw_combo_row_get_selected (ADW_COMBO_ROW (widget));

	{
		struct oc_vpn_proto *protos;
		int n = openconnect_get_supported_protocols (&protos);

		if (selected != GTK_INVALID_LIST_POSITION && selected < (guint) n)
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PROTOCOL, protos[selected].name);
		openconnect_free_supported_protocols (protos);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_GATEWAY, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "proxy_entry"));
	str = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PROXY, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_agent_entry"));
	str = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_USERAGENT, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "fsid_button"));
	str = adw_switch_row_get_active (ADW_SWITCH_ROW (widget))?"yes":"no";
	nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "prevent_invalid_cert_button"));
	str = adw_switch_row_get_active (ADW_SWITCH_ROW (widget))?"yes":"no";
	nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_PREVENT_INVALID_CERT, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "disable_udp_button"));
	str = adw_switch_row_get_active(ADW_SWITCH_ROW (widget))?"yes":"no";
	nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_DISABLE_UDP, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "csd_button"));
	str = adw_expander_row_get_enable_expansion (ADW_EXPANDER_ROW (widget))?"yes":"no";
	nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_ENABLE, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "csd_wrapper_entry"));
	str = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_CSD_WRAPPER, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "reported_os"));
	str = (char *) gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_REPORTED_OS, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "token_mode"));
	mode = token_mode_get_selected (ADW_COMBO_ROW (widget));
	if (mode >= 0)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_TOKEN_MODE, token_modes[mode].pref_value);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "token_secret"));
	str = g_strdup (gtk_editable_get_text (GTK_EDITABLE (widget)));
	if (str) {
		char *src = str, *dst = str;

		/* zap invalid characters */
		for (; *src; src++)
			if (*src >= ' ' && *src <= '~')
				*(dst++) = *src;
		*dst = 0;

		if (strlen (str))
			nm_setting_vpn_add_secret (s_vpn, NM_OPENCONNECT_KEY_TOKEN_SECRET, str);
		g_free (str);
	}

	if (!check_validity (self, error))
		return FALSE;

	/* These are different for every login session, and should not be stored */
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "gwcert",
	                             NM_SETTING_SECRET_FLAG_NOT_SAVED, NULL);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "cookie",
	                             NM_SETTING_SECRET_FLAG_NOT_SAVED, NULL);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "gateway",
	                             NM_SETTING_SECRET_FLAG_NOT_SAVED, NULL);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "resolve",
	                             NM_SETTING_SECRET_FLAG_NOT_SAVED, NULL);

	/* These are purely internal data for the auth-dialog, and should be stored */
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "xmlconfig",
	                             NM_SETTING_SECRET_FLAG_NONE, NULL);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "lasthost",
	                             NM_SETTING_SECRET_FLAG_NONE, NULL);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "autoconnect",
	                             NM_SETTING_SECRET_FLAG_NONE, NULL);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), "certsigs",
	                             NM_SETTING_SECRET_FLAG_NONE, NULL);
	/* Note that the auth-dialog will also store "extra" secrets for form
	   entries, depending on the arbitrary forms that we're offered by the
	   server during authentication. We can't know about those in advance,
	   but the presence of the above four is sufficient to trigger a write
	   of the new secrets, and the code in the keyfile plugin will treat the
	   absence of a flags configuration for a given secret as equivalent to
	   FLAG_NONE, and thus save our "extra" secrets too. */

	auth_widget_update_connection (priv->builder, auth_type, s_vpn);

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	return TRUE;
}

NMVpnEditor *
nm_vpn_editor_new (NMConnection *connection, GError **error)
{
	NMVpnEditor *object;
	OpenconnectEditorPrivate *priv;
	g_autoptr (GError) local_error = NULL;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = g_object_new (OPENCONNECT_TYPE_EDITOR, NULL);
	if (!object) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, "could not create openconnect object");
		return NULL;
	}

	priv = OPENCONNECT_EDITOR_GET_PRIVATE (object);

	g_type_ensure (OC_TYPE_CERT_CHOOSER);
	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_resource (priv->builder, "/org/freedesktop/network-manager-openconnect/nm-openconnect-dialog.ui", &local_error)) {
		g_warning ("Couldn't load builder file: %s", local_error ? local_error->message : "(unknown)");
		g_object_unref (object);
		return NULL;
	}

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "openconnect-vbox"));
	if (!priv->widget) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	if (!init_editor_plugin (OPENCONNECT_EDITOR (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	OpenconnectEditor *plugin = OPENCONNECT_EDITOR (object);
	OpenconnectEditorPrivate *priv = OPENCONNECT_EDITOR_GET_PRIVATE (plugin);

	if (priv->window_group)
		g_object_unref (priv->window_group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->builder)
		g_object_unref (priv->builder);

	G_OBJECT_CLASS (openconnect_editor_parent_class)->dispose (object);
}

static void
openconnect_editor_class_init (OpenconnectEditorClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);


	object_class->dispose = dispose;
}

static void
openconnect_editor_init (OpenconnectEditor *plugin)
{
}

static void
openconnect_editor_interface_init (NMVpnEditorInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

/*****************************************************************************/

#ifndef NM_VPN_OLD

#include "nm-openconnect-editor-plugin.h"

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_openconnect (NMVpnEditorPlugin *editor_plugin,
                                   NMConnection *connection,
                                   GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	return nm_vpn_editor_new (connection, error);
}
#endif

