/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 Tambet Ingo, <tambet@gmail.com>
 * Copyright (C) 2008 - 2021 Red Hat, Inc.
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

#include "auth-helpers.h"

#include "oc-cert-chooser.h"
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <openconnect.h>

static const char *
cert_scheme_value (const char *value)
{
	return value && *value ? value : NULL;
}

static void
init_chooser (GtkBuilder *builder,
              const char *widget_name,
              const char *cert_key,
              const char *key_key,
              NMSettingVpn *s_vpn,
              ChangedCallback changed_cb,
              gpointer user_data)
{
	OcCertChooser *chooser;

	chooser = OC_CERT_CHOOSER (gtk_builder_get_object (builder, widget_name));
	g_return_if_fail (chooser != NULL);

	if (s_vpn) {
		oc_cert_chooser_set_cert (chooser, cert_scheme_value (nm_setting_vpn_get_data_item (s_vpn, cert_key)));
		if (key_key)
			oc_cert_chooser_set_key (chooser, cert_scheme_value (nm_setting_vpn_get_data_item (s_vpn, key_key)));
	}

	g_signal_connect (G_OBJECT (chooser), "changed", G_CALLBACK (changed_cb), user_data);
}

void
tls_pw_init_auth_widget (GtkBuilder *builder,
                         NMSettingVpn *s_vpn,
                         ChangedCallback changed_cb,
                         gpointer user_data)
{
	g_return_if_fail (builder != NULL);
	g_return_if_fail (changed_cb != NULL);

	init_chooser (builder, "ca_chooser", NM_OPENCONNECT_KEY_CACERT, NULL,
	              s_vpn, changed_cb, user_data);
	init_chooser (builder, "mca_cert_chooser", NM_OPENCONNECT_KEY_MCACERT, NM_OPENCONNECT_KEY_MCAKEY,
	              s_vpn, changed_cb, user_data);
	init_chooser (builder, "user_cert_chooser", NM_OPENCONNECT_KEY_USERCERT, NM_OPENCONNECT_KEY_PRIVKEY,
	              s_vpn, changed_cb, user_data);
}

gboolean
auth_widget_check_validity (GtkBuilder *builder, GError **error)
{
	return TRUE;
}

static void
update_cert_from_filechooser (GtkBuilder *builder,
                              const char *key,
                              const char *widget_name,
                              NMSettingVpn *s_vpn)
{
	const char *filename;
	char *authtype;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (key != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	filename = oc_cert_chooser_get_cert (OC_CERT_CHOOSER (gtk_builder_get_object (builder, widget_name)));
	if (filename && strlen(filename)) {
		nm_setting_vpn_add_data_item (s_vpn, key, filename);
		authtype = "cert";
	} else {
		nm_setting_vpn_remove_data_item (s_vpn, key);
		authtype = "password";
	}
	/* Hack to keep older nm-auth-dialog working */
	if (!strcmp(key, NM_OPENCONNECT_KEY_USERCERT) || !strcmp(key, NM_OPENCONNECT_KEY_MCACERT))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENCONNECT_KEY_AUTHTYPE, authtype);
}

static void
update_key_from_filechooser (GtkBuilder *builder,
                             const char *key,
                             const char *widget_name,
                             NMSettingVpn *s_vpn)
{
	const char *filename;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (key != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	filename = oc_cert_chooser_get_key (OC_CERT_CHOOSER (gtk_builder_get_object (builder, widget_name)));
	if (filename && strlen(filename))
		nm_setting_vpn_add_data_item (s_vpn, key, filename);
	else
		nm_setting_vpn_remove_data_item (s_vpn, key);
}

gboolean
auth_widget_update_connection (GtkBuilder *builder,
                               const char *contype,
                               NMSettingVpn *s_vpn)
{
	update_cert_from_filechooser (builder, NM_OPENCONNECT_KEY_CACERT, "ca_chooser", s_vpn);

	update_cert_from_filechooser (builder, NM_OPENCONNECT_KEY_MCACERT, "mca_cert_chooser", s_vpn);
	update_key_from_filechooser (builder, NM_OPENCONNECT_KEY_MCAKEY, "mca_cert_chooser", s_vpn);

	update_cert_from_filechooser (builder, NM_OPENCONNECT_KEY_USERCERT, "user_cert_chooser", s_vpn);
	update_key_from_filechooser (builder, NM_OPENCONNECT_KEY_PRIVKEY, "user_cert_chooser", s_vpn);
	return TRUE;
}
