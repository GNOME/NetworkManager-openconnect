/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/* NetworkManager -- Network link manager
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
 *   Copyright © 2008 - 2009 Intel Corporation.
 *
 * Based on nm-openconnect-vpnc.h:
 *   Copyright © 2005 - 2008 Red Hat, Inc.
 *   Copyright © 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SERVICE_DEFINES_H__
#define __NM_SERVICE_DEFINES_H__

#define NM_VPN_SERVICE_TYPE_OPENCONNECT "org.freedesktop.NetworkManager.openconnect"

#define NM_DBUS_SERVICE_OPENCONNECT    "org.freedesktop.NetworkManager.openconnect"
#define NM_DBUS_INTERFACE_OPENCONNECT  "org.freedesktop.NetworkManager.openconnect"
#define NM_DBUS_PATH_OPENCONNECT       "/org/freedesktop/NetworkManager/openconnect"

#define NM_OPENCONNECT_KEY_GATEWAY "gateway"
#define NM_OPENCONNECT_KEY_COOKIE "cookie"
#define NM_OPENCONNECT_KEY_GWCERT "gwcert"
#define NM_OPENCONNECT_KEY_RESOLVE "resolve"
#define NM_OPENCONNECT_KEY_AUTHTYPE "authtype"
#define NM_OPENCONNECT_KEY_USERCERT "usercert"
#define NM_OPENCONNECT_KEY_CACERT "cacert"
#define NM_OPENCONNECT_KEY_PRIVKEY "userkey"
#define NM_OPENCONNECT_KEY_KEY_PASS "key_pass"
#define NM_OPENCONNECT_KEY_MTU "mtu"
#define NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID "pem_passphrase_fsid"
#define NM_OPENCONNECT_KEY_PREVENT_INVALID_CERT "prevent_invalid_cert"
#define NM_OPENCONNECT_KEY_DISABLE_UDP "disable_udp"
#define NM_OPENCONNECT_KEY_PROTOCOL "protocol"
#define NM_OPENCONNECT_KEY_PROXY "proxy"
#define NM_OPENCONNECT_KEY_CSD_ENABLE "enable_csd_trojan"
#define NM_OPENCONNECT_KEY_USERAGENT "useragent"
#define NM_OPENCONNECT_KEY_CSD_WRAPPER "csd_wrapper"
#define NM_OPENCONNECT_KEY_TOKEN_MODE "stoken_source"
#define NM_OPENCONNECT_KEY_TOKEN_SECRET "stoken_string"
#define NM_OPENCONNECT_KEY_REPORTED_OS "reported_os"
#define NM_OPENCONNECT_KEY_MCACERT "mcacert"
#define NM_OPENCONNECT_KEY_MCAKEY "mcakey"
#define NM_OPENCONNECT_KEY_MCA_PASS "mca_key_pass"
#define NM_OPENCONNECT_KEY_ENTRA_CA "entra_conditional_access"
#define NM_OPENCONNECT_KEY_ENTRA_CA_SSO_URL "entra_conditional_access_sso_url"
#define NM_OPENCONNECT_KEY_ENTRA_CA_AUTHORITY "entra_conditional_access_authority"
#define NM_OPENCONNECT_KEY_ENTRA_CA_CLIENT_ID "entra_conditional_access_client_id"
#define NM_OPENCONNECT_KEY_ENTRA_CA_REDIRECT_URI "entra_conditional_access_redirect_uri"

#endif /* __NM_SERVICE_DEFINES_H__ */
