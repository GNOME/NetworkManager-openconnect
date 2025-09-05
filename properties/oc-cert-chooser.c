/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Certificate / private key chooser built on libadwaita widgets.
 * Replacement for NmaCertChooser, which is not ported to GTK4/libadwaita.
 */

#include "nm-default.h"

#include <glib/gi18n-lib.h>

#include "oc-cert-chooser.h"
#include "oc-pkcs11.h"

typedef struct {
	AdwActionRow *row;
	GtkWidget    *clear_button;
	gboolean      is_key;
	char         *value;
} ChooserRow;

struct _OcCertChooser {
	AdwPreferencesGroup parent;

	ChooserRow cert;
	ChooserRow key;
	gboolean   show_key;
};

enum {
	PROP_0,
	PROP_SHOW_KEY,
	N_PROPS
};

enum {
	CHANGED,
	N_SIGNALS
};

static GParamSpec *properties[N_PROPS];
static guint signals[N_SIGNALS];

G_DEFINE_TYPE (OcCertChooser, oc_cert_chooser, ADW_TYPE_PREFERENCES_GROUP)

static void
chooser_row_update (ChooserRow *cr)
{
	char *basename = NULL;
	const char *text;

	if (cr->value && g_str_has_prefix (cr->value, "pkcs11:"))
		text = cr->value;
	else if (cr->value && *cr->value) {
		basename = g_path_get_basename (cr->value);
		text = basename;
	} else
		text = _("(None)");

	adw_action_row_set_subtitle (cr->row, text);
	gtk_widget_set_tooltip_text (GTK_WIDGET (cr->row), cr->value);
	gtk_widget_set_sensitive (cr->clear_button, cr->value && *cr->value);
	g_free (basename);
}

static void
chooser_row_set (OcCertChooser *self, ChooserRow *cr, const char *value)
{
	if (!value || !*value)
		value = NULL;

	if (g_strcmp0 (cr->value, value) == 0)
		return;

	g_free (cr->value);
	cr->value = g_strdup (value);
	chooser_row_update (cr);
	g_signal_emit (self, signals[CHANGED], 0);
}

static void
file_dialog_open_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	OcCertChooser *self = OC_CERT_CHOOSER (user_data);
	GFile *file;
	char *path;
	ChooserRow *cr;

	file = gtk_file_dialog_open_finish (GTK_FILE_DIALOG (source), result, NULL);
	if (file) {
		path = g_file_get_path (file);
		cr = GPOINTER_TO_INT (g_object_get_data (source, "oc-is-key")) ? &self->key : &self->cert;
		chooser_row_set (self, cr, path);
		g_free (path);
		g_object_unref (file);
	}
	g_object_unref (self);
}

static void
add_filter (GListStore *filters, const char *name, const char * const *patterns)
{
	GtkFileFilter *filter = gtk_file_filter_new ();
	int i;

	gtk_file_filter_set_name (filter, name);
	for (i = 0; patterns[i]; i++)
		gtk_file_filter_add_pattern (filter, patterns[i]);
	g_list_store_append (filters, filter);
	g_object_unref (filter);
}

static void
choose_clicked_cb (GtkButton *button, gpointer user_data)
{
	OcCertChooser *self = OC_CERT_CHOOSER (user_data);
	gboolean is_key = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (button), "oc-is-key"));
	ChooserRow *cr = is_key ? &self->key : &self->cert;
	static const char * const cert_patterns[] = { "*.pem", "*.PEM", "*.crt", "*.CRT", "*.cer", "*.CER", "*.der", "*.DER", NULL };
	static const char * const key_patterns[] = { "*.pem", "*.PEM", "*.key", "*.KEY", "*.der", "*.DER", "*.p12", "*.P12", "*.pfx", "*.PFX", NULL };
	static const char * const all_patterns[] = { "*", NULL };
	GtkFileDialog *dialog;
	GListStore *filters;
	GtkRoot *root;
	GtkWindow *parent = NULL;

	dialog = gtk_file_dialog_new ();
	gtk_file_dialog_set_title (dialog, is_key ? _("Choose a private key") : _("Choose a certificate"));
	gtk_file_dialog_set_modal (dialog, TRUE);

	filters = g_list_store_new (GTK_TYPE_FILE_FILTER);
	if (is_key)
		add_filter (filters, _("Private keys (*.pem, *.key, *.der, *.p12, *.pfx)"), key_patterns);
	else
		add_filter (filters, _("Certificates (*.pem, *.crt, *.cer, *.der)"), cert_patterns);
	add_filter (filters, _("All files"), all_patterns);
	gtk_file_dialog_set_filters (dialog, G_LIST_MODEL (filters));
	g_object_unref (filters);

	if (cr->value && g_path_is_absolute (cr->value)) {
		GFile *file = g_file_new_for_path (cr->value);

		gtk_file_dialog_set_initial_file (dialog, file);
		g_object_unref (file);
	}

	root = gtk_widget_get_root (GTK_WIDGET (self));
	if (root && GTK_IS_WINDOW (root))
		parent = GTK_WINDOW (root);

	g_object_set_data (G_OBJECT (dialog), "oc-is-key", GINT_TO_POINTER (is_key));
	gtk_file_dialog_open (dialog, parent, NULL, file_dialog_open_cb, g_object_ref (self));
	g_object_unref (dialog);
}

static void
clear_clicked_cb (GtkButton *button, gpointer user_data)
{
	OcCertChooser *self = OC_CERT_CHOOSER (user_data);
	gboolean is_key = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (button), "oc-is-key"));

	chooser_row_set (self, is_key ? &self->key : &self->cert, NULL);
}

typedef struct {
	OcCertChooser *chooser;
	gboolean       is_key;
	AdwDialog     *dialog;
	GtkWidget     *stack;
	GtkWidget     *list;
	GCancellable  *cancellable;
	int            refcount; /* held by the dialog and by the pending listing */
} SmartcardDialog;

static void
smartcard_dialog_free (SmartcardDialog *sd)
{
	if (!g_atomic_int_dec_and_test (&sd->refcount))
		return;
	g_object_unref (sd->cancellable);
	g_object_unref (sd->chooser);
	g_free (sd);
}

static void
smartcard_row_activated_cb (GtkListBox *list, GtkListBoxRow *row, gpointer user_data)
{
	SmartcardDialog *sd = user_data;
	OcPkcs11Cert *cert = g_object_get_data (G_OBJECT (row), "oc-pkcs11-cert");

	if (!cert)
		return;

	if (sd->is_key)
		chooser_row_set (sd->chooser, &sd->chooser->key, cert->key_uri);
	else {
		chooser_row_set (sd->chooser, &sd->chooser->cert, cert->cert_uri);
		if (sd->chooser->show_key)
			chooser_row_set (sd->chooser, &sd->chooser->key, cert->key_uri);
	}
	adw_dialog_close (sd->dialog);
}

static void
smartcard_list_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	SmartcardDialog *sd = user_data;
	GError *error = NULL;
	GPtrArray *certs;
	guint i;

	certs = oc_pkcs11_list_certs_finish (result, &error);
	if (g_cancellable_is_cancelled (sd->cancellable)) {
		/* Dialog is gone; its widgets must not be touched */
		g_clear_error (&error);
		if (certs)
			g_ptr_array_unref (certs);
		smartcard_dialog_free (sd);
		return;
	}

	if (!certs || certs->len == 0) {
		g_clear_error (&error);
		gtk_stack_set_visible_child_name (GTK_STACK (sd->stack), "empty");
	} else {
		for (i = 0; i < certs->len; i++) {
			OcPkcs11Cert *cert = g_ptr_array_index (certs, i);
			GtkWidget *row = adw_action_row_new ();

			adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row), cert->label);
			adw_action_row_set_subtitle (ADW_ACTION_ROW (row), cert->token_label);
			gtk_list_box_row_set_activatable (GTK_LIST_BOX_ROW (row), TRUE);
			g_object_set_data_full (G_OBJECT (row), "oc-pkcs11-cert", cert, (GDestroyNotify) oc_pkcs11_cert_free);
			gtk_list_box_append (GTK_LIST_BOX (sd->list), row);
		}
		/* Rows now own the entries */
		g_ptr_array_set_free_func (certs, NULL);
		gtk_stack_set_visible_child_name (GTK_STACK (sd->stack), "list");
	}
	if (certs)
		g_ptr_array_unref (certs);
	smartcard_dialog_free (sd);
}

static void
smartcard_dialog_closed_cb (AdwDialog *dialog, gpointer user_data)
{
	SmartcardDialog *sd = user_data;

	g_cancellable_cancel (sd->cancellable);
	smartcard_dialog_free (sd);
}

static void
smartcard_clicked_cb (GtkButton *button, gpointer user_data)
{
	OcCertChooser *self = OC_CERT_CHOOSER (user_data);
	SmartcardDialog *sd = g_new0 (SmartcardDialog, 1);
	GtkWidget *view, *header, *scrolled, *spinner, *empty;

	sd->refcount = 2;
	sd->chooser = g_object_ref (self);
	sd->is_key = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (button), "oc-is-key"));
	sd->cancellable = g_cancellable_new ();

	sd->dialog = ADW_DIALOG (adw_dialog_new ());
	adw_dialog_set_title (sd->dialog, _("Smartcard Certificates"));
	adw_dialog_set_content_width (sd->dialog, 480);
	adw_dialog_set_content_height (sd->dialog, 360);

	sd->stack = gtk_stack_new ();
	spinner = adw_spinner_new ();
	gtk_widget_set_halign (spinner, GTK_ALIGN_CENTER);
	gtk_widget_set_valign (spinner, GTK_ALIGN_CENTER);
	gtk_widget_set_size_request (spinner, 32, 32);
	gtk_stack_add_named (GTK_STACK (sd->stack), spinner, "loading");

	empty = adw_status_page_new ();
	adw_status_page_set_icon_name (ADW_STATUS_PAGE (empty), "auth-smartcard-symbolic");
	adw_status_page_set_title (ADW_STATUS_PAGE (empty), _("No Certificates Found"));
	adw_status_page_set_description (ADW_STATUS_PAGE (empty), _("Insert a smartcard or token and try again."));
	gtk_stack_add_named (GTK_STACK (sd->stack), empty, "empty");

	sd->list = gtk_list_box_new ();
	gtk_list_box_set_selection_mode (GTK_LIST_BOX (sd->list), GTK_SELECTION_NONE);
	gtk_widget_add_css_class (sd->list, "boxed-list");
	gtk_widget_set_margin_top (sd->list, 12);
	gtk_widget_set_margin_bottom (sd->list, 12);
	gtk_widget_set_margin_start (sd->list, 12);
	gtk_widget_set_margin_end (sd->list, 12);
	gtk_widget_set_valign (sd->list, GTK_ALIGN_START);
	g_signal_connect (sd->list, "row-activated", G_CALLBACK (smartcard_row_activated_cb), sd);
	scrolled = gtk_scrolled_window_new ();
	gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scrolled), sd->list);
	gtk_stack_add_named (GTK_STACK (sd->stack), scrolled, "list");

	gtk_stack_set_visible_child_name (GTK_STACK (sd->stack), "loading");

	view = adw_toolbar_view_new ();
	header = adw_header_bar_new ();
	adw_toolbar_view_add_top_bar (ADW_TOOLBAR_VIEW (view), header);
	adw_toolbar_view_set_content (ADW_TOOLBAR_VIEW (view), sd->stack);
	adw_dialog_set_child (sd->dialog, view);

	g_signal_connect (sd->dialog, "closed", G_CALLBACK (smartcard_dialog_closed_cb), sd);
	adw_dialog_present (sd->dialog, GTK_WIDGET (self));
	oc_pkcs11_list_certs_async (sd->cancellable, smartcard_list_cb, sd);
}

static void
chooser_row_init (OcCertChooser *self, ChooserRow *cr, const char *title, gboolean is_key)
{
	GtkWidget *choose, *smartcard;

	cr->is_key = is_key;
	cr->row = ADW_ACTION_ROW (adw_action_row_new ());
	adw_preferences_row_set_title (ADW_PREFERENCES_ROW (cr->row), title);

	choose = gtk_button_new_from_icon_name ("document-open-symbolic");
	gtk_widget_set_valign (choose, GTK_ALIGN_CENTER);
	gtk_widget_set_tooltip_text (choose, _("Choose…"));
	gtk_widget_add_css_class (choose, "flat");
	g_object_set_data (G_OBJECT (choose), "oc-is-key", GINT_TO_POINTER (is_key));
	g_signal_connect (choose, "clicked", G_CALLBACK (choose_clicked_cb), self);

	cr->clear_button = gtk_button_new_from_icon_name ("edit-clear-symbolic");
	gtk_widget_set_valign (cr->clear_button, GTK_ALIGN_CENTER);
	gtk_widget_set_tooltip_text (cr->clear_button, _("Clear"));
	gtk_widget_add_css_class (cr->clear_button, "flat");
	g_object_set_data (G_OBJECT (cr->clear_button), "oc-is-key", GINT_TO_POINTER (is_key));
	g_signal_connect (cr->clear_button, "clicked", G_CALLBACK (clear_clicked_cb), self);

	smartcard = gtk_button_new_from_icon_name ("auth-smartcard-symbolic");
	gtk_widget_set_valign (smartcard, GTK_ALIGN_CENTER);
	gtk_widget_set_tooltip_text (smartcard, _("Choose from smartcard…"));
	gtk_widget_add_css_class (smartcard, "flat");
	g_object_set_data (G_OBJECT (smartcard), "oc-is-key", GINT_TO_POINTER (is_key));
	g_signal_connect (smartcard, "clicked", G_CALLBACK (smartcard_clicked_cb), self);

	adw_action_row_add_suffix (cr->row, cr->clear_button);
	adw_action_row_add_suffix (cr->row, smartcard);
	adw_action_row_add_suffix (cr->row, choose);
	adw_action_row_set_activatable_widget (cr->row, choose);
	chooser_row_update (cr);
}

static void
oc_cert_chooser_init (OcCertChooser *self)
{
	chooser_row_init (self, &self->cert, _("Certificate"), FALSE);
	adw_preferences_group_add (ADW_PREFERENCES_GROUP (self), GTK_WIDGET (self->cert.row));

	chooser_row_init (self, &self->key, _("Private Key"), TRUE);
	adw_preferences_group_add (ADW_PREFERENCES_GROUP (self), GTK_WIDGET (self->key.row));
	gtk_widget_set_visible (GTK_WIDGET (self->key.row), FALSE);
}

static void
oc_cert_chooser_finalize (GObject *object)
{
	OcCertChooser *self = OC_CERT_CHOOSER (object);

	g_free (self->cert.value);
	g_free (self->key.value);
	G_OBJECT_CLASS (oc_cert_chooser_parent_class)->finalize (object);
}

static void
oc_cert_chooser_set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	OcCertChooser *self = OC_CERT_CHOOSER (object);

	switch (prop_id) {
	case PROP_SHOW_KEY:
		self->show_key = g_value_get_boolean (value);
		gtk_widget_set_visible (GTK_WIDGET (self->key.row), self->show_key);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
	}
}

static void
oc_cert_chooser_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	OcCertChooser *self = OC_CERT_CHOOSER (object);

	switch (prop_id) {
	case PROP_SHOW_KEY:
		g_value_set_boolean (value, self->show_key);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
	}
}

static void
oc_cert_chooser_class_init (OcCertChooserClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = oc_cert_chooser_finalize;
	object_class->set_property = oc_cert_chooser_set_property;
	object_class->get_property = oc_cert_chooser_get_property;

	properties[PROP_SHOW_KEY] =
		g_param_spec_boolean ("show-key", NULL, NULL, FALSE,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS);
	g_object_class_install_properties (object_class, N_PROPS, properties);

	signals[CHANGED] = g_signal_new ("changed",
	                                 G_TYPE_FROM_CLASS (klass),
	                                 G_SIGNAL_RUN_LAST,
	                                 0, NULL, NULL, NULL,
	                                 G_TYPE_NONE, 0);
}

GtkWidget *
oc_cert_chooser_new (const char *title, gboolean show_key)
{
	return g_object_new (OC_TYPE_CERT_CHOOSER,
	                     "title", title,
	                     "show-key", show_key,
	                     NULL);
}

void
oc_cert_chooser_set_cert (OcCertChooser *self, const char *value)
{
	g_return_if_fail (OC_IS_CERT_CHOOSER (self));
	chooser_row_set (self, &self->cert, value);
}

const char *
oc_cert_chooser_get_cert (OcCertChooser *self)
{
	g_return_val_if_fail (OC_IS_CERT_CHOOSER (self), NULL);
	return self->cert.value;
}

void
oc_cert_chooser_set_key (OcCertChooser *self, const char *value)
{
	g_return_if_fail (OC_IS_CERT_CHOOSER (self));
	chooser_row_set (self, &self->key, value);
}

const char *
oc_cert_chooser_get_key (OcCertChooser *self)
{
	g_return_val_if_fail (OC_IS_CERT_CHOOSER (self), NULL);
	return self->key.value;
}
