
#include <errno.h>
#include <string.h>

#include <talloc.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include <osmocom/abis/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>

#include "rspro_util.h"
#include "client.h"

static void push_and_send(struct ipa_client_conn *ipa, struct msgb *msg_tx)
{
	ipa_prepend_header_ext(msg_tx, IPAC_PROTO_EXT_RSPRO);
	ipa_msg_push_header(msg_tx, IPAC_PROTO_OSMO);
	ipa_client_conn_send(ipa, msg_tx);
	/* msg_tx is now queued and will be freed. */
}

void ipa_client_conn_send_rspro(struct ipa_client_conn *ipa, RsproPDU_t *rspro)
{
	struct msgb *msg = rspro_enc_msg(rspro);
	OSMO_ASSERT(msg);
	push_and_send(ipa, msg);
}

static int bankd_handle_msg(struct bankd_client *bc, struct msgb *msg)
{
	RsproPDU_t *pdu = rspro_dec_msg(msg);
	if (!pdu) {
		fprintf(stderr, "Error decoding PDU\n");
		return -1;
	}

	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectClientRes:
		break;
	default:
		fprintf(stderr, "Unknown/Unsuppoerted RSPRO PDU: %s\n", msgb_hexdump(msg));
		return -1;
	}

	return 0;
}

int bankd_read_cb(struct ipa_client_conn *conn, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct bankd_client *bc = conn->data;
	int rc;

	if (msgb_length(msg) < sizeof(*hh))
		goto invalid;
	msg->l2h = &hh->data[0];
	if (hh->proto != IPAC_PROTO_OSMO)
		goto invalid;
	if (!he || msgb_l2len(msg) < sizeof(*he))
		goto invalid;
	msg->l2h = &he->data[0];

	if (he->proto != IPAC_PROTO_EXT_RSPRO)
		goto invalid;

	printf("Received RSPRO %s\n", msgb_hexdump(msg));

	rc = bankd_handle_msg(bc, msg);
	msgb_free(msg);

	return rc;

invalid:
	msgb_free(msg);
	return -1;
}

static const struct log_info_cat default_categories[] = {
	[DMAIN] = {
		.name = "DMAIN",
		.loglevel = LOGL_DEBUG,
		.enabled = 1,
	},
};

static const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

static struct bankd_client *g_client;
static void *g_tall_ctx;
void __thread *talloc_asn1_ctx;
extern int asn_debug;

int main(int argc, char **argv)
{
	g_tall_ctx = talloc_named_const(NULL, 0, "global");

	osmo_fsm_register(&remsim_client_bankd_fsm);
	osmo_fsm_register(&remsim_client_server_fsm);

	g_client = talloc_zero(g_tall_ctx, struct bankd_client);
	g_client->bankd_host = "localhost";
	g_client->bankd_port = 9999;
	g_client->own_comp_id.type = ComponentType_remsimClient;
	OSMO_STRLCPY_ARRAY(g_client->own_comp_id.name, "fixme-name");
	OSMO_STRLCPY_ARRAY(g_client->own_comp_id.software, "remsim-client");
	OSMO_STRLCPY_ARRAY(g_client->own_comp_id.sw_version, PACKAGE_VERSION);

	//asn_debug = 1;
	osmo_init_logging2(g_tall_ctx, &log_info);

	if (bankd_conn_fsm_alloc(g_client) < 0) {
		fprintf(stderr, "Unable to connect: %s\n", strerror(errno));
		exit(1);
	}

	while (1) {
		osmo_select_main(0);
	}
}
