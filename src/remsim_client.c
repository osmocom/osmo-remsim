
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

struct bankd_client {
	/* connection to the remsim-server (control) */
	struct ipa_client_conn *srv_conn;

	/* our own component ID */
	struct app_comp_id own_comp_id;

	/* connection to the remsim-bankd */
	char *bankd_host;
	uint16_t bankd_port;
	struct ipa_client_conn *bankd_conn;
};


static void bankd_send(struct bankd_client *bc, struct msgb *msg_tx)
{
	ipa_prepend_header_ext(msg_tx, IPAC_PROTO_EXT_RSPRO);
	ipa_msg_push_header(msg_tx, IPAC_PROTO_OSMO);
	ipa_client_conn_send(bc->bankd_conn, msg_tx);
	/* msg_tx is now queued and will be freed. */
}

static void bankd_send_rspro(struct bankd_client *bc, RsproPDU_t *rspro)
{
	struct msgb *msg = rspro_enc_msg(rspro);
	OSMO_ASSERT(msg);
	bankd_send(bc, msg);
}












static void bankd_updown_cb(struct ipa_client_conn *conn, int up)
{
	struct bankd_client *bc = conn->data;

	printf("RSPRO link to %s:%d %s\n", conn->addr, conn->port, up ? "UP" : "DOWN");
	if (!up)
		exit(3);
	else {
		const ClientSlot_t clslot = { .clientId = 23, .slotNr = 1 };
		RsproPDU_t *pdu = rspro_gen_ConnectClientReq(&bc->own_comp_id, &clslot);
		bankd_send_rspro(bc, pdu);
	}
}

static int bankd_read_cb(struct ipa_client_conn *conn, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct bankd_client *bc = conn->data;

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

	/* FIXME: do something */
	printf("Received RSPRO %s\n", msgb_hexdump(msg));

	msgb_free(msg);
	return 0;

invalid:
	msgb_free(msg);
	return -1;
}

static const struct log_info_cat default_categories[] = {
};

static const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

static struct bankd_client g_client;
static void *g_tall_ctx;
void __thread *talloc_asn1_ctx;
extern int asn_debug;

int main(int argc, char **argv)
{
	int rc;

	g_tall_ctx = talloc_named_const(NULL, 0, "global");

	g_client.bankd_host = "localhost";
	g_client.bankd_port = 9999;
	g_client.own_comp_id.type = ComponentType_remsimClient;
	OSMO_STRLCPY_ARRAY(g_client.own_comp_id.name, "fixme-name");
	OSMO_STRLCPY_ARRAY(g_client.own_comp_id.software, "remsim-client");
	OSMO_STRLCPY_ARRAY(g_client.own_comp_id.sw_version, PACKAGE_VERSION);

	//asn_debug = 1;
	osmo_init_logging2(g_tall_ctx, &log_info);

	g_client.bankd_conn = ipa_client_conn_create(g_tall_ctx, NULL, 0,
						   g_client.bankd_host, g_client.bankd_port,
						   bankd_updown_cb, bankd_read_cb,
						   NULL, &g_client);
	if (!g_client.bankd_conn) {
		fprintf(stderr, "Unable to connect: %s\n", strerror(errno));
		exit(1);
	}
	rc = ipa_client_conn_open(g_client.bankd_conn);
	if (rc < 0) {
		fprintf(stderr, "Unable to connect RSPRO to %s:%d - %s\n",
			g_client.bankd_conn->addr, g_client.bankd_conn->port, strerror(errno));
		return 0;
	}

	while (1) {
		osmo_select_main(0);
	}
}
