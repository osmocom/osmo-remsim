
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
#include "debug.h"

static int bankd_handle_msg(struct bankd_client *bc, struct msgb *msg)
{
	RsproPDU_t *pdu = rspro_dec_msg(msg);
	if (!pdu) {
		fprintf(stderr, "Error decoding PDU\n");
		return -1;
	}

	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectClientRes:
		/* Store 'identity' of bankd to in peer_comp_id */
		rspro_comp_id_retrieve(&bc->peer_comp_id, &pdu->msg.choice.connectClientRes.identity);
		osmo_fsm_inst_dispatch(bc->bankd_fi, BDC_E_CLIENT_CONN_RES, pdu);
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
	switch (hh->proto) {
	case IPAC_PROTO_OSMO:
		if (!he || msgb_l2len(msg) < sizeof(*he))
			goto invalid;
		msg->l2h = &he->data[0];
		switch (he->proto) {
		case IPAC_PROTO_EXT_RSPRO:
			printf("Received RSPRO %s\n", msgb_hexdump(msg));
			rc = bankd_handle_msg(bc, msg);
			break;
		default:
			goto invalid;
		}
		break;
	default:
		goto invalid;
	}

	return rc;

invalid:
	msgb_free(msg);
	return -1;
}

static struct bankd_client *g_client;
static void *g_tall_ctx;
void __thread *talloc_asn1_ctx;
int asn_debug;

/* handle incoming messages from server */
static int srvc_handle_rx(struct rspro_server_conn *srvc, const RsproPDU_t *pdu)
{
	RsproPDU_t  *resp;

	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectClientRes:
		/* Store 'identity' of server in srvc->peer_comp_id */
		rspro_comp_id_retrieve(&srvc->peer_comp_id, &pdu->msg.choice.connectClientRes.identity);
		osmo_fsm_inst_dispatch(srvc->fi, SRVC_E_CLIENT_CONN_RES, (void *) pdu);
		break;
	case RsproPDUchoice_PR_configClientReq:
		/* store/set the clientID as instructed by the server */
		if (!g_client->clslot)
			g_client->clslot = talloc_zero(g_client, ClientSlot_t);
		*g_client->clslot = pdu->msg.choice.configClientReq.clientSlot;
		/* store/set the bankd ip/port as instructed by the server */
		osmo_talloc_replace_string(g_client, &g_client->bankd_host,
					   rspro_IpAddr2str(&pdu->msg.choice.configClientReq.bankd.ip));
		g_client->bankd_port = ntohs(pdu->msg.choice.configClientReq.bankd.port);
		/* instruct bankd FSM to connect */
		osmo_fsm_inst_dispatch(g_client->bankd_fi, BDC_E_ESTABLISH, NULL);
		/* send response to server */
		resp = rspro_gen_ConfigClientRes(ResultCode_ok);
		ipa_client_conn_send_rspro(srvc->conn, resp);
		break;
	default:
		fprintf(stderr, "Unknown/Unsupported RSPRO PDU type: %u\n", pdu->msg.present);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct rspro_server_conn *srvc;
	int rc;

	g_tall_ctx = talloc_named_const(NULL, 0, "global");

	g_client = talloc_zero(g_tall_ctx, struct bankd_client);

	srvc = &g_client->srv_conn;
	srvc->server_host = "localhost";
	srvc->server_port = 9998;
	srvc->handle_rx = srvc_handle_rx;
	srvc->own_comp_id.type = ComponentType_remsimClient;
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.name, "fixme-name");
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.software, "remsim-client");
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.sw_version, PACKAGE_VERSION);
	rc = server_conn_fsm_alloc(g_client, srvc);
	if (rc < 0) {
		fprintf(stderr, "Unable to create Server conn FSM: %s\n", strerror(errno));
		exit(1);
	}

	asn_debug = 0;
	osmo_init_logging2(g_tall_ctx, &log_info);

	if (bankd_conn_fsm_alloc(g_client) < 0) {
		fprintf(stderr, "Unable to connect: %s\n", strerror(errno));
		exit(1);
	}

	while (1) {
		osmo_select_main(0);
	}
}
