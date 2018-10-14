#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <talloc.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/fsm.h>

#include <osmocom/abis/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>

#include "client.h"
#include "rspro_util.h"

#define S(x)	(1 << (x))

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

static void bankd_updown_cb(struct ipa_client_conn *conn, int up)
{
	struct bankd_client *bc = conn->data;

	printf("RSPRO link to %s:%d %s\n", conn->addr, conn->port, up ? "UP" : "DOWN");

	osmo_fsm_inst_dispatch(bc->bankd_fi, up ? BDC_E_TCP_UP: BDC_E_TCP_DOWN, 0);
}

/***********************************************************************
 * bankd connection FSM
 ***********************************************************************/

enum bankd_conn_fsm_state {
	/* waiting for initial connectiong to remsim-bankd */
	BDC_ST_INIT,
	/* bankd connection established, waiting for ClientConnectRes */
	BDC_ST_ESTABLISHED,
	/* bankd connection etsablished, ClientConnect succeeded */
	BDC_ST_CONNECTED,
	/* connection lost, we're waiting for a re-establish */
	BDC_ST_REESTABLISH,
};

static const struct value_string remsim_client_bankd_fsm_event_names[] = {
	OSMO_VALUE_STRING(BDC_E_TCP_UP),
	OSMO_VALUE_STRING(BDC_E_TCP_DOWN),
	OSMO_VALUE_STRING(BDC_E_CLIENT_CONN_RES),
	{ 0, NULL }
};

#define T1_WAIT_CLIENT_CONN_RES		10
#define T2_RECONNECT			10


static void bdc_st_init_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bankd_client *bc = (struct bankd_client *) fi->priv;
	int rc;

	printf("onenter\n");
	bc->bankd_conn = ipa_client_conn_create(bc, NULL, 0, bc->bankd_host, bc->bankd_port,
						bankd_updown_cb, bankd_read_cb, NULL, bc);
	if (!bc->bankd_conn) {
		fprintf(stderr, "Unable to create socket: %s\n", strerror(errno));
		exit(1);
	}
	/* Attempt to connect TCP socket */
	rc = ipa_client_conn_open(bc->bankd_conn);
	if (rc < 0) {
		fprintf(stderr, "Unable to connect: %s\n", strerror(errno));
		exit(1);
	}
}

static void bdc_st_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case BDC_E_TCP_UP:
		osmo_fsm_inst_state_chg(fi, BDC_ST_ESTABLISHED, T1_WAIT_CLIENT_CONN_RES, 1);
		break;
	case BDC_E_TCP_DOWN:
		osmo_fsm_inst_state_chg(fi, BDC_ST_REESTABLISH, T2_RECONNECT, 2);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void bdc_st_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bankd_client *bc = (struct bankd_client *) fi->priv;
	RsproPDU_t *pdu;

	/* FIXME: Send ClientConnReq */
	pdu = rspro_gen_ConnectClientReq(&bc->own_comp_id, bc->clslot);
	ipa_client_conn_send_rspro(bc->bankd_conn, pdu);
}

static void bdc_st_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case BDC_E_TCP_DOWN:
		osmo_fsm_inst_state_chg(fi, BDC_ST_REESTABLISH, T2_RECONNECT, 2);
		break;
	case BDC_E_CLIENT_CONN_RES:
		/* somehow notify the main code? */
		osmo_fsm_inst_state_chg(fi, BDC_ST_CONNECTED, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void bdc_st_connected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case BDC_E_TCP_DOWN:
		osmo_fsm_inst_state_chg(fi, BDC_ST_REESTABLISH, T2_RECONNECT, 2);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void bdc_st_reestablish_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bankd_client *bc = (struct bankd_client *) fi->priv;
	int rc;

	/* Attempt to connect TCP socket */
	rc = ipa_client_conn_open(bc->bankd_conn);
	if (rc < 0) {
		fprintf(stderr, "Unable to connect RSPRO to %s:%d - %s\n",
			bc->bankd_conn->addr, bc->bankd_conn->port, strerror(errno));
		/* FIXME: retry? Timer? Abort? */
		OSMO_ASSERT(0);
	}
}

static void bdc_st_reestablish(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case BDC_E_TCP_UP:
		osmo_fsm_inst_state_chg(fi, BDC_ST_ESTABLISHED, T1_WAIT_CLIENT_CONN_RES, 1);
		break;
	case BDC_E_TCP_DOWN:
		/* wait for normal T2 timeout */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int remsim_client_bankd_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->T) {
	case 2:
		osmo_fsm_inst_state_chg(fi, BDC_ST_REESTABLISH, T2_RECONNECT, 2);
		break;
	case 1:
		/* FIXME: close connection and re-start */
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static const struct osmo_fsm_state bankd_conn_fsm_states[] = {
	[BDC_ST_INIT] = {
		.name = "INIT",
		.in_event_mask = S(BDC_E_TCP_UP) | S(BDC_E_TCP_DOWN),
		.out_state_mask = S(BDC_ST_ESTABLISHED) | S(BDC_ST_REESTABLISH),
		.action = bdc_st_init,
	},
	[BDC_ST_ESTABLISHED] = {
		.name = "ESTABLISHED",
		.in_event_mask = S(BDC_E_TCP_DOWN) | S(BDC_E_CLIENT_CONN_RES),
		.out_state_mask = S(BDC_ST_CONNECTED) | S(BDC_ST_REESTABLISH),
		.action = bdc_st_established,
		.onenter = bdc_st_established_onenter,
	},
	[BDC_ST_CONNECTED] = {
		.name = "CONNECTED",
		.in_event_mask = S(BDC_E_TCP_DOWN),
		.out_state_mask = S(BDC_ST_REESTABLISH),
		.action = bdc_st_connected,
	},
	[BDC_ST_REESTABLISH] = {
		.name = "REESTABLISH",
		.in_event_mask = S(BDC_E_TCP_UP) | S(BDC_E_TCP_DOWN),
		.out_state_mask = S(BDC_ST_ESTABLISHED) | S(BDC_ST_REESTABLISH),
		.action = bdc_st_reestablish,
		.onenter = bdc_st_reestablish_onenter,
	},
};

struct osmo_fsm remsim_client_bankd_fsm = {
	.name = "BANKD_CONN",
	.states = bankd_conn_fsm_states,
	.num_states = ARRAY_SIZE(bankd_conn_fsm_states),
	.timer_cb = remsim_client_bankd_fsm_timer_cb,
	.log_subsys = DMAIN,
	.event_names = remsim_client_bankd_fsm_event_names,
};

int bankd_conn_fsm_alloc(struct bankd_client *bc)
{
	struct osmo_fsm_inst *fi;

	fi = osmo_fsm_inst_alloc(&remsim_client_bankd_fsm, bc, bc, LOGL_DEBUG, "bankd");
	if (!fi)
		return -1;

	bc->bankd_fi = fi;
	/* onenter of the initial state is not automatically executed by osmo_fsm :( */
	bdc_st_init_onenter(fi, 0);
	return 0;
}

/***********************************************************************
 * server connection FSM
 ***********************************************************************/

enum server_conn_fsm_state {
	/* waiting for initial connectiong to remsim-server */
	SRVC_ST_INIT,
	/* server connection established, waiting for ClientConnectRes */
	SRVC_ST_ESTABLISHED,
	/* server connection etsablished, ClientConnect succeeded */
	SRVC_ST_CONNECTED,
	/* connection lost, we're waiting for a re-establish */
	SRVC_ST_REESTABLISH,
};

static const struct value_string server_conn_fsm_event_names[] = {
	OSMO_VALUE_STRING(SRVC_E_TCP_UP),
	OSMO_VALUE_STRING(SRVC_E_TCP_DOWN),
	OSMO_VALUE_STRING(SRVC_E_CLIENT_CONN_RES),
	{ 0, NULL }
};

static void srvc_updown_cb(struct ipa_client_conn *conn, int up)
{
	struct rspro_server_conn *srvc = conn->data;

	printf("RSPRO link to %s:%d %s\n", conn->addr, conn->port, up ? "UP" : "DOWN");

	osmo_fsm_inst_dispatch(srvc->fi, up ? SRVC_E_TCP_UP: SRVC_E_TCP_DOWN, 0);
}

static int srvc_read_cb(struct ipa_client_conn *conn, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct rspro_server_conn *srvc = conn->data;
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
#if 0
	rc = bankd_handle_msg(srvc, msg);
	msgb_free(msg);

	return rc;
#endif

invalid:
	msgb_free(msg);
	return -1;
}


static void srvc_st_init_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;
	int rc;

	srvc->conn = ipa_client_conn_create(fi, NULL, 0, srvc->server_host, srvc->server_port,
						srvc_updown_cb, srvc_read_cb, NULL, srvc);
	if (!srvc->conn) {
		fprintf(stderr, "Unable to create socket: %s\n", strerror(errno));
		/* FIXME */
	}
	/* Attempt to connect TCP socket */
	rc = ipa_client_conn_open(srvc->conn);
	if (rc < 0) {
		fprintf(stderr, "Unable to connect: %s\n", strerror(errno));
		/* FIXME */
	}
}

static void srvc_st_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SRVC_E_TCP_UP:
		osmo_fsm_inst_state_chg(fi, SRVC_ST_ESTABLISHED, T1_WAIT_CLIENT_CONN_RES, 1);
		break;
	case SRVC_E_TCP_DOWN:
		osmo_fsm_inst_state_chg(fi, SRVC_ST_REESTABLISH, T2_RECONNECT, 2);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void srvc_st_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;
	RsproPDU_t *pdu;

	/* FIXME: Bankd in case of Bankd connection! */
	pdu = rspro_gen_ConnectClientReq(&srvc->own_comp_id, NULL);
	ipa_client_conn_send_rspro(srvc->conn, pdu);
}

static void srvc_st_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SRVC_E_TCP_DOWN:
		osmo_fsm_inst_state_chg(fi, SRVC_ST_REESTABLISH, T2_RECONNECT, 2);
		break;
	case SRVC_E_CLIENT_CONN_RES:
		/* somehow notify the main code? */
		osmo_fsm_inst_state_chg(fi, SRVC_ST_CONNECTED, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void srvc_st_connected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SRVC_E_TCP_DOWN:
		osmo_fsm_inst_state_chg(fi, SRVC_ST_REESTABLISH, T2_RECONNECT, 2);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void srvc_st_reestablish_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;
	int rc;

	/* Attempt to connect TCP socket */
	rc = ipa_client_conn_open(srvc->conn);
	if (rc < 0) {
		fprintf(stderr, "Unable to connect RSPRO to %s:%d - %s\n",
			srvc->server_host, srvc->server_port, strerror(errno));
		/* FIXME: retry? Timer? Abort? */
		OSMO_ASSERT(0);
	}
}

static void srvc_st_reestablish(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SRVC_E_TCP_UP:
		osmo_fsm_inst_state_chg(fi, SRVC_ST_ESTABLISHED, T1_WAIT_CLIENT_CONN_RES, 1);
		break;
	case SRVC_E_TCP_DOWN:
		/* wait for normal T2 call-back */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int server_conn_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->T) {
	case 2:
		osmo_fsm_inst_state_chg(fi, SRVC_ST_REESTABLISH, T2_RECONNECT, 2);
		break;
	case 1:
		/* FIXME: close connection and re-start connection attempt */
		break;
	default:
		OSMO_ASSERT(0);
	}

	return 0;
}

static const struct osmo_fsm_state server_conn_fsm_states[] = {
	[SRVC_ST_INIT] = {
		.name = "INIT",
		.in_event_mask = S(SRVC_E_TCP_UP) | S(SRVC_E_TCP_DOWN),
		.out_state_mask = S(SRVC_ST_ESTABLISHED) | S(SRVC_ST_REESTABLISH),
		.action = srvc_st_init,
		.onenter = srvc_st_init_onenter,
	},
	[SRVC_ST_ESTABLISHED] = {
		.name = "ESTABLISHED",
		.in_event_mask = S(SRVC_E_TCP_DOWN) | S(SRVC_E_CLIENT_CONN_RES),
		.out_state_mask = S(SRVC_ST_CONNECTED) | S(SRVC_ST_REESTABLISH),
		.action = srvc_st_established,
		.onenter = srvc_st_established_onenter,
	},
	[SRVC_ST_CONNECTED] = {
		.name = "CONNECTED",
		.in_event_mask = S(SRVC_E_TCP_DOWN),
		.out_state_mask = S(SRVC_ST_REESTABLISH),
		.action = srvc_st_connected,
	},
	[SRVC_ST_REESTABLISH] = {
		.name = "REESTABLISH",
		.in_event_mask = S(SRVC_E_TCP_UP) | S(SRVC_E_TCP_DOWN),
		.out_state_mask = S(SRVC_ST_ESTABLISHED) | S(SRVC_ST_REESTABLISH),
		.action = srvc_st_reestablish,
		.onenter = srvc_st_reestablish_onenter,
	},
};

struct osmo_fsm remsim_client_server_fsm = {
	.name = "SERVER_CONN",
	.states = server_conn_fsm_states,
	.num_states = ARRAY_SIZE(server_conn_fsm_states),
	.timer_cb = server_conn_fsm_timer_cb,
	.log_subsys = DMAIN,
	.event_names = server_conn_fsm_event_names,
};

int server_conn_fsm_alloc(void *ctx, struct rspro_server_conn *srvc)
{
	struct osmo_fsm_inst *fi;

	fi = osmo_fsm_inst_alloc(&remsim_client_server_fsm, ctx, srvc, LOGL_DEBUG, "server");
	if (!fi)
		return -1;

	srvc->fi = fi;
	/* onenter of the initial state is not automatically executed by osmo_fsm :( */
	srvc_st_init_onenter(fi, 0);
	return 0;
}
