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
	default:
		OSMO_ASSERT(0);
	}
}

static void bdc_st_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bankd_client *bc = (struct bankd_client *) fi->priv;
	RsproPDU_t *pdu;

	/* FIXME: Send ClientConnReq */
	const ClientSlot_t clslot = { .clientId = 23, .slotNr = 1 };
	pdu = rspro_gen_ConnectClientReq(&bc->own_comp_id, &clslot);
	bankd_send_rspro(bc, pdu);
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
	default:
		OSMO_ASSERT(0);
	}
}

static int remsim_client_bankd_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	return 0;
}

static const struct osmo_fsm_state bankd_conn_fsm_states[] = {
	[BDC_ST_INIT] = {
		.name = "INIT",
		.in_event_mask = S(BDC_E_TCP_UP),
		.out_state_mask = S(BDC_ST_ESTABLISHED),
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
		.in_event_mask = S(BDC_E_TCP_UP),
		.out_state_mask = S(BDC_ST_ESTABLISHED),
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


static void srvc_st_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
}

static void srvc_st_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
}

static void srvc_st_connected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
}

static void srvc_st_reestablish(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
}

static int server_conn_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	return 0;
}

static const struct osmo_fsm_state server_conn_fsm_states[] = {
	[SRVC_ST_INIT] = {
		.name = "INIT",
		.in_event_mask = S(SRVC_E_TCP_UP),
		.out_state_mask = S(SRVC_ST_ESTABLISHED),
		.action = srvc_st_init,
	},
	[SRVC_ST_ESTABLISHED] = {
		.name = "ESTABLISHED",
		.in_event_mask = S(SRVC_E_TCP_DOWN) | S(SRVC_E_CLIENT_CONN_RES),
		.out_state_mask = S(SRVC_ST_CONNECTED) | S(SRVC_ST_REESTABLISH),
		.action = srvc_st_established,
	},
	[SRVC_ST_CONNECTED] = {
		.name = "CONNECTED",
		.in_event_mask = S(SRVC_E_TCP_DOWN),
		.out_state_mask = S(SRVC_ST_REESTABLISH),
		.action = srvc_st_connected,
	},
	[SRVC_ST_REESTABLISH] = {
		.name = "REESTABLISH",
		.in_event_mask = S(SRVC_E_TCP_UP),
		.out_state_mask = S(SRVC_ST_ESTABLISHED),
		.action = srvc_st_reestablish,
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

int server_conn_fsm_alloc(struct bankd_client *bc)
{
	struct osmo_fsm_inst *fi;

	fi = osmo_fsm_inst_alloc(&remsim_client_server_fsm, bc, bc, LOGL_DEBUG, "server");
	if (!fi)
		return -1;

	bc->srv_fi = fi;
	/* onenter of the initial state is not automatically executed by osmo_fsm :( */
	///srvc_st_init_onenter(fi, 0);
	return 0;
}
