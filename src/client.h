#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/rspro/RsproPDU.h>

#include "rspro_util.h"
#include "debug.h"

/* fsm.c */

enum bankd_conn_fsm_event {
	BDC_E_ESTABLISH,	/* instruct BDC to (re)etablish TCP connection to bankd */
	BDC_E_TCP_UP,		/* notify BDC that TCP connection is up/connected */
	BDC_E_TCP_DOWN,		/* notify BDC that TCP connection is down/disconnected */
	BDC_E_CLIENT_CONN_RES,	/* notify BDC that ClientConnectRes has been received */
};

extern struct osmo_fsm remsim_client_bankd_fsm;


enum server_conn_fsm_event {
	SRVC_E_TCP_UP,
	SRVC_E_TCP_DOWN,
	SRVC_E_KA_TIMEOUT,
	SRVC_E_CLIENT_CONN_RES,
};

struct rspro_server_conn;

/* representing a client-side connection to a RSPRO server */
struct rspro_server_conn {
	/* state */
	struct ipa_client_conn *conn;
	struct osmo_fsm_inst *fi;
	struct osmo_fsm_inst *keepalive_fi;
	int (*handle_rx)(struct rspro_server_conn *conn, const RsproPDU_t *pdu);
	/* IPA protocol identity */
	struct ipaccess_unit ipa_dev;

	/* our own component ID */
	struct app_comp_id own_comp_id;
	/* remote component ID */
	struct app_comp_id peer_comp_id;

	/* client id and slot number */
	ClientSlot_t *clslot;

	/* configuration */
	char *server_host;
	uint16_t server_port;
};

int server_conn_fsm_alloc(void *ctx, struct rspro_server_conn *srvc);
extern struct osmo_fsm remsim_client_server_fsm;

/* main.c */

struct bankd_client {
	/* connection to the remsim-server (control) */
	struct rspro_server_conn srv_conn;

	/* remote component ID */
	struct app_comp_id peer_comp_id;

	/* connection to the remsim-bankd */
	char *bankd_host;
	uint16_t bankd_port;
	struct ipa_client_conn *bankd_conn;
	struct osmo_fsm_inst *bankd_fi;
};

void ipa_client_conn_send_rspro(struct ipa_client_conn *ipa, RsproPDU_t *rspro);
int bankd_read_cb(struct ipa_client_conn *conn, struct msgb *msg);
int bankd_conn_fsm_alloc(struct bankd_client *bc);
