#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/rspro/RsproPDU.h>

#include "rspro_util.h"
#include "rspro_client_fsm.h"
#include "debug.h"

/* fsm.c */

enum bankd_conn_fsm_event {
	BDC_E_ESTABLISH,	/* instruct BDC to (re)etablish TCP connection to bankd */
	BDC_E_TCP_UP,		/* notify BDC that TCP connection is up/connected */
	BDC_E_TCP_DOWN,		/* notify BDC that TCP connection is down/disconnected */
	BDC_E_CLIENT_CONN_RES,	/* notify BDC that ClientConnectRes has been received */
};

extern struct osmo_fsm remsim_client_bankd_fsm;


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

int bankd_conn_send_rspro(struct bankd_client *bc, RsproPDU_t *pdu);
int bankd_read_cb(struct ipa_client_conn *conn, struct msgb *msg);
int bankd_conn_fsm_alloc(struct bankd_client *bc);
