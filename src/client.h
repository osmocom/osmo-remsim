#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/abis/ipa.h>

#include "rspro_util.h"

enum {
	DMAIN,
};

/* fsm.c */

enum bankd_conn_fsm_event {
	BDC_E_TCP_UP,
	BDC_E_TCP_DOWN,
	BDC_E_CLIENT_CONN_RES,
};


enum server_conn_fsm_event {
	SRVC_E_TCP_UP,
	SRVC_E_TCP_DOWN,
	SRVC_E_CLIENT_CONN_RES,
};

extern struct osmo_fsm remsim_client_bankd_fsm;
extern struct osmo_fsm remsim_client_server_fsm;

/* main.c */

struct bankd_client {
	/* connection to the remsim-server (control) */
	struct ipa_client_conn *srv_conn;
	struct osmo_fsm_inst *srv_fi;

	/* our own component ID */
	struct app_comp_id own_comp_id;

	/* connection to the remsim-bankd */
	char *bankd_host;
	uint16_t bankd_port;
	struct ipa_client_conn *bankd_conn;
	struct osmo_fsm_inst *bankd_fi;
};

void bankd_send_rspro(struct bankd_client *bc, RsproPDU_t *rspro);
int bankd_read_cb(struct ipa_client_conn *conn, struct msgb *msg);
int bankd_conn_fsm_alloc(struct bankd_client *bc);
