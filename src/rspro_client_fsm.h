#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/netif/stream.h>
#include <osmocom/rspro/RsproPDU.h>

#include "rspro_util.h"

enum server_conn_fsm_event {
	SRVC_E_ESTABLISH,	/* instruct SRVC to (re)etablish TCP connection to bankd */
	SRVC_E_DISCONNECT,	/* instruct SRVC to disconnect TCP connection to bankd */
	SRVC_E_TCP_UP,
	SRVC_E_TCP_DOWN,
	SRVC_E_KA_TIMEOUT,
	SRVC_E_KA_TERMINATED,
	SRVC_E_CLIENT_CONN_RES,
	SRVC_E_RSPRO_TX		/* transmit a RSPRO PDU to the peer */
};

/* representing a client-side connection to a RSPRO server */
struct rspro_server_conn {
	/* state */
	struct osmo_stream_cli *conn;
	struct osmo_fsm_inst *fi;
	struct osmo_fsm_inst *keepalive_fi;
	int (*handle_rx)(struct rspro_server_conn *conn, const RsproPDU_t *pdu);

	/* index into k_reestablish_delay[] for this connection */
	size_t reestablish_delay_idx;

	/* timestamp of last re-establish attempt, in milliseconds */
	int64_t reestablish_last_ms;

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

	/* FSM events we are to sent to the parent FSM on connect / disconnect */
	uint32_t parent_conn_evt;
	uint32_t parent_disc_evt;

	/* only in case we are representing a bankd client */
	struct {
		uint16_t bank_id;
		uint16_t num_slots;
	} bankd;
};

int server_conn_send_rspro(struct rspro_server_conn *srvc, RsproPDU_t *rspro);
int server_conn_fsm_alloc(void *ctx, struct rspro_server_conn *srvc);
