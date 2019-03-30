/* (C) 2018-2019 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */


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

#define T1_WAIT_CLIENT_CONN_RES		10
#define T2_RECONNECT			10

/***********************************************************************
 * server connection FSM: remsim-{client,bankd} to remsim-server
 ***********************************************************************/

static void push_and_send(struct ipa_client_conn *ipa, struct msgb *msg_tx)
{
	ipa_prepend_header_ext(msg_tx, IPAC_PROTO_EXT_RSPRO);
	ipa_msg_push_header(msg_tx, IPAC_PROTO_OSMO);
	ipa_client_conn_send(ipa, msg_tx);
	/* msg_tx is now queued and will be freed. */
}

int ipa_client_conn_send_rspro(struct ipa_client_conn *ipa, RsproPDU_t *rspro)
{
	struct msgb *msg = rspro_enc_msg(rspro);
	if (!msg) {
		ASN_STRUCT_FREE(asn_DEF_RsproPDU, rspro);
		return -1;
	}
	push_and_send(ipa, msg);
	return 0;
}

int server_conn_send_rspro(struct rspro_server_conn *srvc, RsproPDU_t *rspro)
{
	LOGPFSM(srvc->fi, "Tx RSPRO %s\n", rspro_msgt_name(rspro));
	return ipa_client_conn_send_rspro(srvc->conn, rspro);
}

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
	OSMO_VALUE_STRING(SRVC_E_KA_TIMEOUT),
	OSMO_VALUE_STRING(SRVC_E_CLIENT_CONN_RES),
	{ 0, NULL }
};

static void srvc_updown_cb(struct ipa_client_conn *conn, int up)
{
	struct rspro_server_conn *srvc = conn->data;

	LOGPFSM(srvc->fi, "RSPRO link to %s:%d %s\n", conn->addr, conn->port, up ? "UP" : "DOWN");

	osmo_fsm_inst_dispatch(srvc->fi, up ? SRVC_E_TCP_UP: SRVC_E_TCP_DOWN, 0);
}

static int srvc_read_cb(struct ipa_client_conn *conn, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct rspro_server_conn *srvc = conn->data;
	RsproPDU_t *pdu;
	int rc;

	if (msgb_length(msg) < sizeof(*hh))
		goto invalid;
	msg->l2h = &hh->data[0];
	switch (hh->proto) {
	case IPAC_PROTO_IPACCESS:
		rc = ipaccess_bts_handle_ccm(srvc->conn, &srvc->ipa_dev, msg);
		if (rc < 0)
			break;
		switch (hh->data[0]) {
		case IPAC_MSGT_PONG:
			ipa_keepalive_fsm_pong_received(srvc->keepalive_fi);
			rc = 0;
			break;
		default:
			break;
		}
		break;
	case IPAC_PROTO_OSMO:
		if (!he || msgb_l2len(msg) < sizeof(*he))
			goto invalid;
		msg->l2h = &he->data[0];
		switch (he->proto) {
		case IPAC_PROTO_EXT_RSPRO:
			LOGPFSM(srvc->fi, "Received RSPRO %s\n", msgb_hexdump(msg));
			pdu = rspro_dec_msg(msg);
			if (!pdu)
				goto invalid;
			rc = srvc->handle_rx(srvc, pdu);
			ASN_STRUCT_FREE(asn_DEF_RsproPDU, pdu);
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
	LOGPFSML(srvc->fi, LOGL_ERROR, "Error decoding PDU\n");
	msgb_free(msg);
	return -1;
}

static const struct ipa_keepalive_params ka_params = {
	.interval = 30,
	.wait_for_resp = 10,
};

static void srvc_st_init_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;
	int rc;

	srvc->conn = ipa_client_conn_create(fi, NULL, 0, srvc->server_host, srvc->server_port,
						srvc_updown_cb, srvc_read_cb, NULL, srvc);
	if (!srvc->conn) {
		LOGPFSM(fi, "Unable to create socket: %s\n", strerror(errno));
		goto out_fi;
	}

	srvc->keepalive_fi = ipa_client_conn_alloc_keepalive_fsm(srvc->conn, &ka_params, fi->id);
	if (!srvc->keepalive_fi) {
		LOGPFSM(fi, "Unable to create keepalive FSM\n");
		goto out_conn;
	}
	/* ensure parent is notified once keepalive FSM instance is dying */
	osmo_fsm_inst_change_parent(srvc->keepalive_fi, srvc->fi, SRVC_E_KA_TIMEOUT);

	/* Attempt to connect TCP socket */
	rc = ipa_client_conn_open(srvc->conn);
	if (rc < 0) {
		LOGPFSML(fi, LOGL_NOTICE, "Unable to connect: %s\n", strerror(errno));
		goto out_ka;
	}

	return;

out_ka:
	osmo_fsm_inst_term(srvc->keepalive_fi, OSMO_FSM_TERM_ERROR, NULL);
out_conn:
	ipa_client_conn_destroy(srvc->conn);
out_fi:
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
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

	ipa_keepalive_fsm_start(srvc->keepalive_fi);

	if (srvc->own_comp_id.type == ComponentType_remsimClient)
		pdu = rspro_gen_ConnectClientReq(&srvc->own_comp_id, srvc->clslot);
	else
		pdu = rspro_gen_ConnectBankReq(&srvc->own_comp_id, 1, 8 /* FIXME */);
	server_conn_send_rspro(srvc, pdu);
}

static void srvc_st_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;
	RsproPDU_t *pdu = NULL;
	e_ResultCode res;

	switch (event) {
	case SRVC_E_TCP_DOWN:
	case SRVC_E_KA_TIMEOUT:
		osmo_fsm_inst_state_chg(fi, SRVC_ST_REESTABLISH, T2_RECONNECT, 2);
		break;
	case SRVC_E_CLIENT_CONN_RES:
		pdu = data;
		res = rspro_get_result(pdu);
		if (res != ResultCode_ok) {
			ipa_client_conn_close(srvc->conn);
			osmo_fsm_inst_dispatch(fi, SRVC_E_TCP_DOWN, NULL);
		} else {
			/* somehow notify the main code? */
			osmo_fsm_inst_state_chg(fi, SRVC_ST_CONNECTED, 0, 0);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void srvc_st_connected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SRVC_E_TCP_DOWN:
	case SRVC_E_KA_TIMEOUT:
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

	ipa_keepalive_fsm_stop(srvc->keepalive_fi);

	/* Attempt to connect TCP socket */
	rc = ipa_client_conn_open(srvc->conn);
	if (rc < 0) {
		LOGPFSM(fi, "Unable to connect RSPRO to %s:%d - %s\n",
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
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;

	switch (fi->T) {
	case 2:
		osmo_fsm_inst_state_chg(fi, SRVC_ST_REESTABLISH, T2_RECONNECT, 2);
		break;
	case 1:
		/* FIXME: close connection and re-start connection attempt */
		ipa_client_conn_close(srvc->conn);
		osmo_fsm_inst_dispatch(fi, SRVC_E_TCP_DOWN, NULL);
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
		.in_event_mask = S(SRVC_E_TCP_DOWN) | S(SRVC_E_KA_TIMEOUT) | S(SRVC_E_CLIENT_CONN_RES),
		.out_state_mask = S(SRVC_ST_CONNECTED) | S(SRVC_ST_REESTABLISH),
		.action = srvc_st_established,
		.onenter = srvc_st_established_onenter,
	},
	[SRVC_ST_CONNECTED] = {
		.name = "CONNECTED",
		.in_event_mask = S(SRVC_E_TCP_DOWN) | S(SRVC_E_KA_TIMEOUT),
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

struct osmo_fsm rspro_client_server_fsm = {
	.name = "RSPRO_CLIENT",
	.states = server_conn_fsm_states,
	.num_states = ARRAY_SIZE(server_conn_fsm_states),
	.timer_cb = server_conn_fsm_timer_cb,
	.log_subsys = DMAIN,
	.event_names = server_conn_fsm_event_names,
};

int server_conn_fsm_alloc(void *ctx, struct rspro_server_conn *srvc)
{
	struct osmo_fsm_inst *fi;

	fi = osmo_fsm_inst_alloc(&rspro_client_server_fsm, ctx, srvc, LOGL_DEBUG, "server");
	if (!fi)
		return -1;

	srvc->fi = fi;
	/* onenter of the initial state is not automatically executed by osmo_fsm :( */
	srvc_st_init_onenter(fi, 0);
	return 0;
}

static __attribute__((constructor)) void on_dso_load(void)
{
	osmo_fsm_register(&rspro_client_server_fsm);
}
