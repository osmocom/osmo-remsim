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
 */


#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <talloc.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>

#include "debug.h"
#include "asn1c_helpers.h"
#include "rspro_client_fsm.h"

#define S(x)	(1 << (x))

#define T1_WAIT_CLIENT_CONN_RES		10
#define T2_RECONNECT			10

static const int k_reestablish_delay_s[] = {
	0, 0, 0,                            // 3 immediate retries
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1,       // 1 Hz for 30 seconds
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,       // 1/2 hz for 1 minute
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4,       // 1/4 Hz for 2 minutes
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8,       // 1/8 Hz for 4 minutes
	16,                                 // 1/16 Hz thereafter
};

#define REESTABLISH_DELAY_COUNT ARRAY_SIZE(k_reestablish_delay_s)

/***********************************************************************
 * client-side FSM for a RSPRO connection to remsim-server
 *
 * This implements the TCP/IPA client side of an RSPRO connection between
 * a logical (TCP-level) client implementation and a remote RSPRO server.
 *
 * 'client' and 'server' here strictly refer to RSPRO protocol roles, not
 * to be confused with the remsim-client or remsim-server!
 *
 * Specifically, this RSPRO client FSM is used by both remsim-client and
 * remsim-bankd for their RSPRO control connection to remsim-server.
 ***********************************************************************/

static void push_and_send(struct osmo_stream_cli *cli, struct msgb *msg_tx)
{
	ipa_prepend_header_ext(msg_tx, IPAC_PROTO_EXT_RSPRO);
	ipa_prepend_header(msg_tx, IPAC_PROTO_OSMO);
	osmo_stream_cli_send(cli, msg_tx);
	/* msg_tx is now queued and will be freed. */
}

static int cli_conn_send_rspro(struct osmo_stream_cli *cli, RsproPDU_t *rspro)
{
	struct msgb *msg = rspro_enc_msg(rspro);
	if (!msg) {
		LOGP(DRSPRO, LOGL_ERROR, "Error encoding RSPRO: %s\n", rspro_msgt_name(rspro));
		osmo_log_backtrace(DRSPRO, LOGL_ERROR);
		ASN_STRUCT_FREE(asn_DEF_RsproPDU, rspro);
		return -1;
	}
	push_and_send(cli, msg);
	return 0;
}

static int _server_conn_send_rspro(struct rspro_server_conn *srvc, RsproPDU_t *rspro)
{
	LOGPFSML(srvc->fi, LOGL_DEBUG, "Tx RSPRO %s\n", rspro_msgt_name(rspro));
	return cli_conn_send_rspro(srvc->conn, rspro);
}

int server_conn_send_rspro(struct rspro_server_conn *srvc, RsproPDU_t *rspro)
{
	if (!rspro) {
		LOGPFSML(srvc->fi, LOGL_ERROR, "Attempt to transmit NULL\n");
		osmo_log_backtrace(DRSPRO, LOGL_ERROR);
		return -EINVAL;
	}
	if (osmo_fsm_inst_dispatch(srvc->fi, SRVC_E_RSPRO_TX, rspro) < 0) {
		ASN_STRUCT_FREE(asn_DEF_RsproPDU, rspro);
		return -EPERM;
	}
	return 0;
}

enum server_conn_fsm_state {
	/* waiting for initial connection to remsim-server */
	SRVC_ST_INIT,
	/* server connection established, waiting for ClientConnectRes */
	SRVC_ST_ESTABLISHED,
	/* server connection established, ClientConnect succeeded */
	SRVC_ST_CONNECTED,
	/* connection lost, 1st step: delaying until we re-establish */
	SRVC_ST_REESTABLISH_DELAY,
	/* connection lost, 2nd step: wait for a re-establish */
	SRVC_ST_REESTABLISH,
};

static const struct value_string server_conn_fsm_event_names[] = {
	OSMO_VALUE_STRING(SRVC_E_ESTABLISH),
	OSMO_VALUE_STRING(SRVC_E_DISCONNECT),
	OSMO_VALUE_STRING(SRVC_E_TCP_UP),
	OSMO_VALUE_STRING(SRVC_E_TCP_DOWN),
	OSMO_VALUE_STRING(SRVC_E_KA_TIMEOUT),
	OSMO_VALUE_STRING(SRVC_E_CLIENT_CONN_RES),
	OSMO_VALUE_STRING(SRVC_E_RSPRO_TX),
	{ 0, NULL }
};

static int srvc_connect_cb(struct osmo_stream_cli *cli)
{
	struct rspro_server_conn *srvc = osmo_stream_cli_get_data(cli);
	LOGPFSML(srvc->fi, LOGL_NOTICE, "RSPRO link to %s:%d UP\n", srvc->server_host, srvc->server_port);
	osmo_fsm_inst_dispatch(srvc->fi, SRVC_E_TCP_UP, 0);
	return 0;
}

static int srvc_disconnect_cb(struct osmo_stream_cli *cli)
{
	struct rspro_server_conn *srvc = osmo_stream_cli_get_data(cli);

	LOGPFSML(srvc->fi, LOGL_NOTICE, "RSPRO link to %s:%d DOWN\n", srvc->server_host, srvc->server_port);

	if (srvc->ka_fi) {
		osmo_ipa_ka_fsm_stop(srvc->ka_fi);
		osmo_ipa_ka_fsm_free(srvc->ka_fi);
		srvc->ka_fi = NULL;
	}

	osmo_fsm_inst_dispatch(srvc->fi, SRVC_E_TCP_DOWN, 0);
	return 0;
}

static struct msgb *ipa_bts_id_ack(void)
{
	struct msgb *nmsg2;
	nmsg2 = ipa_msg_alloc(0);
	if (!nmsg2)
		return NULL;
	msgb_v_put(nmsg2, IPAC_MSGT_ID_ACK);
	ipa_prepend_header(nmsg2, IPAC_PROTO_IPACCESS);
	return nmsg2;
}

static int _ipaccess_bts_handle_ccm(struct osmo_stream_cli *cli, struct rspro_server_conn *srvc, struct msgb *msg)
{
	/* special handling for IPA CCM. */
	if (osmo_ipa_msgb_cb_proto(msg) != IPAC_PROTO_IPACCESS)
		return 0;

	int ret = 0;
	const uint8_t *data = msgb_l2(msg);
	int len = msgb_l2len(msg);
	OSMO_ASSERT(len > 0);
	uint8_t msg_type = *data;

	/* ping, pong and acknowledgment cases. */
	struct osmo_fd tmp_ofd = { .fd = osmo_stream_cli_get_fd(cli) };
	OSMO_ASSERT(tmp_ofd.fd >= 0);
	ret = ipa_ccm_rcvmsg_bts_base(msg, &tmp_ofd);
	if (ret < 0)
		goto err;

	/* this is a request for identification from the BSC. */
	if (msg_type == IPAC_MSGT_ID_GET) {
		struct msgb *rmsg;
		LOGPFSML(srvc->fi, LOGL_NOTICE, "received ID_GET for unit ID %u/%u/%u\n",
			 srvc->ipa_dev.site_id, srvc->ipa_dev.bts_id, srvc->ipa_dev.trx_id);
		rmsg = ipa_ccm_make_id_resp_from_req(&srvc->ipa_dev, data + 1, len - 1);
		if (!rmsg) {
			LOGPFSML(srvc->fi, LOGL_ERROR, "Failed parsing ID_GET message.\n");
			goto err;
		}
		osmo_stream_cli_send(cli, rmsg);

		/* send ID_ACK. */
		rmsg = ipa_bts_id_ack();
		if (!rmsg) {
			LOGPFSML(srvc->fi, LOGL_ERROR, "Failed allocating ID_ACK message.\n");
			goto err;
		}
		osmo_stream_cli_send(cli, rmsg);
	}
	return 1;

err:
	return -1;
}

static int srvc_read_cb(struct osmo_stream_cli *cli, int res, struct msgb *msg)
{
	enum ipaccess_proto ipa_proto = osmo_ipa_msgb_cb_proto(msg);
	struct rspro_server_conn *srvc = osmo_stream_cli_get_data(cli);
	RsproPDU_t *pdu;
	int rc;

	if (res <= 0) {
		LOGPFSML(srvc->fi, LOGL_NOTICE, "failed reading from socket: %d\n", res);
		goto err;
	}

	switch (ipa_proto) {
	case IPAC_PROTO_IPACCESS:
		OSMO_ASSERT(msgb_l2len(msg) > 0);
		uint8_t msg_type = msg->l2h[0];
		rc = _ipaccess_bts_handle_ccm(srvc->conn, srvc, msg);
		if (rc < 0) {
			msgb_free(msg);
			break;
		}
		switch (msg_type) {
		case IPAC_MSGT_PONG:
			osmo_ipa_ka_fsm_pong_received(srvc->ka_fi);
			rc = 0;
			break;
		default:
			break;
		}
		break;
	case IPAC_PROTO_OSMO:
		switch (osmo_ipa_msgb_cb_proto_ext(msg)) {
		case IPAC_PROTO_EXT_RSPRO:
			LOGPFSML(srvc->fi, LOGL_DEBUG, "Received RSPRO %s\n", msgb_hexdump(msg));
			pdu = rspro_dec_msg(msg);
			if (!pdu) {
				rc = -EIO;
				break;
			}
			rc = srvc->handle_rx(srvc, pdu);
			ASN_STRUCT_FREE(asn_DEF_RsproPDU, pdu);
			break;
		default:
			goto err;
		}
		break;
	default:
		goto err;
	}

	msgb_free(msg);
	return rc;

err:
	msgb_free(msg);
	osmo_stream_cli_close(cli);
	return -EBADF;
}

static int64_t get_monotonic_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_BOOTTIME, &t);
	return ((1000LL * t.tv_sec) + (t.tv_nsec / 1000000));
}

static void srvc_do_reestablish(struct osmo_fsm_inst *fi)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;

	const int64_t since_last_ms = get_monotonic_ms() - srvc->reestablish_last_ms;

	/* reset delay loop if it has been > 2x the longest timeout since our last attempt;
	 * this lets us revert to rapid reconnect behavior for a good connection */
	const int64_t reset_ms = 2*1000*(OSMO_MAX(OSMO_MAX(T1_WAIT_CLIENT_CONN_RES, T2_RECONNECT),
		k_reestablish_delay_s[REESTABLISH_DELAY_COUNT-1]));

	if (since_last_ms > reset_ms) {
		srvc->reestablish_delay_idx = 0;
		LOGPFSML(fi, LOGL_DEBUG, "->REESTABLISH_DELAY reset; %" PRId64 "ms since last attempt\n",
			since_last_ms);
	}

	/* determine if we need to delay reestablishment */
	const int64_t need_ms = (int64_t) k_reestablish_delay_s[srvc->reestablish_delay_idx] * 1000;
	int64_t delay_ms = need_ms - since_last_ms;

	if (delay_ms > 0) {
		LOGPFSML(fi, LOGL_DEBUG, "->REESTABLISH_DELAY delay %" PRId64 "ms; %" PRId64 "ms since last attempt [step %zu/%zu@%ds]\n",
			delay_ms, since_last_ms, srvc->reestablish_delay_idx, (REESTABLISH_DELAY_COUNT-1),
			k_reestablish_delay_s[srvc->reestablish_delay_idx]);
	} else {
		/* cheat and always use a minimum delay of 1ms to ensure a fsm timeout is triggered */
		delay_ms = 1;
	}

	osmo_fsm_inst_state_chg_ms(fi, SRVC_ST_REESTABLISH_DELAY, delay_ms, 3);
}

static void srvc_st_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SRVC_E_ESTABLISH:
	default:
		OSMO_ASSERT(0);
	}
}

static void srvc_st_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;
	RsproPDU_t *pdu;

	osmo_ipa_ka_fsm_start(srvc->ka_fi);

	if (srvc->own_comp_id.type == ComponentType_remsimClient)
		pdu = rspro_gen_ConnectClientReq(&srvc->own_comp_id, srvc->clslot);
	else
		pdu = rspro_gen_ConnectBankReq(&srvc->own_comp_id, srvc->bankd.bank_id,
					       srvc->bankd.num_slots);
	_server_conn_send_rspro(srvc, pdu);
}

static void srvc_st_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;
	RsproPDU_t *pdu = NULL;
	e_ResultCode res;

	switch (event) {
	case SRVC_E_TCP_DOWN:
	case SRVC_E_KA_TIMEOUT:
		srvc_do_reestablish(fi);
		break;
	case SRVC_E_CLIENT_CONN_RES:
		pdu = data;
		res = rspro_get_result(pdu);
		if (res != ResultCode_ok) {
			LOGPFSML(fi, LOGL_ERROR, "Rx RSPRO connectClientRes(result=%s), closing\n",
				 asn_enum_name(&asn_DEF_ResultCode, res));
			osmo_stream_cli_close(srvc->conn);
		} else {
			/* somehow notify the main code? */
			osmo_fsm_inst_state_chg(fi, SRVC_ST_CONNECTED, 0, 0);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void srvc_st_connected_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;

	if (fi->proc.parent)
		osmo_fsm_inst_dispatch(fi->proc.parent, srvc->parent_conn_evt, NULL);
}

static void srvc_st_connected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;
	RsproPDU_t *pdu = NULL;

	switch (event) {
	case SRVC_E_TCP_DOWN:
	case SRVC_E_KA_TIMEOUT:
		srvc_do_reestablish(fi);
		break;
	case SRVC_E_RSPRO_TX:
		pdu = data;
		_server_conn_send_rspro(srvc, pdu);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void srvc_st_connected_onleave(struct osmo_fsm_inst *fi, uint32_t next_state)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;

	if (fi->proc.parent)
		osmo_fsm_inst_dispatch(fi->proc.parent, srvc->parent_disc_evt, NULL);
}

static int ipa_keepalive_send_cb(struct osmo_ipa_ka_fsm_inst *ka_fi, struct msgb *msg, void *data)
{
	struct osmo_stream_cli *cli = data;
	osmo_stream_cli_send(cli, msg);
	return 0;
}

static int ipa_keepalive_timeout_cb(struct osmo_ipa_ka_fsm_inst *ka_fi, void *data)
{
	struct osmo_stream_cli *cli = data;
	struct rspro_server_conn *srvc = osmo_stream_cli_get_data(cli);
	osmo_fsm_inst_dispatch(srvc->fi, SRVC_E_KA_TIMEOUT, NULL);
	return 0;
}

static void srvc_st_reestablish_delay_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;

	if (srvc->conn) {
		LOGPFSML(fi, LOGL_INFO, "Destroying existing connection to server\n");
		osmo_stream_cli_destroy(srvc->conn);
		srvc->conn = NULL;
	}

	/* saturate timeout at last (longest) entry */
	if (srvc->reestablish_delay_idx < REESTABLISH_DELAY_COUNT-1) {
		srvc->reestablish_delay_idx++;
	}
}

static void srvc_st_reestablish_delay(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	default:
		OSMO_ASSERT(0);
	}
}

static void srvc_st_reestablish_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;
	int rc;

	srvc->reestablish_last_ms = get_monotonic_ms();

	LOGPFSML(fi, LOGL_INFO, "Creating TCP connection to server at %s:%u\n",
		 srvc->server_host, srvc->server_port);
	srvc->conn = osmo_stream_cli_create(fi);
	if (!srvc->conn) {
		LOGPFSML(fi, LOGL_FATAL, "Unable to create socket: %s\n", strerror(errno));
		goto err_exit;
	}

	osmo_stream_cli_set_name(srvc->conn, fi->id);
	osmo_stream_cli_set_data(srvc->conn, srvc);
	osmo_stream_cli_set_addr(srvc->conn, srvc->server_host);
	osmo_stream_cli_set_port(srvc->conn, srvc->server_port);
	osmo_stream_cli_set_proto(srvc->conn, IPPROTO_TCP);
	osmo_stream_cli_set_nodelay(srvc->conn, true);

	/* Reconnect is handled by upper layers: */
	osmo_stream_cli_set_reconnect_timeout(srvc->conn, -1);

	osmo_stream_cli_set_segmentation_cb(srvc->conn, osmo_ipa_segmentation_cb);
	osmo_stream_cli_set_connect_cb(srvc->conn, srvc_connect_cb);
	osmo_stream_cli_set_disconnect_cb(srvc->conn, srvc_disconnect_cb);
	osmo_stream_cli_set_read_cb2(srvc->conn, srvc_read_cb);

	srvc->ka_fi = osmo_ipa_ka_fsm_alloc(srvc->conn, fi->id);
	if (!srvc->ka_fi) {
		LOGPFSM(fi, "Unable to create keepalive FSM\n");
		goto err_free_cli;
	}
	osmo_ipa_ka_fsm_set_data(srvc->ka_fi, srvc->conn);
	osmo_ipa_ka_fsm_set_ping_interval(srvc->ka_fi, 30);
	osmo_ipa_ka_fsm_set_pong_timeout(srvc->ka_fi, 10);
	osmo_ipa_ka_fsm_set_send_cb(srvc->ka_fi, ipa_keepalive_send_cb);
	osmo_ipa_ka_fsm_set_timeout_cb(srvc->ka_fi, ipa_keepalive_timeout_cb);

	/* Attempt to connect TCP socket */
	rc = osmo_stream_cli_open(srvc->conn);
	if (rc < 0) {
		LOGPFSML(fi, LOGL_FATAL, "Unable to connect RSPRO to %s:%u - %s\n",
			srvc->server_host, srvc->server_port, strerror(errno));
		/* FIXME: retry? Timer? Abort? */
		goto err_free_ka_fi;
	}

err_free_ka_fi:
	osmo_ipa_ka_fsm_free(srvc->ka_fi);
	srvc->ka_fi = NULL;
err_free_cli:
	osmo_stream_cli_destroy(srvc->conn);
	srvc->conn = NULL;
err_exit:
	exit(1);
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

static void srvc_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;

	switch (event) {
	case SRVC_E_ESTABLISH:
		/* reset delay connect immediately on our first connection */
		srvc->reestablish_delay_idx = 0;
		srvc->reestablish_last_ms = 0;
		srvc_do_reestablish(fi);
		break;
	case SRVC_E_DISCONNECT:
		if (srvc->conn) {
			LOGPFSML(fi, LOGL_INFO, "Destroying existing connection to server\n");
			osmo_stream_cli_destroy(srvc->conn);
			srvc->conn = NULL;
		}
		osmo_fsm_inst_state_chg(fi, SRVC_ST_INIT, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int server_conn_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct rspro_server_conn *srvc = (struct rspro_server_conn *) fi->priv;

	switch (fi->T) {
	case 3:
		/* delay has expired; let's re-establish */
		osmo_fsm_inst_state_chg(fi, SRVC_ST_REESTABLISH, T2_RECONNECT, 2);
		break;
	case 2:
		/* TCP reconnect failed: retry after wait */
		srvc_do_reestablish(fi);
		break;
	case 1:
		/* no ClientConnectRes received: disconnect + reconnect */
		osmo_stream_cli_close(srvc->conn);
		break;
	default:
		OSMO_ASSERT(0);
	}

	return 0;
}

static const struct osmo_fsm_state server_conn_fsm_states[] = {
	[SRVC_ST_INIT] = {
		.name = "INIT",
		.in_event_mask = 0, /* S(SRVC_E_ESTABLISH) via allstate */
		.out_state_mask = S(SRVC_ST_INIT) | S(SRVC_ST_REESTABLISH_DELAY),
		.action = srvc_st_init,
	},
	[SRVC_ST_ESTABLISHED] = {
		.name = "ESTABLISHED",
		.in_event_mask = S(SRVC_E_TCP_DOWN) | S(SRVC_E_KA_TIMEOUT) | S(SRVC_E_CLIENT_CONN_RES),
		.out_state_mask = S(SRVC_ST_CONNECTED) | S(SRVC_ST_REESTABLISH_DELAY) | S(SRVC_ST_INIT),
		.action = srvc_st_established,
		.onenter = srvc_st_established_onenter,
	},
	[SRVC_ST_CONNECTED] = {
		.name = "CONNECTED",
		.in_event_mask = S(SRVC_E_TCP_DOWN) | S(SRVC_E_KA_TIMEOUT) | S(SRVC_E_RSPRO_TX),
		.out_state_mask = S(SRVC_ST_REESTABLISH_DELAY) | S(SRVC_ST_INIT),
		.action = srvc_st_connected,
		.onenter = srvc_st_connected_onenter,
		.onleave = srvc_st_connected_onleave,
	},
	[SRVC_ST_REESTABLISH_DELAY] = {
		.name = "REESTABLISH_DELAY",
		.in_event_mask = 0,
		.out_state_mask = S(SRVC_ST_REESTABLISH) | S(SRVC_ST_INIT),
		.action = srvc_st_reestablish_delay,
		.onenter = srvc_st_reestablish_delay_onenter,
	},
	[SRVC_ST_REESTABLISH] = {
		.name = "REESTABLISH",
		.in_event_mask = S(SRVC_E_TCP_UP) | S(SRVC_E_TCP_DOWN),
		.out_state_mask = S(SRVC_ST_ESTABLISHED) | S(SRVC_ST_REESTABLISH_DELAY) | S(SRVC_ST_INIT),
		.action = srvc_st_reestablish,
		.onenter = srvc_st_reestablish_onenter,
	},
};

struct osmo_fsm rspro_client_server_fsm = {
	.name = "RSPRO_CLIENT",
	.states = server_conn_fsm_states,
	.num_states = ARRAY_SIZE(server_conn_fsm_states),
	.allstate_event_mask = S(SRVC_E_ESTABLISH) | S(SRVC_E_DISCONNECT),
	.allstate_action = srvc_allstate_action,
	.timer_cb = server_conn_fsm_timer_cb,
	.log_subsys = DRSPRO,
	.event_names = server_conn_fsm_event_names,
};

int server_conn_fsm_alloc(void *ctx, struct rspro_server_conn *srvc)
{
	struct osmo_fsm_inst *fi;

	fi = osmo_fsm_inst_alloc(&rspro_client_server_fsm, ctx, srvc, LOGL_DEBUG, "server");
	if (!fi)
		return -1;

	srvc->fi = fi;
	srvc->reestablish_delay_idx = 0;
	srvc->reestablish_last_ms = 0;

	return 0;
}

static __attribute__((constructor)) void on_dso_load(void)
{
	OSMO_ASSERT(osmo_fsm_register(&rspro_client_server_fsm) == 0);
}
