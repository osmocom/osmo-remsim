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

#include <errno.h>
#include <string.h>
#include <signal.h>

#define _GNU_SOURCE
#include <getopt.h>

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
		LOGPFSML(bc->bankd_fi, LOGL_ERROR, "Error decoding PDU\n");
		return -1;
	}

	LOGPFSM(bc->bankd_fi, "Rx RSPRO %s\n", rspro_msgt_name(pdu));

	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectClientRes:
		/* Store 'identity' of bankd to in peer_comp_id */
		rspro_comp_id_retrieve(&bc->peer_comp_id, &pdu->msg.choice.connectClientRes.identity);
		osmo_fsm_inst_dispatch(bc->bankd_fi, BDC_E_CLIENT_CONN_RES, pdu);
		break;
	default:
		LOGPFSML(bc->bankd_fi, LOGL_ERROR, "Unknown/Unsuppoerted RSPRO PDU %s: %s\n",
			 rspro_msgt_name(pdu), msgb_hexdump(msg));
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
	case IPAC_PROTO_IPACCESS:
		rc = ipaccess_bts_handle_ccm(conn, &bc->srv_conn.ipa_dev, msg);
		if (rc < 0)
			break;
		switch (hh->data[0]) {
		case IPAC_MSGT_PONG:
			ipa_keepalive_fsm_pong_received(bc->srv_conn.keepalive_fi);
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
			LOGPFSML(bc->bankd_fi, LOGL_DEBUG, "Received RSPRO %s\n", msgb_hexdump(msg));
			rc = bankd_handle_msg(bc, msg);
			break;
		default:
			goto invalid;
		}
		break;
	default:
		goto invalid;
	}

	msgb_free(msg);
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
	case RsproPDUchoice_PR_configClientIdReq:
		/* store/set the clientID as instructed by the server */
		if (!g_client->srv_conn.clslot)
			g_client->srv_conn.clslot = talloc_zero(g_client, ClientSlot_t);
		*g_client->srv_conn.clslot = pdu->msg.choice.configClientIdReq.clientSlot;
		/* send response to server */
		resp = rspro_gen_ConfigClientIdRes(ResultCode_ok);
		server_conn_send_rspro(srvc, resp);
		break;
	case RsproPDUchoice_PR_configClientBankReq:
		/* store/set the bankd ip/port as instructed by the server */
		osmo_talloc_replace_string(g_client, &g_client->bankd_host,
					   rspro_IpAddr2str(&pdu->msg.choice.configClientBankReq.bankd.ip));
		g_client->bankd_port = pdu->msg.choice.configClientBankReq.bankd.port;
		rspro2bank_slot(&g_client->bankd_slot, &pdu->msg.choice.configClientBankReq.bankSlot);
		/* instruct bankd FSM to connect */
		osmo_fsm_inst_dispatch(g_client->bankd_fi, BDC_E_ESTABLISH, NULL);
		/* send response to server */
		resp = rspro_gen_ConfigClientBankRes(ResultCode_ok);
		server_conn_send_rspro(srvc, resp);
		break;
	default:
		LOGPFSML(srvc->fi, LOGL_ERROR, "Unknown/Unsupported RSPRO PDU type: %s\n",
			 rspro_msgt_name(pdu));
		return -1;
	}

	return 0;
}

static void handle_sig_usr1(int signal)
{
	OSMO_ASSERT(signal == SIGUSR1);
	talloc_report_full(g_tall_ctx, stderr);
}

static void printf_help()
{
	printf(
		"  -h --help                  Print this help message\n"
		"  -i --server-ip A.B.C.D     remsim-server IP address\n"
		"  -p --server-port 13245     remsim-server TCP port\n"
		"  -i --client-id <0-65535>   RSPRO ClientId of this client\n"
		"  -n --client-slot <0-65535> RSPRO SlotNr of this client\n"
	      );
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "server-ip", 1, 0, 'i' },
			{ "server-port", 1, 0, 'p' },
			{ "client-id", 1, 0, 'c' },
			{ "client-slot", 1, 0, 'n' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hi:p:c:n:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			printf_help();
			exit(0);
			break;
		case 'i':
			g_client->srv_conn.server_host = optarg;
			break;
		case 'p':
			g_client->srv_conn.server_port = atoi(optarg);
			break;
		case 'c':
			if (!g_client->srv_conn.clslot)
				g_client->srv_conn.clslot = talloc_zero(g_client, ClientSlot_t);
			g_client->srv_conn.clslot->clientId = atoi(optarg);
			break;
		case 's':
			if (!g_client->srv_conn.clslot)
				g_client->srv_conn.clslot = talloc_zero(g_client, ClientSlot_t);
			g_client->srv_conn.clslot->slotNr = atoi(optarg);
			break;
		default:
			break;
		}
	}
}

int main(int argc, char **argv)
{
	struct rspro_server_conn *srvc;
	int rc;

	g_tall_ctx = talloc_named_const(NULL, 0, "global");
	talloc_asn1_ctx = talloc_named_const(g_tall_ctx, 0, "asn1");
	msgb_talloc_ctx_init(g_tall_ctx, 0);

	osmo_init_logging2(g_tall_ctx, &log_info);

	g_client = talloc_zero(g_tall_ctx, struct bankd_client);

	srvc = &g_client->srv_conn;
	srvc->server_host = "localhost";
	srvc->server_port = 9998;
	srvc->handle_rx = srvc_handle_rx;
	srvc->own_comp_id.type = ComponentType_remsimClient;
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.name, "fixme-name");
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.software, "remsim-client");
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.sw_version, PACKAGE_VERSION);

	handle_options(argc, argv);

	signal(SIGUSR1, handle_sig_usr1);

	rc = server_conn_fsm_alloc(g_client, srvc);
	if (rc < 0) {
		fprintf(stderr, "Unable to create Server conn FSM: %s\n", strerror(errno));
		exit(1);
	}
	osmo_fsm_inst_dispatch(srvc->fi, SRVC_E_ESTABLISH, NULL);

	asn_debug = 0;

	if (bankd_conn_fsm_alloc(g_client) < 0) {
		fprintf(stderr, "Unable to connect: %s\n", strerror(errno));
		exit(1);
	}

	while (1) {
		osmo_select_main(0);
	}
}
