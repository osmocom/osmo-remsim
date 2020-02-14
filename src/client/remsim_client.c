/* (C) 2018-2020 by Harald Welte <laforge@gnumonks.org>
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

#include <talloc.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include "rspro_util.h"
#include "client.h"
#include "debug.h"

static int bankd_handle_rx(struct rspro_server_conn *bankdc, const RsproPDU_t *pdu)
{
	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectClientRes:
		/* Store 'identity' of bankd to in peer_comp_id */
		rspro_comp_id_retrieve(&bankdc->peer_comp_id, &pdu->msg.choice.connectClientRes.identity);
		osmo_fsm_inst_dispatch(bankdc->fi, SRVC_E_CLIENT_CONN_RES, (void *) pdu);
		break;
	case RsproPDUchoice_PR_tpduCardToModem:
	case RsproPDUchoice_PR_setAtrReq:
		return client_user_bankd_handle_rx(bankdc, pdu);
	default:
		LOGPFSML(bankdc->fi, LOGL_ERROR, "Unknown/Unsupported RSPRO PDU %s\n",
			 rspro_msgt_name(pdu));
		return -1;
	}

	return 0;
}

/* handle incoming messages from server */
static int srvc_handle_rx(struct rspro_server_conn *srvc, const RsproPDU_t *pdu)
{
	struct bankd_client *bc = srvc2bankd_client(srvc);
	RsproPDU_t  *resp;

	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectClientRes:
		/* Store 'identity' of server in srvc->peer_comp_id */
		rspro_comp_id_retrieve(&srvc->peer_comp_id, &pdu->msg.choice.connectClientRes.identity);
		osmo_fsm_inst_dispatch(srvc->fi, SRVC_E_CLIENT_CONN_RES, (void *) pdu);
		break;
	case RsproPDUchoice_PR_configClientIdReq:
		/* store/set the clientID as instructed by the server */
		if (!srvc->clslot)
			srvc->clslot = talloc_zero(srvc, ClientSlot_t);
		*srvc->clslot = pdu->msg.choice.configClientIdReq.clientSlot;
		if (!bc->bankd_conn.clslot)
			bc->bankd_conn.clslot = talloc_zero(bc, ClientSlot_t);
		*bc->bankd_conn.clslot = *bc->srv_conn.clslot;
		/* send response to server */
		resp = rspro_gen_ConfigClientIdRes(ResultCode_ok);
		server_conn_send_rspro(srvc, resp);
		break;
	case RsproPDUchoice_PR_configClientBankReq:
		/* store/set the bankd ip/port as instructed by the server */
		osmo_talloc_replace_string(bc, &bc->bankd_conn.server_host,
					   rspro_IpAddr2str(&pdu->msg.choice.configClientBankReq.bankd.ip));
		rspro2bank_slot(&bc->bankd_slot, &pdu->msg.choice.configClientBankReq.bankSlot);
		bc->bankd_conn.server_port = pdu->msg.choice.configClientBankReq.bankd.port;
		/* instruct bankd FSM to connect */
		osmo_fsm_inst_dispatch(bc->bankd_conn.fi, SRVC_E_ESTABLISH, NULL);
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

struct bankd_client *remsim_client_create(void *ctx, const char *name, const char *software)
{
	struct bankd_client *bc = talloc_zero(ctx, struct bankd_client);
	struct rspro_server_conn *srvc, *bankdc;
	int rc;

	if (!bc)
		return NULL;

	/* create and [attempt to] establish connection to remsim-server */
	srvc = &bc->srv_conn;
	srvc->server_host = "localhost";
	srvc->server_port = 9998;
	srvc->handle_rx = srvc_handle_rx;
	srvc->own_comp_id.type = ComponentType_remsimClient;
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.name, name);
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.software, software);
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.sw_version, PACKAGE_VERSION);

	rc = server_conn_fsm_alloc(bc, srvc);
	if (rc < 0) {
		fprintf(stderr, "Unable to create Server conn FSM: %s\n", strerror(errno));
		exit(1);
	}

	bankdc = &bc->bankd_conn;
	/* server_host / server_port are configured from remsim-server */
	bankdc->handle_rx = bankd_handle_rx;
	memcpy(&bankdc->own_comp_id, &srvc->own_comp_id, sizeof(bankdc->own_comp_id));
	rc = server_conn_fsm_alloc(bc, bankdc);
	if (rc < 0) {
		fprintf(stderr, "Unable to connect bankd conn FSM: %s\n", strerror(errno));
		exit(1);
	}
	osmo_fsm_inst_update_id(bankdc->fi, "bankd");

	return bc;
}

void remsim_client_set_clslot(struct bankd_client *bc, int client_id, int slot_nr)
{
	if (!bc->srv_conn.clslot) {
		bc->srv_conn.clslot = talloc_zero(bc, ClientSlot_t);
		OSMO_ASSERT(bc->srv_conn.clslot);
	}

	if (!bc->bankd_conn.clslot) {
		bc->bankd_conn.clslot = talloc_zero(bc, ClientSlot_t);
		OSMO_ASSERT(bc->bankd_conn.clslot);
	}

	if (client_id >= 0) {
		bc->srv_conn.clslot->clientId = client_id;
		bc->bankd_conn.clslot->clientId = client_id;
	}

	if (slot_nr >= 0) {
		bc->srv_conn.clslot->slotNr = slot_nr;
		bc->bankd_conn.clslot->slotNr = slot_nr;
	}
}



#include <signal.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>

static void *g_tall_ctx;
void __thread *talloc_asn1_ctx;
int asn_debug;

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

static void handle_options(struct bankd_client *bc, int argc, char **argv)
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
			bc->srv_conn.server_host = optarg;
			break;
		case 'p':
			bc->srv_conn.server_port = atoi(optarg);
			break;
		case 'c':
			remsim_client_set_clslot(bc, atoi(optarg), -1);
			break;
		case 'n':
			remsim_client_set_clslot(bc, -1, atoi(optarg));
			break;
		default:
			break;
		}
	}
}

int main(int argc, char **argv)
{
	struct bankd_client *g_client;
	char hostname[256];

	gethostname(hostname, sizeof(hostname));

	g_tall_ctx = talloc_named_const(NULL, 0, "global");
	talloc_asn1_ctx = talloc_named_const(g_tall_ctx, 0, "asn1");
	msgb_talloc_ctx_init(g_tall_ctx, 0);

	osmo_init_logging2(g_tall_ctx, &log_info);

	g_client = remsim_client_create(g_tall_ctx, hostname, "remsim-client");

	handle_options(g_client, argc, argv);

	osmo_fsm_inst_dispatch(g_client->srv_conn.fi, SRVC_E_ESTABLISH, NULL);

	signal(SIGUSR1, handle_sig_usr1);

	asn_debug = 0;

	client_user_main(g_client);
}
