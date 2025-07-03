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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include <pthread.h>

#include <sys/socket.h>
#include <netdb.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/core/fsm.h>

#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>

#include <asn_application.h>
#include <osmocom/rspro/RsproPDU.h>

#include "bankd.h"
#include "rspro_client_fsm.h"
#include "debug.h"
#include "rspro_util.h"
#include "gsmtap.h"

/* signal indicates to worker thread that its map has been deleted */
#define SIGMAPDEL	SIGRTMIN+1
#define SIGMAPADD	SIGRTMIN+2

static void handle_sig_usr1(int sig);
static void handle_sig_mapdel(int sig);
static void handle_sig_mapadd(int sig);

__thread void *talloc_asn1_ctx;
struct bankd *g_bankd;
static void *g_tall_ctx;
static char g_hostname[256];

static void *worker_main(void *arg);

/***********************************************************************
* bankd core / main thread
***********************************************************************/

int asn_debug;

static void bankd_init(struct bankd *bankd)
{
	g_tall_ctx = talloc_named_const(NULL, 0, "global");
	osmo_init_logging2(g_tall_ctx, &log_info);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	osmo_fsm_log_addr(0);
	log_set_print_tid(osmo_stderr_target, 1);
	log_enable_multithread();

	asn_debug = 0;

	/* initialize members of 'bankd' */
	bankd->slotmaps = slotmap_init(bankd);
	INIT_LLIST_HEAD(&bankd->workers);
	pthread_mutex_init(&bankd->workers_mutex, NULL);

	/* set some defaults, overridden by commandline/config */
	bankd->srvc.bankd.bank_id = 1;
	bankd->srvc.bankd.num_slots = 8;

	bankd->comp_id.type = ComponentType_remsimBankd;
	OSMO_STRLCPY_ARRAY(bankd->comp_id.name, g_hostname);
	OSMO_STRLCPY_ARRAY(bankd->comp_id.software, "remsim-bankd");
	OSMO_STRLCPY_ARRAY(bankd->comp_id.sw_version, PACKAGE_VERSION);
	/* FIXME: other members of app_comp_id */

	INIT_LLIST_HEAD(&bankd->pcsc_slot_names);

	bankd->cfg.permit_shared_pcsc = false;
	bankd->cfg.gsmtap_host = NULL;
	bankd->cfg.gsmtap_slot = -1;
}

/* create + start a new bankd_worker thread */
static struct bankd_worker *bankd_create_worker(struct bankd *bankd, unsigned int i)
{
	struct bankd_worker *worker;
	int rc;

	worker = talloc_zero(bankd, struct bankd_worker);
	if (!worker)
		return NULL;

	worker->bankd = bankd;
	worker->num = i;
	worker->ops = &pcsc_driver_ops;
	worker->last_vccPresent = true; /* allow cold reset should first indication be false */
	worker->last_resetActive = false; /* allow warm reset should first indication be true */

	/* in the initial state, the worker has no client.fd, bank_slot or pcsc handle yet */

	rc = pthread_create(&worker->thread, NULL, worker_main, worker);
	if (rc != 0) {
		talloc_free(worker);
		return NULL;
	}

	pthread_mutex_lock(&bankd->workers_mutex);
	llist_add_tail(&worker->list, &bankd->workers);
	pthread_mutex_unlock(&bankd->workers_mutex);

	return worker;
}

static bool terminate = false;

/* deliver given signal 'sig' to the firts worker matching bs and cs (if given) */
static void send_signal_to_worker(const struct bank_slot *bs, const struct client_slot *cs, int sig)
{
	struct bankd_worker *worker;
	pthread_mutex_lock(&g_bankd->workers_mutex);
	llist_for_each_entry(worker, &g_bankd->workers, list) {
		if (bs && (bs->bank_id != worker->slot.bank_id || bs->slot_nr != worker->slot.slot_nr))
			continue;
		if (cs && (cs->client_id != worker->client.clslot.client_id ||
			   cs->slot_nr != worker->client.clslot.slot_nr))
			continue;

		pthread_kill(worker->thread, sig);
		break;
	}
	pthread_mutex_unlock(&g_bankd->workers_mutex);
}

/* Remove a mapping */
static void bankd_srvc_remove_mapping(struct slot_mapping *map)
{
	struct bank_slot bs = map->bank;

	slotmap_del(g_bankd->slotmaps, map);

	/* kill/reset the respective worker, if any! */
	send_signal_to_worker(&bs, NULL, SIGMAPDEL);
}

/* handle incoming messages from server */
static int bankd_srvc_handle_rx(struct rspro_server_conn *srvc, const RsproPDU_t *pdu)
{
	const CreateMappingReq_t *creq = NULL;
	const RemoveMappingReq_t *rreq = NULL;
	struct bankd_worker *worker;
	struct slot_mapping *map;
	struct bank_slot bs;
	struct client_slot cs;
	RsproPDU_t *resp;

	LOGPFSML(srvc->fi, LOGL_DEBUG, "Rx RSPRO %s\n", rspro_msgt_name(pdu));

	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectBankRes:
		if (pdu->msg.choice.connectBankRes.identity.type != ComponentType_remsimServer) {
			LOGPFSML(srvc->fi, LOGL_ERROR, "Server connection to a ComponentType(%ld) != RemsimServer? "
				 "Check your IP/Port configuration\n",
				 pdu->msg.choice.connectBankRes.identity.type);
			osmo_fsm_inst_dispatch(srvc->fi, SRVC_E_DISCONNECT, NULL);
			return -1;
		}
		/* Store 'identity' of server in srvc->peer_comp_id */
		rspro_comp_id_retrieve(&srvc->peer_comp_id, &pdu->msg.choice.connectBankRes.identity);
		osmo_fsm_inst_dispatch(srvc->fi, SRVC_E_CLIENT_CONN_RES, (void *) pdu);
		break;
	case RsproPDUchoice_PR_createMappingReq:
		creq = &pdu->msg.choice.createMappingReq;
		if (creq->bank.bankId != g_bankd->srvc.bankd.bank_id) {
			LOGPFSML(srvc->fi, LOGL_ERROR, "createMapping specifies invalid Bank ID %lu "
				 "(we are %u)\n", creq->bank.bankId, g_bankd->srvc.bankd.bank_id);
			resp = rspro_gen_CreateMappingRes(ResultCode_illegalBankId);
		} else if (creq->bank.slotNr >= g_bankd->srvc.bankd.num_slots) {
			LOGPFSML(srvc->fi, LOGL_ERROR, "createMapping specifies invalid Slot Nr %lu "
				 "(we have %u)\n", creq->bank.slotNr, g_bankd->srvc.bankd.num_slots);
			resp = rspro_gen_CreateMappingRes(ResultCode_illegalSlotId);
		} else {
			rspro2bank_slot(&bs, &creq->bank);
			rspro2client_slot(&cs, &creq->client);

			/* check if slot map exists */
			map = slotmap_by_bank(g_bankd->slotmaps, &bs);
			if (map) {
				if (client_slot_equals(&map->client, &cs)) {
					LOGPFSML(srvc->fi, LOGL_ERROR, "ignoring identical slotmap\n");
					resp = rspro_gen_CreateMappingRes(ResultCode_ok);
					goto send_resp;
				} else {
					LOGPFSML(srvc->fi, LOGL_NOTICE, "slot already connected to client %d:%d. Removing old mapping.\n",
						 map->client.client_id, map->client.slot_nr);
					bankd_srvc_remove_mapping(map);
				}
			}

			/* check if client map exists */
			map = slotmap_by_client(g_bankd->slotmaps, &cs);
			if (map) {
				LOGPFSML(srvc->fi, LOGL_NOTICE, "client already connected to slot %d:%d. Removing old mapping.\n",
					 map->bank.bank_id, map->bank.slot_nr);
				bankd_srvc_remove_mapping(map);
			}

			/* Add a new mapping */
			map = slotmap_add(g_bankd->slotmaps, &bs, &cs);
			if (!map) {
				LOGPFSML(srvc->fi, LOGL_ERROR, "could not create slotmap\n");
				resp = rspro_gen_CreateMappingRes(ResultCode_illegalSlotId);
			} else {
				send_signal_to_worker(NULL, &cs, SIGMAPADD);
				resp = rspro_gen_CreateMappingRes(ResultCode_ok);
			}
		}
send_resp:
		server_conn_send_rspro(srvc, resp);
		break;
	case RsproPDUchoice_PR_removeMappingReq:
		rreq = &pdu->msg.choice.removeMappingReq;
		if (rreq->bank.bankId != g_bankd->srvc.bankd.bank_id) {
			LOGPFSML(srvc->fi, LOGL_ERROR, "removeMapping specifies invalid Bank ID %lu "
				 "(we are %u)\n", rreq->bank.bankId, g_bankd->srvc.bankd.bank_id);
			resp = rspro_gen_RemoveMappingRes(ResultCode_illegalBankId);
		} else if (rreq->bank.slotNr >= g_bankd->srvc.bankd.num_slots) {
			LOGPFSML(srvc->fi, LOGL_ERROR, "removeMapping specifies invalid Slot Nr %lu "
				 "(we have %u)\n", rreq->bank.slotNr, g_bankd->srvc.bankd.num_slots);
			resp = rspro_gen_RemoveMappingRes(ResultCode_illegalSlotId);
		} else {
			rspro2bank_slot(&bs, &rreq->bank);
			/* Remove a mapping */
			map = slotmap_by_bank(g_bankd->slotmaps, &bs);
			if (!map) {
				LOGPFSML(srvc->fi, LOGL_ERROR, "B(%lu:%lu) could not find to-be-deleted slotmap\n", rreq->bank.bankId, rreq->bank.slotNr);
				resp = rspro_gen_RemoveMappingRes(ResultCode_unknownSlotmap);
			} else {
				rspro2client_slot(&cs, &rreq->client);
				if (!client_slot_equals(&map->client, &cs)) {
					LOGPFSML(srvc->fi, LOGL_NOTICE, "B(%lu:%lu): ClientId in removeMappingReq != map\n", rreq->bank.bankId, rreq->bank.slotNr);
					resp = rspro_gen_RemoveMappingRes(ResultCode_unknownSlotmap);
				} else {
					LOGPFSML(srvc->fi, LOGL_INFO, "B(%lu:%lu): removing slotmap\n", rreq->bank.bankId, rreq->bank.slotNr);
					bankd_srvc_remove_mapping(map);
					resp = rspro_gen_RemoveMappingRes(ResultCode_ok);
				}
			}
		}
		server_conn_send_rspro(srvc, resp);
		break;
	case RsproPDUchoice_PR_resetStateReq:
		/* delete all slotmaps */
		slotmap_del_all(g_bankd->slotmaps);
		/* notify all workers about maps having disappeared */
		pthread_mutex_lock(&g_bankd->workers_mutex);
		llist_for_each_entry(worker, &g_bankd->workers, list) {
			pthread_kill(worker->thread, SIGMAPDEL);
		}
		pthread_mutex_unlock(&g_bankd->workers_mutex);
		/* send response to server */
		resp = rspro_gen_ResetStateRes(ResultCode_ok);
		server_conn_send_rspro(srvc, resp);
		break;
	default:
		LOGPFSML(srvc->fi, LOGL_ERROR, "Unknown/Unsupported RSPRO PDU type: %u\n",
			 pdu->msg.present);
		return -1;
	}

	return 0;
}

static void printf_help(FILE *out)
{
	fprintf(out,
"  -h --help                    Print this help message\n"
"  -V --version                 Print the version of the program\n"
"  -d --debug option            Enable debug logging (e.g. DMAIN:DST2)\n"
"  -i --server-host A.B.C.D     remsim-server IP address (mandatory)\n"
"  -p --server-port <1-65535>   remsim-server TCP port (default: 9998)\n"
"  -b --bank-id <1-1023>        Bank Identifier of this SIM bank (default: 1)\n"
"  -n --num-slots <1-1023>      Number of Slots in this SIM bank (default: 8)\n"
"  -I --bind-ip A.B.C.D         Local IP address to bind for incoming client\n"
"                               connections (default: INADDR_ANY)\n"
"  -P --bind-port <1-65535>		Local TCP port to bind for incoming client\n"
"                               connections (default: 9999)\n"
"  -s --permit-shared-pcsc      Permit SHARED access to PC/SC readers (default: exclusive)\n"
"  -g --gsmtap-ip A.B.C.D       Enable GSMTAP and send APDU traces to given IP\n"
"  -G --gsmtap-slot <0-1023>    Limit tracing to given bank slot, only (default: all slots)\n"
"  -L --disable-color           Disable colors for logging to stderr\n"
"  -T --timestamp               Prefix every log line with a timestamp\n"
"  -e --log-level number        Set a global loglevel.\n"
	      );
}

static int g_bind_port = 9999;
static char *g_bind_ip = NULL;

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'V' },
			{ "debug", 1, 0, 'd' },
			{ "server-host", 1, 0, 'i' },
			{ "server-port", 1, 0, 'p' },
			{ "bank-id", 1, 0, 'b' },
			{ "num-slots", 1, 0, 'n' },
			{ "component-name", 1, 0, 'N' },
			{ "bind-ip", 1, 0, 'I' },
			{ "bind-port", 1, 0, 'P' },
			{ "permit-shared-pcsc", 0, 0, 's' },
			{ "gsmtap-ip", 1, 0, 'g' },
			{ "gsmtap-slot", 1, 0, 'G' },
			{ "disable-color", 0, 0, 'L' },
			{ "timestamp", 0, 0, 'T' },
			{ "log-level", 1, 0, 'e' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hVd:i:p:b:n:N:I:P:sg:G:LTe:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			printf_help(stdout);
			exit(0);
			break;
		case 'V':
			printf("osmo-remsim-bankd version %s\n", VERSION);
			exit(0);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'i':
			g_bankd->srvc.server_host = optarg;
			break;
		case 'p':
			g_bankd->srvc.server_port = atoi(optarg);
			break;
		case 'b':
			g_bankd->srvc.bankd.bank_id = atoi(optarg);
			break;
		case 'n':
			g_bankd->srvc.bankd.num_slots = atoi(optarg);
			break;
		case 'N':
			OSMO_STRLCPY_ARRAY(g_bankd->srvc.own_comp_id.name, optarg);
			break;
		case 'I':
			g_bind_ip = optarg;
			break;
		case 'P':
			g_bind_port = atoi(optarg);
			break;
		case 's':
			g_bankd->cfg.permit_shared_pcsc = true;
			break;
		case 'g':
			g_bankd->cfg.gsmtap_host = optarg;
			break;
		case 'G':
			g_bankd->cfg.gsmtap_slot = atoi(optarg);
			break;
		case 'L':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		}
	}
}

int main(int argc, char **argv)
{
	struct rspro_server_conn *srvc;
	int i, rc;

	g_bankd = talloc_zero(NULL, struct bankd);
	OSMO_ASSERT(g_bankd);

	if (gethostname(g_hostname, sizeof(g_hostname)) < 0)
		OSMO_STRLCPY_ARRAY(g_hostname, "unknown");

	bankd_init(g_bankd);

	srvc = &g_bankd->srvc;
	srvc->server_host = NULL;
	srvc->server_port = 9998;
	srvc->handle_rx = bankd_srvc_handle_rx;
	srvc->own_comp_id.type = ComponentType_remsimBankd;
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.name, g_hostname);
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.software, "remsim-bankd");
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.sw_version, PACKAGE_VERSION);

	handle_options(argc, argv);

	if (!srvc->server_host) {
		fprintf(stderr, "ERROR: You must specify the host name / IP of the remsim-server to which "
			"the bankd shall connect to\n\n");
		printf_help(stderr);
		exit(2);
	}

	g_bankd->main = pthread_self();
	signal(SIGMAPDEL, handle_sig_mapdel);
	signal(SIGMAPADD, handle_sig_mapadd);
	signal(SIGUSR1, handle_sig_usr1);

	LOGP(DMAIN, LOGL_INFO, "Reading PCSC slots...\n");
	/* Np lock or mutex required for the pcsc_slot_names list, as this is only
	 * read once during bankd initialization, when the worker threads haven't
	 * started yet */
	rc = bankd_pcsc_read_slotnames(g_bankd, "bankd_pcsc_slots.csv");
	if (rc) {
		fprintf(stderr, "ERROR: failed reading bankd_pcsc_slots.csv file\n");
		exit(1);
	}

	/* Connection towards remsim-server */
	rc = server_conn_fsm_alloc(g_bankd, srvc);
	if (rc < 0) {
		fprintf(stderr, "Unable to create Server conn FSM: %s\n", strerror(errno));
		exit(1);
	}
	osmo_fsm_inst_dispatch(srvc->fi, SRVC_E_ESTABLISH, NULL);

	/* create listening socket for inbound client connections */
	LOGP(DMAIN, LOGL_INFO, "Initiating listen TCP socket at %s:%d\n",
	     g_bind_ip ? g_bind_ip : "INADDR_ANY", g_bind_port);
	rc = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP, g_bind_ip, g_bind_port, OSMO_SOCK_F_BIND);
	if (rc < 0) {
		fprintf(stderr, "Unable to create TCP socket at %s:%d: %s\n",
			g_bind_ip ? g_bind_ip : "INADDR_ANY", g_bind_port, strerror(errno));
		exit(1);
	}
	g_bankd->accept_fd = rc;

	/* initialize gsmtap, if required */
	if (g_bankd->cfg.gsmtap_host) {
		LOGP(DMAIN, LOGL_INFO, "Initiating GSMTAP\n");
		rc = bankd_gsmtap_init(g_bankd->cfg.gsmtap_host);
		if (rc < 0) {
			fprintf(stderr, "Unable to open GSMTAP\n");
			exit(1);
		}
	}

	/* create worker threads: One per reader/slot! */
	for (i = 0; i < g_bankd->srvc.bankd.num_slots; i++) {
		struct bankd_worker *w;
		LOGP(DMAIN, LOGL_INFO, "Initiating worker %d\n", i);
		w = bankd_create_worker(g_bankd, i);
		if (!w) {
			fprintf(stderr, "Error creating bankd worker thread\n");
			exit(21);
		}
	}

	while (!terminate) {
		osmo_select_main(0);
	}
	LOGP(DMAIN, LOGL_NOTICE, "Terminated\n");
	talloc_free(g_bankd);
	exit(0);
}



/***********************************************************************
 * bankd worker thread
 ***********************************************************************/

static __thread struct bankd_worker *g_worker;

struct value_string worker_state_names[] = {
	{ BW_ST_INIT, 			"INIT" },
	{ BW_ST_ACCEPTING,		"ACCEPTING" },
	{ BW_ST_CONN_WAIT_ID,		"CONN_WAIT_ID" },
	{ BW_ST_CONN_CLIENT,		"CONN_CLIENT" },
	{ BW_ST_CONN_CLIENT_WAIT_MAP,	"CONN_CLIENT_WAIT_MAP" },
	{ BW_ST_CONN_CLIENT_MAPPED,	"CONN_CLIENT_MAPPED" },
	{ BW_ST_CONN_CLIENT_MAPPED_CARD,"CONN_CLIENT_MAPPED_CARD" },
	{ BW_ST_CONN_CLIENT_UNMAPPED,	"CONN_CLIENT_UNMAPPED" },
	{ 0, NULL }
};

static int worker_send_rspro(struct bankd_worker *worker, RsproPDU_t *pdu);

static void worker_set_state(struct bankd_worker *worker, enum bankd_worker_state new_state)
{
	LOGW(worker, "Changing state to %s\n", get_value_string(worker_state_names, new_state));
	worker->state = new_state;
	worker->timeout = 0;
}

static void worker_set_state_timeout(struct bankd_worker *worker, enum bankd_worker_state new_state,
				     unsigned int timeout_secs)
{
	LOGW(worker, "Changing state to %s (timeout=%u)\n",
		get_value_string(worker_state_names, new_state), timeout_secs);
	worker->state = new_state;
	worker->timeout = timeout_secs;
}

/* signal handler for receiving SIGMAPDEL from main thread */
static void handle_sig_mapdel(int sig)
{
	LOGW(g_worker, "SIGMAPDEL received: Main thread informs us our map is gone\n");
	OSMO_ASSERT(sig == SIGMAPDEL);
	if (g_worker->state >= BW_ST_CONN_CLIENT_MAPPED) {
		g_worker->slot.bank_id = 0xffff;
		g_worker->slot.slot_nr = 0xffff;
		worker_set_state(g_worker, BW_ST_CONN_CLIENT_UNMAPPED);
	}
}

/* signal handler for receiving SIGMAPADD from main thread */
static void handle_sig_mapadd(int sig)
{
	LOGW(g_worker, "SIGMAPADD received\n");
	/* do nothing */
}

static void handle_sig_usr1(int sig)
{
	OSMO_ASSERT(sig == SIGUSR1);

	if (pthread_equal(g_bankd->main, pthread_self())) {
		struct bankd_worker *worker;
		/* main thread */
		fprintf(stderr, "=== Talloc Report of main thread:\n");
		talloc_report_full(g_tall_ctx, stderr);

		/* iterate over worker threads and ask them to dump their talloc state */
		pthread_mutex_lock(&g_bankd->workers_mutex);
		llist_for_each_entry(worker, &g_bankd->workers, list) {
			pthread_kill(worker->thread, SIGUSR1);
		}
		pthread_mutex_unlock(&g_bankd->workers_mutex);
	} else {
		/* worker thread */
		fprintf(stderr, "=== Talloc Report of %s\n", g_worker->name);
		talloc_report_full(g_worker->tall_ctx, stderr);
	}
}

static void worker_cleanup(void *arg)
{
	struct bankd_worker *worker = (struct bankd_worker *) arg;
	struct bankd *bankd = worker->bankd;

	/* FIXME: should we still do this? in the thread ?!? */
	pthread_mutex_lock(&bankd->workers_mutex);
	llist_del(&worker->list);
	talloc_free(worker);	/* FIXME: is this safe? */
	pthread_mutex_unlock(&bankd->workers_mutex);
}

static int worker_open_card(struct bankd_worker *worker)
{
	int rc;

	OSMO_ASSERT(worker->state == BW_ST_CONN_CLIENT_MAPPED);

	if (!worker->reader.name) {
		/* resolve PC/SC reader name from slot_id -> name map */
		worker->reader.name = bankd_pcsc_get_slot_name(worker->bankd, &worker->slot);
		if (!worker->reader.name) {
			LOGW(worker, "No PC/SC reader name configured for %u/%u, fix your config\n",
				worker->slot.bank_id, worker->slot.slot_nr);
			return -1;
		}
	}
	OSMO_ASSERT(worker->reader.name);

	rc = worker->ops->open_card(worker);
	if (rc < 0)
		return rc;

	worker_set_state(worker, BW_ST_CONN_CLIENT_MAPPED_CARD);
	/* FIXME: notify client about this state change */

	return 0;
}


static int blocking_ipa_read(struct bankd_worker *worker, uint8_t *buf, unsigned int buf_size)
{
	struct ipaccess_head *hh;
	uint16_t len;
	int needed, rc;

	if (buf_size < sizeof(*hh))
		return -1;

	hh = (struct ipaccess_head *) buf;

	/* we use 'recv' and not 'read' below, as 'recv' will always fail with -EINTR
	 * in case of a signal being received */

restart_hdr:
	/* 1) blocking recv from the socket (IPA header) */
	rc = recv(worker->client.fd, buf, sizeof(*hh), 0);
	if (rc == -1 && errno == EINTR) {
		if (worker->state == BW_ST_CONN_CLIENT_UNMAPPED)
			return -23;
		goto restart_hdr;
	} else if (rc < 0)
		return rc;
	else if (rc < sizeof(*hh))
		return -2;

	len = ntohs(hh->len);
	needed = len; //- sizeof(*hh);

restart_body:
	/* 2) blocking recv from the socket (payload) */
	rc = recv(worker->client.fd, buf+sizeof(*hh), needed, 0);
	if (rc == -1 && errno == EINTR) {
		if (worker->state == BW_ST_CONN_CLIENT_UNMAPPED)
			return -23;
		goto restart_body;
	} else if (rc < 0)
		return rc;
	else if (rc < needed)
		return -3;

	return len;
}

static int worker_send_rspro(struct bankd_worker *worker, RsproPDU_t *pdu)
{
	struct msgb *msg = rspro_enc_msg(pdu);
	int rc;

	if (!msg) {
		ASN_STRUCT_FREE(asn_DEF_RsproPDU, pdu);
		LOGW(worker, "error encoding RSPRO\n");
		return -1;
	}

	msg->l2h = msg->data;
	/* prepend the header */
	ipa_prepend_header_ext(msg, IPAC_PROTO_EXT_RSPRO);
	ipa_prepend_header(msg, IPAC_PROTO_OSMO);

	/* actually send it through the socket */
	rc = write(worker->client.fd, msgb_data(msg), msgb_length(msg));
	if (rc == msgb_length(msg))
		rc = 0;
	else {
		LOGW(worker, "error during write: %d != %d\n", rc, msgb_length(msg));
		rc = -1;
	}

	msgb_free(msg);

	return rc;
}

/* attempt to obtain slot-map */
static int worker_try_slotmap(struct bankd_worker *worker)
{
	struct slot_mapping *slmap;

	slmap = slotmap_by_client(worker->bankd->slotmaps, &worker->client.clslot);
	if (!slmap) {
		LOGW(worker, "No slotmap (yet) for client C(%u:%u)\n",
			worker->client.clslot.client_id, worker->client.clslot.slot_nr);
		/* check in 10s if the map has been installed meanwhile by main thread */
		worker_set_state_timeout(worker, BW_ST_CONN_CLIENT_WAIT_MAP, 10);
		return -1;
	} else {
		LOGW(worker, "slotmap found: C(%u:%u) -> B(%u:%u)\n",
			slmap->client.client_id, slmap->client.slot_nr,
			slmap->bank.bank_id, slmap->bank.slot_nr);
		worker->slot = slmap->bank;
		worker_set_state_timeout(worker, BW_ST_CONN_CLIENT_MAPPED, 10);
		return worker_open_card(worker);
	}
}

/* inform the remote end (client) about the (new) ATR */
static int worker_send_atr(struct bankd_worker *worker)
{
	RsproPDU_t *set_atr;
	set_atr = rspro_gen_SetAtrReq(worker->client.clslot.client_id,
				      worker->client.clslot.slot_nr,
				      worker->card.atr, worker->card.atr_len);

	/* trace ATR to GSMTAP, if configured */
	if (g_bankd->cfg.gsmtap_host && (g_bankd->cfg.gsmtap_slot == -1 ||
		g_bankd->cfg.gsmtap_slot == worker->slot.slot_nr)) {
		bankd_gsmtap_send_apdu(GSMTAP_SIM_ATR, worker->card.atr, worker->card.atr_len,
			NULL, 0);
	}

	if (!set_atr)
		return -1;
	return worker_send_rspro(worker, set_atr);
}

static int worker_handle_connectClientReq(struct bankd_worker *worker, const RsproPDU_t *pdu)
{
	const struct ComponentIdentity *cid = &pdu->msg.choice.connectClientReq.identity;
	RsproPDU_t *resp = NULL;
	e_ResultCode res;
	int rc;

	OSMO_ASSERT(pdu->msg.present == RsproPDUchoice_PR_connectClientReq);

	LOGW(worker, "Rx RSPRO connectClientReq(T=%lu, N='%s', SW='%s', VER='%s')\n",
		cid->type, cid->name.buf, cid->software.buf, cid->swVersion.buf);
	/* FIXME: store somewhere? */

	if (worker->state != BW_ST_CONN_WAIT_ID) {
		LOGW(worker, "Unexpected connectClientReq\n");
		res = ResultCode_illegalClientId;
		rc = -102;
		goto respond_and_err;
	}

	if (!pdu->msg.choice.connectClientReq.clientSlot) {
		LOGW(worker, "missing clientID, aborting\n");
		res = ResultCode_illegalClientId;
		rc = -103;
		goto respond_and_err;
	}
	worker->client.clslot.client_id = pdu->msg.choice.connectClientReq.clientSlot->clientId;
	worker->client.clslot.slot_nr = pdu->msg.choice.connectClientReq.clientSlot->slotNr;
	worker_set_state(worker, BW_ST_CONN_CLIENT);

	if (worker_try_slotmap(worker) >= 0)
		res = ResultCode_ok;
	else
		res = ResultCode_cardNotPresent;

	resp = rspro_gen_ConnectClientRes(&worker->bankd->comp_id, res);
	rc = worker_send_rspro(worker, resp);
	if (rc < 0)
		return rc;

	if (res == ResultCode_ok)
		rc = worker_send_atr(worker);

	return rc;

respond_and_err:
	if (res) {
		resp = rspro_gen_ConnectClientRes(&worker->bankd->comp_id, res);
		worker_send_rspro(worker, resp);
	}
	return rc;
}

static int worker_handle_tpduModemToCard(struct bankd_worker *worker, const RsproPDU_t *pdu)
{
	const struct TpduModemToCard *mdm2sim = &pdu->msg.choice.tpduModemToCard;
	uint8_t rx_buf[1024];
	DWORD rx_buf_len = sizeof(rx_buf);
	RsproPDU_t *pdu_resp;
	struct client_slot clslot;
	struct bank_slot bslot;
	int rc;

	LOGW(worker, "Rx RSPRO tpduModemToCard(%s)\n",
	     osmo_hexdump_nospc(mdm2sim->data.buf, mdm2sim->data.size));

	if (worker->state != BW_ST_CONN_CLIENT_MAPPED_CARD) {
		LOGW(worker, "Unexpected tpduModemToCaard\n");
		return -104;
	}

	/* Validate that toBankSlot / fromClientSlot match our expectations */
	rspro2client_slot(&clslot, &mdm2sim->fromClientSlot);
	rspro2bank_slot(&bslot, &mdm2sim->toBankSlot);
	if (!bank_slot_equals(&worker->slot, &bslot)) {
		LOGW(worker, "Unexpected BankSlot %u:%u in tpduModemToCard\n",
			bslot.bank_id, bslot.slot_nr);
		return -105;
	}
	if (!client_slot_equals(&worker->client.clslot, &clslot)) {
		LOGW(worker, "Unexpected ClientSlot %u:%u in tpduModemToCard\n",
			clslot.client_id, clslot.slot_nr);
		return -106;
	}

	rc = worker->ops->transceive(worker, mdm2sim->data.buf, mdm2sim->data.size,
				     rx_buf, &rx_buf_len);
	if (rc < 0)
		return rc;

	LOGW(worker, "Tx RSPRO tpduCardToModem(%s)\n", osmo_hexdump_nospc(rx_buf, rx_buf_len));
	/* encode response PDU and send it */
	pdu_resp = rspro_gen_TpduCard2Modem(&mdm2sim->toBankSlot, &mdm2sim->fromClientSlot,
					    rx_buf, rx_buf_len);
	worker_send_rspro(worker, pdu_resp);

	/* trace APDU to GSMTAP, if configured */
	if (g_bankd->cfg.gsmtap_host && (g_bankd->cfg.gsmtap_slot == -1 ||
		g_bankd->cfg.gsmtap_slot == worker->slot.slot_nr)) {
		bankd_gsmtap_send_apdu(GSMTAP_SIM_APDU, mdm2sim->data.buf, mdm2sim->data.size, rx_buf,
			rx_buf_len);
	}
	return 0;
}

static int worker_handle_clientSlotStatusInd(struct bankd_worker *worker, const RsproPDU_t *pdu)
{
	const struct ClientSlotStatusInd *cssi = &pdu->msg.choice.clientSlotStatusInd;
	const struct SlotPhysStatus *sps = &cssi->slotPhysStatus;
	int rc = 0;

	LOGW(worker, "Rx RSPRO clientSlotStatusInd(RST=%s, VCC=%s, CLK=%s)\n",
		sps->resetActive ? "ACTIVE" : "INACTIVE",
		sps->vccPresent ? *sps->vccPresent ? "PRESENT" : "ABSENT" : "NULL",
		sps->clkActive ? *sps->clkActive ? "ACTIVE" : "INACTIVE" : "NULL");

	/* perform cold or warm reset */
	if (sps->vccPresent && *sps->vccPresent == 0) {
		/* VCC is not present */

		if (worker->last_vccPresent) {
			/* falling edge detected on VCC; perform cold reset */
			rc = worker->ops->reset_card(worker, true);
		}
	} else if (sps->resetActive) {
		if (!worker->last_resetActive) {
			/* VCC is present (or not reported) and rising edge detected on reset; perform warm reset */
			rc = worker->ops->reset_card(worker, false);
		}
	}

	/* update last known states */
	if (sps->vccPresent) {
		worker->last_vccPresent = *sps->vccPresent != 0;
	}

	worker->last_resetActive = sps->resetActive != 0;

	return rc;
}

/* handle one incoming RSPRO message from a client inside a worker thread */
static int worker_handle_rspro(struct bankd_worker *worker, const RsproPDU_t *pdu)
{
	int rc = -100;

	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectClientReq:
		rc = worker_handle_connectClientReq(worker, pdu);
		break;
	case RsproPDUchoice_PR_tpduModemToCard:
		rc = worker_handle_tpduModemToCard(worker, pdu);
		break;
	case RsproPDUchoice_PR_clientSlotStatusInd:
		rc = worker_handle_clientSlotStatusInd(worker, pdu);
		rc = 0;
		break;
	case RsproPDUchoice_PR_setAtrRes:
		LOGW(worker, "Rx RSPRO %s\n", rspro_msgt_name(pdu));
		rc = 0;
		break;
	default:
		LOGW(worker, "Rx RSPRO %s (unhandled)\n", rspro_msgt_name(pdu));
		rc = -101;
		break;
	}

	return rc;
}

static int wait_for_fd_or_timeout(int fd, unsigned int timeout_secs)
{
	struct timeval tout = { timeout_secs, 0 };
	fd_set readset;

	FD_ZERO(&readset);
	FD_SET(fd, &readset);
	return select(fd + 1, &readset, NULL, NULL, timeout_secs ? &tout : NULL);
}

/* body of the main transceive loop */
static int worker_transceive_loop(struct bankd_worker *worker)
{
	struct ipaccess_head *hh;
	struct ipaccess_head_ext *hh_ext;
	uint8_t buf[65536]; /* maximum length expressed in 16bit length field */
	asn_dec_rval_t rval;
	int data_len, rc;
	RsproPDU_t *pdu = NULL;

restart_wait:
	rc = wait_for_fd_or_timeout(worker->client.fd, worker->timeout);
	if (rc == -1 && errno == EINTR) {
		if (worker->state == BW_ST_CONN_CLIENT_UNMAPPED)
			return -23;
		else
			worker_try_slotmap(worker);
		goto restart_wait;
	} else if (rc < 0)
		return rc;
	else if (rc == 0) {
		/* TIMEOUT case */
		switch (worker->state) {
		case BW_ST_CONN_CLIENT_WAIT_MAP:
			/* re-check if mapping exists meanwhile? */
			rc = worker_try_slotmap(worker);
			break;
		case BW_ST_CONN_CLIENT_MAPPED:
			/* re-check if reader/card can be opened meanwhile? */
			rc = worker_open_card(worker);
			break;
		default:
			OSMO_ASSERT(0);
		}
		if (rc == 0)
			worker_send_atr(worker);
		/* return early, so we do another select rather than the blocking read below */
		return 0;
	};

	/* 1) blocking read of entire IPA message from the socket */
	rc = blocking_ipa_read(worker, buf, sizeof(buf));
	if (rc < 0)
		return rc;
	data_len = rc;

	hh = (struct ipaccess_head *) buf;
	if (hh->proto != IPAC_PROTO_OSMO && hh->proto != IPAC_PROTO_IPACCESS) {
		LOGW(worker, "Received unsupported IPA protocol != OSMO: 0x%02x\n", hh->proto);
		return -4;
	}

	if (hh->proto == IPAC_PROTO_IPACCESS) {
		switch (hh->data[0]) {
		case IPAC_MSGT_PING:
			return ipa_ccm_send_pong(worker->client.fd);
		case IPAC_MSGT_ID_ACK:
			return ipa_ccm_send_id_ack(g_worker->client.fd);
		default:
			LOGW(worker, "IPA CCM 0x%02x not implemented yet\n", hh->data[0]);
			break;
		}
		return 0;
	}

	hh_ext = (struct ipaccess_head_ext *) buf + sizeof(*hh);
	if (data_len < sizeof(*hh_ext)) {
		LOGW(worker, "Received short message\n");
		return -5;
	}
	data_len -= sizeof(*hh_ext);
	if (hh_ext->proto != IPAC_PROTO_EXT_RSPRO) {
		LOGW(worker, "Received unsupported IPA EXT protocol != RSPRO: 0x%02x\n", hh_ext->proto);
		return -6;
	}

	/* 2) ASN1 BER decode of the message */
	rval = ber_decode(NULL, &asn_DEF_RsproPDU, (void **) &pdu, hh_ext->data, data_len);
	if (rval.code != RC_OK) {
		LOGW(worker, "Error during BER decode of RSPRO\n");
		return -7;
	}

	/* 3) handling of the message, possibly resulting in PCSC commands */
	rc = worker_handle_rspro(worker, pdu);
	ASN_STRUCT_FREE(asn_DEF_RsproPDU, pdu);
	if (rc < 0) {
		LOGW(worker, "Error handling RSPRO\n");
		return rc;
	}

	/* everything OK if we reach here */
	return 0;
}

/* obtain an ascii representation of the client IP/port */
static int worker_client_addrstr(char *out, unsigned int outlen, const struct bankd_worker *worker)
{
	char hostbuf[32], portbuf[32];
	int rc;

	rc = getnameinfo((const struct sockaddr *)&worker->client.peer_addr,
			 worker->client.peer_addr_len, hostbuf, sizeof(hostbuf),
			 portbuf, sizeof(portbuf), NI_NUMERICHOST | NI_NUMERICSERV);
	if (rc != 0) {
		out[0] = '\0';
		return -1;
	}
	snprintf(out, outlen, "%s:%s", hostbuf, portbuf);
	return 0;
}

/* worker thread main function */
static void *worker_main(void *arg)
{
	void *top_ctx;
	int rc;

	g_worker = (struct bankd_worker *) arg;

	worker_set_state(g_worker, BW_ST_INIT);

	/* not permitted in multithreaded environment */
	talloc_disable_null_tracking();
	g_worker->tall_ctx = talloc_named_const(NULL, 0, "top");
	talloc_asn1_ctx = talloc_named_const(g_worker->tall_ctx, 0, "asn1");

	/* set the thread name */
	g_worker->name = talloc_asprintf(g_worker->tall_ctx, "bankd-worker(%u)", g_worker->num);
	pthread_setname_np(pthread_self(), g_worker->name);

	/* push cleanup helper */
	pthread_cleanup_push(&worker_cleanup, g_worker);

	g_worker->slot.bank_id = 0xffff;
	g_worker->slot.slot_nr = 0xffff;

	/* we continuously perform the same loop here, recycling the worker thread
	 * once the client connection is gone or we have some trouble with the card/reader */
	while (1) {
		char buf[128];

		g_worker->client.peer_addr_len = sizeof(g_worker->client.peer_addr);

		worker_set_state(g_worker, BW_ST_ACCEPTING);
		/* first wait for an incoming TCP connection */
		rc = accept(g_worker->bankd->accept_fd, (struct sockaddr *) &g_worker->client.peer_addr,
			    &g_worker->client.peer_addr_len);
		if (rc < 0) {
			continue;
		}
		g_worker->client.fd = rc;
		worker_client_addrstr(buf, sizeof(buf), g_worker);
		LOGW(g_worker, "Accepted connection from %s\n", buf);
		worker_set_state(g_worker, BW_ST_CONN_WAIT_ID);

		/* run the main worker transceive loop body until there was some error */
		while (1) {
			rc = worker_transceive_loop(g_worker);
			if (rc < 0)
				break;
			if (g_worker->state == BW_ST_CONN_CLIENT_UNMAPPED)
				break;
		}

		if (rc == -23)
			LOGW(g_worker, "Client unmapped: Cleaning up state\n");
		else
			LOGW(g_worker, "Error %d occurred: Cleaning up state\n", rc);

		/* clean-up: reset to sane state */
		memset(&g_worker->card, 0, sizeof(g_worker->card));
		g_worker->ops->cleanup(g_worker);
		if (g_worker->reader.name)
			g_worker->reader.name = NULL;
		if (g_worker->client.fd >= 0)
			close(g_worker->client.fd);
		memset(&g_worker->client.peer_addr, 0, sizeof(g_worker->client.peer_addr));
		g_worker->client.fd = -1;
		g_worker->client.clslot.client_id = g_worker->client.clslot.slot_nr = 0;
	}

	pthread_cleanup_pop(1);
	talloc_free(top_ctx);
	pthread_exit(NULL);
}
