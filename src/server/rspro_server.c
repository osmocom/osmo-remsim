#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/abis/ipa.h>

#include <osmocom/rspro/RsproPDU.h>

#include "debug.h"
#include "rspro_util.h"
#include "rspro_server.h"

#define S(x)	(1 << (x))

static RsproPDU_t *slotmap2CreateMappingReq(const struct slot_mapping *slotmap)
{
	ClientSlot_t clslot;
	BankSlot_t bslot;

	client_slot2rspro(&clslot, &slotmap->client);
	bank_slot2rspro(&bslot, &slotmap->bank);

	return rspro_gen_CreateMappingReq(&clslot, &bslot);
}

static RsproPDU_t *slotmap2RemoveMappingReq(const struct slot_mapping *slotmap)
{
	ClientSlot_t clslot;
	BankSlot_t bslot;

	client_slot2rspro(&clslot, &slotmap->client);
	bank_slot2rspro(&bslot, &slotmap->bank);

	return rspro_gen_RemoveMappingReq(&clslot, &bslot);
}


static void client_conn_send(struct rspro_client_conn *conn, RsproPDU_t *pdu)
{
	if (!pdu) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Attempt to transmit NULL\n");
		osmo_log_backtrace(DMAIN, LOGL_ERROR);
		return;
	}
	LOGPFSM(conn->fi, "Tx RSPRO %s\n", rspro_msgt_name(pdu));

	struct msgb *msg_tx = rspro_enc_msg(pdu);
	if (!msg_tx) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Error encdoing RSPRO %s\n", rspro_msgt_name(pdu));
		osmo_log_backtrace(DMAIN, LOGL_ERROR);
		ASN_STRUCT_FREE(asn_DEF_RsproPDU, pdu);
		return;
	}
	ipa_prepend_header_ext(msg_tx, IPAC_PROTO_EXT_RSPRO);
	ipa_msg_push_header(msg_tx, IPAC_PROTO_OSMO);
	ipa_server_conn_send(conn->peer, msg_tx);
}


/***********************************************************************
 * per-client connection FSM
 ***********************************************************************/

static void rspro_client_conn_destroy(struct rspro_client_conn *conn);

enum remsim_server_client_fsm_state {
	CLNTC_ST_INIT,
	CLNTC_ST_ESTABLISHED,
	CLNTC_ST_WAIT_CONF_RES,		/* waiting for ConfigClientRes */
	CLNTC_ST_CONNECTED_BANKD,
	CLNTC_ST_CONNECTED_CLIENT,
};

enum remsim_server_client_event {
	CLNTC_E_TCP_UP,
	CLNTC_E_CLIENT_CONN,	/* Connect{Client,Bank}Req received */
	CLNTC_E_BANK_CONN,
	CLNTC_E_TCP_DOWN,
	CLNTC_E_KA_TIMEOUT,
	CLNTC_E_CREATE_MAP_RES,	/* CreateMappingRes received */
	CLNTC_E_REMOVE_MAP_RES,	/* RemoveMappingRes received */
	CLNTC_E_CONFIG_CL_RES,	/* ConfigClientRes received */
	CLNTC_E_PUSH,		/* drain maps_new or maps_delreq */
	CLNTC_E_CL_CFG_BANKD,	/* send [new] ConfigConfigBankReq */
};

static const struct value_string server_client_event_names[] = {
	OSMO_VALUE_STRING(CLNTC_E_TCP_UP),
	OSMO_VALUE_STRING(CLNTC_E_CLIENT_CONN),
	OSMO_VALUE_STRING(CLNTC_E_BANK_CONN),
	OSMO_VALUE_STRING(CLNTC_E_TCP_DOWN),
	OSMO_VALUE_STRING(CLNTC_E_KA_TIMEOUT),
	OSMO_VALUE_STRING(CLNTC_E_CREATE_MAP_RES),
	OSMO_VALUE_STRING(CLNTC_E_REMOVE_MAP_RES),
	OSMO_VALUE_STRING(CLNTC_E_CONFIG_CL_RES),
	OSMO_VALUE_STRING(CLNTC_E_PUSH),
	OSMO_VALUE_STRING(CLNTC_E_CL_CFG_BANKD),
	{ 0, NULL }
};

static void clnt_st_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case CLNTC_E_TCP_UP:
		osmo_fsm_inst_state_chg(fi, CLNTC_ST_ESTABLISHED, 10, 1);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void clnt_st_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct rspro_client_conn *conn = fi->priv;
	const RsproPDU_t *pdu = data;
	const ConnectClientReq_t *cclreq = NULL;
	const ConnectBankReq_t *cbreq = NULL;
	RsproPDU_t *resp = NULL;

	switch (event) {
	case CLNTC_E_CLIENT_CONN:
		cclreq = &pdu->msg.choice.connectClientReq;
		/* save the [remote] component identity in 'conn' */
		rspro_comp_id_retrieve(&conn->comp_id, &cclreq->identity);
		if (conn->comp_id.type != ComponentType_remsimClient) {
			LOGPFSM(fi, "ConnectClientReq from identity != Client ?!?\n");
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		}

		/* reparent us from srv->connections to srv->clients */
		pthread_rwlock_wrlock(&conn->srv->rwlock);
		llist_del(&conn->list);
		llist_add_tail(&conn->list, &conn->srv->clients);
		pthread_rwlock_unlock(&conn->srv->rwlock);

		if (!cclreq->clientSlot) {
#if 0
			/* FIXME: determine ClientID */
			resp = rspro_gen_ConnectClientRes(&conn->srv->comp_id, ResultCode_ok);
			client_conn_send(conn, resp);
			osmo_fsm_inst_state_chg(fi, CLNTC_ST_WAIT_CL_CONF_RES, 3, 30);
#else
			/* FIXME: the original plan was to dynamically assign a ClientID
			 * from server to client here. Send ConfigReq and transition to
			 * CLNTC_ST_WAIT_CONF_RES */
			LOGPFSM(fi, "ConnectClientReq without ClientId not supported yet!\n");
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
#endif
		} else {
			/* FIXME: check for unique-ness */
			rspro2client_slot(&conn->client.slot, cclreq->clientSlot);
			osmo_fsm_inst_update_id_f(fi, "C%u:%u", conn->client.slot.client_id,
						  conn->client.slot.slot_nr);
			osmo_fsm_inst_update_id_f(conn->keepalive_fi, "C%u:%u",
						  conn->client.slot.client_id,
						  conn->client.slot.slot_nr);
			resp = rspro_gen_ConnectClientRes(&conn->srv->comp_id, ResultCode_ok);
			client_conn_send(conn, resp);
			osmo_fsm_inst_state_chg(fi, CLNTC_ST_CONNECTED_CLIENT, 0, 0);
		}
		break;
	case CLNTC_E_BANK_CONN:
		cbreq = &pdu->msg.choice.connectBankReq;
		/* save the [remote] component identity in 'conn' */
		rspro_comp_id_retrieve(&conn->comp_id, &cbreq->identity);
		if (conn->comp_id.type != ComponentType_remsimBankd) {
			LOGPFSM(fi, "ConnectBankReq from identity != Bank ?!?\n");
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		}
		/* FIXME: check for unique-ness */
		conn->bank.bank_id = cbreq->bankId;
		conn->bank.num_slots = cbreq->numberOfSlots;
		osmo_fsm_inst_update_id_f(fi, "B%u", conn->bank.bank_id);
		osmo_fsm_inst_update_id_f(conn->keepalive_fi, "B%u", conn->bank.bank_id);

		/* reparent us from srv->connections to srv->banks */
		pthread_rwlock_wrlock(&conn->srv->rwlock);
		llist_del(&conn->list);
		llist_add_tail(&conn->list, &conn->srv->banks);
		pthread_rwlock_unlock(&conn->srv->rwlock);

		/* send response to bank first */
		resp = rspro_gen_ConnectBankRes(&conn->srv->comp_id, ResultCode_ok);
		client_conn_send(conn, resp);

		/* the state change will associate any pre-existing slotmaps */
		osmo_fsm_inst_state_chg(fi, CLNTC_ST_CONNECTED_BANKD, 0, 0);

		osmo_fsm_inst_dispatch(fi, CLNTC_E_PUSH, NULL);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void clnt_st_wait_cl_conf_res(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case CLNTC_E_CONFIG_CL_RES:
		osmo_fsm_inst_state_chg(fi, CLNTC_ST_CONNECTED_CLIENT, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/*! find a connected client (if any) for given slotmap and update its Bankd configuration.
 * \param[in] map slotmap whose client connection shall be updated
 * \param[in] srv rspro_server on which we operate
 * \param[in] bankd_conn bankd connection serving the map (may be NULL if not known)
 */
static void _update_client_for_slotmap(struct slot_mapping *map, struct rspro_server *srv,
					struct rspro_client_conn *bankd_conn)
{
	struct rspro_client_conn *conn = client_conn_by_slot(srv, &map->client);
	char ip_str[INET6_ADDRSTRLEN];
	char port_str[6];
	uint32_t bankd_ip;
	int bankd_port;
	bool changed = false;
	int rc;

	OSMO_ASSERT(map);
	OSMO_ASSERT(srv);

	if (!conn)
		LOGP(DMAIN, LOGL_DEBUG, "%s\n", __func__);
	else
		LOGPFSM(conn->fi, "%s\n", __func__);

	if (!conn)
		return;

	if (!bank_slot_equals(&conn->client.bankd.slot, &map->bank)) {
		LOGPFSM(conn->fi, "BankSlot has changed B%u:%u -> B%u:%u\n",
			conn->client.bankd.slot.bank_id, conn->client.bankd.slot.slot_nr,
			map->bank.bank_id, map->bank.slot_nr);
		conn->client.bankd.slot = map->bank;
		changed = true;
	}

	/* if caller didn't provide bankd_conn, resolve it from map */
	if (!bankd_conn)
		bankd_conn = bankd_conn_by_id(srv, map->bank.bank_id);
	if (!bankd_conn)
		return;

	/* obtain IP and port of bankd */
	rc = osmo_sock_get_ip_and_port(bankd_conn->peer->ofd.fd, ip_str, sizeof(ip_str),
					port_str, sizeof(port_str), false);
	if (rc < 0) {
		LOGPFSM(bankd_conn->fi, "Error during getpeername\n");
		return;
	}
	bankd_ip = ntohl(inet_addr(ip_str));
	bankd_port = 9999; /* TODO: configurable */
	if (conn->client.bankd.port != bankd_port || conn->client.bankd.ip != bankd_ip) {
		LOGPFSM(conn->fi, "Bankd IP/Port changed to %s:%s\n", ip_str, port_str);
		conn->client.bankd.ip = bankd_ip;
		conn->client.bankd.port = bankd_port;
		changed = true;
	}

	/* update the client with new bankd information, if any changes were made */
	if (changed)
		osmo_fsm_inst_dispatch(conn->fi, CLNTC_E_CL_CFG_BANKD, NULL);
}

static void clnt_st_connected_client_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rspro_client_conn *conn = fi->priv;
	struct slotmaps *slotmaps = conn->srv->slotmaps;
	struct slot_mapping *map;

	LOGPFSM(fi, "%s\n", __func__);

	/* check for an existing slotmap for this client/slot */
	slotmaps_rdlock(slotmaps);
	llist_for_each_entry(map, &slotmaps->mappings, list) {
		if (client_slot_equals(&map->client, &conn->client.slot)) {
			_update_client_for_slotmap(map, conn->srv, NULL);
			break;
		}
	}
	slotmaps_unlock(slotmaps);
#if 0
	ClientSlot_t clslot;
	RsproPDU_t *pdu;

	/* send configuration to this new client */
	client_slot2rspro(&clslot, FIXME);
	pdu = rspro_gen_ConfigClientReq(&clslot, bankd_ip, bankd_port);
	client_conn_send(conn, pdu);
#endif
}

static void clnt_st_connected_bankd_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rspro_client_conn *conn = fi->priv;
	struct slotmaps *slotmaps = conn->srv->slotmaps;
	struct slot_mapping *map;

	LOGPFSM(fi, "Associating pre-existing slotmaps (if any)\n");
	/* Link all known mappings to this new bank */
	slotmaps_wrlock(slotmaps);
	llist_for_each_entry(map, &slotmaps->mappings, list) {
		if (map->bank.bank_id == conn->bank.bank_id)
			_slotmap_state_change(map, SLMAP_S_NEW, &conn->bank.maps_new);
	}
	slotmaps_unlock(slotmaps);
}

static void clnt_st_connected_client(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct rspro_client_conn *conn = fi->priv;
	BankSlot_t bslot;
	RsproPDU_t *tx;

	switch (event) {
	case CLNTC_E_CL_CFG_BANKD: /* Send [new] Bankd information to client */
		bank_slot2rspro(&bslot, &conn->client.bankd.slot);
		tx = rspro_gen_ConfigClientBankReq(&bslot, conn->client.bankd.ip,
						   conn->client.bankd.port);
		client_conn_send(conn, tx);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void clnt_st_connected_bankd(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct rspro_client_conn *conn = fi->priv;
	struct slotmaps *slotmaps = conn->srv->slotmaps;
	const __attribute__((unused)) RsproPDU_t *rx = NULL;
	struct slot_mapping *map, *map2;

	switch (event) {
	case CLNTC_E_CREATE_MAP_RES: /* Bankd acknowledges mapping was created */
		rx = data;
		slotmaps_wrlock(slotmaps);
		/* FIXME: resolve map by pdu->tag */
		/* as hack use first element of conn->maps_unack */
		map = llist_first_entry(&conn->bank.maps_unack, struct slot_mapping, bank_list);
		if (!map) {
			slotmaps_unlock(slotmaps);
			LOGPFSM(fi, "CreateMapRes but no unacknowledged map");
			break;
		}
		_slotmap_state_change(map, SLMAP_S_ACTIVE, &conn->bank.maps_active);
		slotmaps_unlock(slotmaps);
		_update_client_for_slotmap(map, conn->srv, conn);
		break;
	case CLNTC_E_REMOVE_MAP_RES: /* Bankd acknowledges mapping was removed */
		rx = data;
		slotmaps_wrlock(slotmaps);
		/* FIXME: resolve map by pdu->tag */
		/* as hack use first element of conn->maps_deleting */
		map = llist_first_entry(&conn->bank.maps_deleting, struct slot_mapping, bank_list);
		if (!map) {
			slotmaps_unlock(slotmaps);
			LOGPFSM(fi, "RemoveMapRes but no unacknowledged map");
			break;
		}
		slotmaps_unlock(slotmaps);
		/* slotmap_del() will remove it from both global and bank list */
		slotmap_del(map->maps, map);
		/* FIXME: update client! */
		break;
	case CLNTC_E_PUSH: /* check if any create or delete requests are pending */
		slotmaps_wrlock(slotmaps);
		/* send any pending create requests */
		llist_for_each_entry_safe(map, map2, &conn->bank.maps_new, bank_list) {
			RsproPDU_t *pdu = slotmap2CreateMappingReq(map);
			client_conn_send(conn, pdu);
			_slotmap_state_change(map, SLMAP_S_UNACKNOWLEDGED, &conn->bank.maps_unack);
		}
		/* send any pending delete requests */
		llist_for_each_entry_safe(map, map2, &conn->bank.maps_delreq, bank_list) {
			RsproPDU_t *pdu = slotmap2RemoveMappingReq(map);
			client_conn_send(conn, pdu);
			_slotmap_state_change(map, SLMAP_S_DELETING, &conn->bank.maps_deleting);
		}
		slotmaps_unlock(slotmaps);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void clnt_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct rspro_client_conn *conn = fi->priv;

	switch (event) {
	case CLNTC_E_TCP_DOWN:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	case CLNTC_E_KA_TIMEOUT:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int server_client_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	//struct rspro_client_conn *conn = fi->priv;

	switch (fi->T) {
	case 1:
		/* No ClientConnectReq received:disconnect */
		return 1; /* ask core to terminate FSM */
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static void server_client_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct rspro_client_conn *conn = fi->priv;
	/* this call will destroy the IPA connection, which will in turn call closed_cb()
	 * which will try to deliver a E_TCP_DOWN event. Clear conn->fi to avoid that loop */
	conn->fi = NULL;
	rspro_client_conn_destroy(conn);
}

static const struct osmo_fsm_state server_client_fsm_states[] = {
	[CLNTC_ST_INIT] = {
		.name = "INIT",
		.in_event_mask = S(CLNTC_E_TCP_UP),
		.out_state_mask = S(CLNTC_ST_ESTABLISHED),
		.action = clnt_st_init,
	},
	[CLNTC_ST_ESTABLISHED] = {
		.name = "ESTABLISHED",
		.in_event_mask = S(CLNTC_E_CLIENT_CONN) | S(CLNTC_E_BANK_CONN),
		.out_state_mask = S(CLNTC_ST_CONNECTED_CLIENT) | S(CLNTC_ST_WAIT_CONF_RES) |
				  S(CLNTC_ST_CONNECTED_BANKD),
		.action = clnt_st_established,
	},
	[CLNTC_ST_WAIT_CONF_RES] = {
		.name = "WAIT_CONFIG_RES",
		.in_event_mask = S(CLNTC_E_CONFIG_CL_RES),
		.out_state_mask = S(CLNTC_ST_CONNECTED_CLIENT),
		.action = clnt_st_wait_cl_conf_res,
	},
	[CLNTC_ST_CONNECTED_CLIENT] = {
		.name = "CONNECTED_CLIENT",
		.in_event_mask = S(CLNTC_E_CL_CFG_BANKD),
		.action = clnt_st_connected_client,
		.onenter = clnt_st_connected_client_onenter,
	},
	[CLNTC_ST_CONNECTED_BANKD] = {
		.name = "CONNECTED_BANKD",
		.in_event_mask = S(CLNTC_E_CREATE_MAP_RES) | S(CLNTC_E_REMOVE_MAP_RES) |
				 S(CLNTC_E_PUSH),
		.action = clnt_st_connected_bankd,
		.onenter = clnt_st_connected_bankd_onenter,
	},

};

static struct osmo_fsm remsim_server_client_fsm = {
	.name = "SERVER_CONN",
	.states = server_client_fsm_states,
	.num_states = ARRAY_SIZE(server_client_fsm_states),
	.allstate_event_mask = S(CLNTC_E_TCP_DOWN) | S(CLNTC_E_KA_TIMEOUT),
	.allstate_action = clnt_allstate_action,
	.cleanup = server_client_cleanup,
	.timer_cb = server_client_fsm_timer_cb,
	.log_subsys = DMAIN,
	.event_names = server_client_event_names,
};

struct osmo_fsm_inst *server_client_fsm_alloc(void *ctx, struct rspro_client_conn *conn)
{
	//const char *id = osmo_sock_get_name2(conn->peer->ofd.fd);
	return osmo_fsm_inst_alloc(&remsim_server_client_fsm, ctx, conn, LOGL_DEBUG, NULL);
}


static __attribute__((constructor)) void on_dso_load(void)
{
	osmo_fsm_register(&remsim_server_client_fsm);
}


/***********************************************************************
 * IPA RSPRO Server
 ***********************************************************************/

struct rspro_client_conn *_client_conn_by_slot(struct rspro_server *srv, const struct client_slot *cslot)
{
	struct rspro_client_conn *conn;
	llist_for_each_entry(conn, &srv->clients, list) {
		if (client_slot_equals(&conn->client.slot, cslot))
			return conn;
	}
	return NULL;
}
struct rspro_client_conn *client_conn_by_slot(struct rspro_server *srv, const struct client_slot *cslot)
{
	struct rspro_client_conn *conn;
	pthread_rwlock_rdlock(&srv->rwlock);
	conn = _client_conn_by_slot(srv, cslot);
	pthread_rwlock_unlock(&srv->rwlock);
	return conn;
}

struct rspro_client_conn *_bankd_conn_by_id(struct rspro_server *srv, uint16_t bank_id)
{
	struct rspro_client_conn *conn;
	llist_for_each_entry(conn, &srv->banks, list) {
		if (conn->bank.bank_id == bank_id)
			return conn;
	}
	return NULL;
}
struct rspro_client_conn *bankd_conn_by_id(struct rspro_server *srv, uint16_t bank_id)
{
	struct rspro_client_conn *conn;
	pthread_rwlock_rdlock(&srv->rwlock);
	conn = _bankd_conn_by_id(srv, bank_id);
	pthread_rwlock_unlock(&srv->rwlock);
	return conn;
}

static int handle_rx_rspro(struct rspro_client_conn *conn, const RsproPDU_t *pdu)
{
	LOGPFSM(conn->fi, "Rx RSPRO %s\n", rspro_msgt_name(pdu));

	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectClientReq:
		osmo_fsm_inst_dispatch(conn->fi, CLNTC_E_CLIENT_CONN, (void *)pdu);
		break;
	case RsproPDUchoice_PR_connectBankReq:
		osmo_fsm_inst_dispatch(conn->fi, CLNTC_E_BANK_CONN, (void *)pdu);
		break;
	case RsproPDUchoice_PR_createMappingRes:
		osmo_fsm_inst_dispatch(conn->fi, CLNTC_E_CREATE_MAP_RES, (void *)pdu);
		break;
	case RsproPDUchoice_PR_removeMappingRes:
		osmo_fsm_inst_dispatch(conn->fi, CLNTC_E_REMOVE_MAP_RES, (void *)pdu);
		break;
	case RsproPDUchoice_PR_configClientIdRes:
		osmo_fsm_inst_dispatch(conn->fi, CLNTC_E_CONFIG_CL_RES, (void *)pdu);
		break;
	case RsproPDUchoice_PR_configClientBankRes:
		/* TODO: store somewhere that client has ACKed? */
		break;
	default:
		LOGPFSML(conn->fi, LOGL_ERROR, "Received unknown/unimplemented RSPRO msg_type %s\n",
			 rspro_msgt_name(pdu));
		return -1;
	}
	return 0;
}

/* data was received from one of the client connections to the RSPRO socket */
static int sock_read_cb(struct ipa_server_conn *peer, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct rspro_client_conn *conn = peer->data;
	RsproPDU_t *pdu;
	int rc;

	if (msgb_length(msg) < sizeof(*hh))
		goto invalid;
	msg->l2h = &hh->data[0];
	switch (hh->proto) {
	case IPAC_PROTO_IPACCESS:
		rc = ipa_server_conn_ccm(peer, msg);
		if (rc < 0)
			break;
		switch (hh->data[0]) {
		case IPAC_MSGT_PONG:
			ipa_keepalive_fsm_pong_received(conn->keepalive_fi);
			rc = 0;
			break;
		default:
			break;
		}
		break;
	case IPAC_PROTO_OSMO:
		if (!he || msgb_l2len(msg)< sizeof(*he))
			goto invalid;
		msg->l2h = &he->data[0];

		switch (he->proto) {
		case IPAC_PROTO_EXT_RSPRO:
			pdu = rspro_dec_msg(msg);
			if (!pdu)
				goto invalid;

			rc = handle_rx_rspro(conn, pdu);
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
	msgb_free(msg);
	return -1;
}

static int sock_closed_cb(struct ipa_server_conn *peer)
{
	struct rspro_client_conn *conn = peer->data;
	if (conn->fi)
		osmo_fsm_inst_dispatch(conn->fi, CLNTC_E_TCP_DOWN, NULL);
	/* FIXME: who cleans up conn? */
	/* ipa server code relases 'peer' just after this */
	return 0;
}

static const struct ipa_keepalive_params ka_params = {
	.interval = 30,
	.wait_for_resp = 10,
};

/* a new TCP connection was accepted on the RSPRO server socket */
static int accept_cb(struct ipa_server_link *link, int fd)
{
	struct rspro_server *srv = link->data;
	struct rspro_client_conn *conn;

	conn = talloc_zero(srv, struct rspro_client_conn);
	OSMO_ASSERT(conn);

	conn->srv = srv;
	/* don't allocate peer under 'conn', as it must survive 'conn' during teardown */
	conn->peer = ipa_server_conn_create(link, link, fd, sock_read_cb, sock_closed_cb, conn);
	if (!conn->peer)
		goto out_err;

	/* don't allocate 'fi' as slave from 'conn', as 'fi' needs to survive 'conn' during
	 * teardown */
	conn->fi = server_client_fsm_alloc(srv, conn);
	if (!conn->fi)
		goto out_err_conn;

	/* use ipa_keepalive_fsm to periodically send an IPA_PING and expect a PONG in response */
	conn->keepalive_fi = ipa_server_conn_alloc_keepalive_fsm(conn->peer, &ka_params, NULL);
	if (!conn->keepalive_fi)
		goto out_err_fi;
	/* ensure parent is notified once keepalive FSM instance is dying */
	osmo_fsm_inst_change_parent(conn->keepalive_fi, conn->fi, CLNTC_E_KA_TIMEOUT);
	ipa_keepalive_fsm_start(conn->keepalive_fi);

	INIT_LLIST_HEAD(&conn->bank.maps_new);
	INIT_LLIST_HEAD(&conn->bank.maps_unack);
	INIT_LLIST_HEAD(&conn->bank.maps_active);
	INIT_LLIST_HEAD(&conn->bank.maps_delreq);
	INIT_LLIST_HEAD(&conn->bank.maps_deleting);

	pthread_rwlock_wrlock(&conn->srv->rwlock);
	llist_add_tail(&conn->list, &srv->connections);
	pthread_rwlock_unlock(&conn->srv->rwlock);

	osmo_fsm_inst_dispatch(conn->fi, CLNTC_E_TCP_UP, NULL);
	return 0;

out_err_fi:
	osmo_fsm_inst_term(conn->fi, OSMO_FSM_TERM_ERROR, NULL);
out_err_conn:
	ipa_server_conn_destroy(conn->peer);
	/* the above will free 'conn' down the chain */
	return -1;
out_err:
	talloc_free(conn);
	return -1;
}

/* call-back if we were triggered by a rest_api thread */
int event_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct rspro_server *srv = ofd->data;
	struct rspro_client_conn *conn;
	bool non_empty_new, non_empty_del;
	uint64_t value;
	int rc;

	/* read from the socket to "confirm" the event and make it non-readable again */
	rc = read(ofd->fd, &value, 8);
	if (rc < 8) {
		fprintf(stderr, "Error reading eventfd: %d\n", rc);
		return rc;
	}

	printf("rspro_server: Event FD arrived, checking for any pending work\n");

	pthread_rwlock_rdlock(&srv->rwlock);
	llist_for_each_entry(conn, &srv->banks, list) {
		slotmaps_rdlock(srv->slotmaps);
		non_empty_new = llist_empty(&conn->bank.maps_new);
		non_empty_del = llist_empty(&conn->bank.maps_delreq);
		slotmaps_unlock(srv->slotmaps);

		/* trigger FSM to send any pending new/deleted maps */
		if (non_empty_new || non_empty_del)
			osmo_fsm_inst_dispatch(conn->fi, CLNTC_E_PUSH, NULL);
	}
	pthread_rwlock_unlock(&srv->rwlock);

	return 0;
}

/* unlink all slotmaps from any of the lists of this conn->bank.maps_* */
static void _unlink_all_slotmaps(struct rspro_client_conn *conn)
{
	struct slot_mapping *smap, *smap2;

	llist_for_each_entry_safe(smap, smap2, &conn->bank.maps_new, bank_list) {
		/* unlink from list and keep in state NEW */
		_slotmap_state_change(smap, SLMAP_S_NEW, NULL);
	}
	llist_for_each_entry_safe(smap, smap2, &conn->bank.maps_unack, bank_list) {
		/* unlink from list and change to state NEW */
		_slotmap_state_change(smap, SLMAP_S_NEW, NULL);
	}
	llist_for_each_entry_safe(smap, smap2, &conn->bank.maps_active, bank_list) {
		/* unlink from list and change to state NEW */
		_slotmap_state_change(smap, SLMAP_S_NEW, NULL);
	}
	llist_for_each_entry_safe(smap, smap2, &conn->bank.maps_delreq, bank_list) {
		/* unlink from list and delete */
		_slotmap_del(smap->maps, smap);
	}
	llist_for_each_entry_safe(smap, smap2, &conn->bank.maps_deleting, bank_list) {
		/* unlink from list and delete */
		_slotmap_del(smap->maps, smap);
	}
}

/* only to be used by the FSM cleanup. */
static void rspro_client_conn_destroy(struct rspro_client_conn *conn)
{
	/* this will internally call closed_cb() which will dispatch a TCP_DOWN event */
	ipa_server_conn_destroy(conn->peer);
	conn->peer = NULL;

	/* ensure all slotmaps are unlinked + returned to NEW or deleted */
	slotmaps_wrlock(conn->srv->slotmaps);
	_unlink_all_slotmaps(conn);
	slotmaps_unlock(conn->srv->slotmaps);

	pthread_rwlock_wrlock(&conn->srv->rwlock);
	llist_del(&conn->list);
	pthread_rwlock_unlock(&conn->srv->rwlock);

	talloc_free(conn);
}


struct rspro_server *rspro_server_create(void *ctx, const char *host, uint16_t port)

{
	struct rspro_server *srv = talloc_zero(ctx, struct rspro_server);
	OSMO_ASSERT(srv);

	pthread_rwlock_init(&srv->rwlock, NULL);
	pthread_rwlock_wrlock(&srv->rwlock);
	INIT_LLIST_HEAD(&srv->connections);
	INIT_LLIST_HEAD(&srv->clients);
	INIT_LLIST_HEAD(&srv->banks);
	pthread_rwlock_unlock(&srv->rwlock);

	srv->link = ipa_server_link_create(ctx, NULL, host, port, accept_cb, srv);
	ipa_server_link_open(srv->link);

	return srv;
}

void rspro_server_destroy(struct rspro_server *srv)
{
	/* FIXME: clear all lists */

	ipa_server_link_destroy(srv->link);
	srv->link = NULL;
	talloc_free(srv);
}
