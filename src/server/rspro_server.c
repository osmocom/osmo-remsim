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

static void client_slot2rspro(ClientSlot_t *out, const struct client_slot *in)
{
	out->clientId = in->client_id;
	out->slotNr = in->slot_nr;
}

static void rspro2client_slot(struct client_slot *out, const ClientSlot_t *in)
{
	out->client_id = in->clientId;
	out->slot_nr = in->slotNr;
}

static void bank_slot2rspro(BankSlot_t *out, const struct bank_slot *in)
{
	out->bankId = in->bank_id;
	out->slotNr = in->slot_nr;
}

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
	struct msgb *msg_tx = rspro_enc_msg(pdu);
	if (!msg_tx) {
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
	CLNTC_ST_CONNECTED,
};

enum remsim_server_client_event {
	CLNTC_E_TCP_UP,
	CLNTC_E_CLIENT_CONN,	/* Connect{Client,Bank}Req received */
	CLNTC_E_BANK_CONN,
	CLNTC_E_TCP_DOWN,
	CLNTC_E_CREATE_MAP_RES,	/* CreateMappingRes received */
	CLNTC_E_REMOVE_MAP_RES,	/* RemoveMappingRes received */
	CLNTC_E_CONFIG_CL_RES,	/* ConfigClientRes received */
	CLNTC_E_PUSH,		/* drain maps_new or maps_delreq */
};

static const struct value_string server_client_event_names[] = {
	OSMO_VALUE_STRING(CLNTC_E_TCP_UP),
	OSMO_VALUE_STRING(CLNTC_E_CLIENT_CONN),
	OSMO_VALUE_STRING(CLNTC_E_BANK_CONN),
	OSMO_VALUE_STRING(CLNTC_E_TCP_DOWN),
	OSMO_VALUE_STRING(CLNTC_E_CREATE_MAP_RES),
	OSMO_VALUE_STRING(CLNTC_E_REMOVE_MAP_RES),
	OSMO_VALUE_STRING(CLNTC_E_CONFIG_CL_RES),
	OSMO_VALUE_STRING(CLNTC_E_PUSH),
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
			resp = rspro_gen_ConnectClientRes(&conn->srv->comp_id, ResultCode_ok);
			client_conn_send(conn, resp);
			osmo_fsm_inst_state_chg(fi, CLNTC_ST_CONNECTED, 0, 0);
		}

		/* reparent us from srv->connections to srv->clients */
		pthread_rwlock_wrlock(&conn->srv->rwlock);
		llist_del(&conn->list);
		llist_add_tail(&conn->list, &conn->srv->clients);
		pthread_rwlock_unlock(&conn->srv->rwlock);
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

		/* reparent us from srv->connections to srv->banks */
		pthread_rwlock_wrlock(&conn->srv->rwlock);
		llist_del(&conn->list);
		llist_add_tail(&conn->list, &conn->srv->banks);
		pthread_rwlock_unlock(&conn->srv->rwlock);

		/* send response to bank first */
		resp = rspro_gen_ConnectBankRes(&conn->srv->comp_id, ResultCode_ok);
		client_conn_send(conn, resp);

		/* the state change will associate any pre-existing slotmaps */
		osmo_fsm_inst_state_chg(fi, CLNTC_ST_CONNECTED, 0, 0);

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
		osmo_fsm_inst_state_chg(fi, CLNTC_ST_CONNECTED, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void clnt_st_connected_cl_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
#if 0
	struct rspro_client_conn *conn = fi->priv;
	ClientSlot_t clslot;
	RsproPDU_t *pdu;

	/* send configuration to this new client */
	client_slot2rspro(&clslot, FIXME);
	pdu = rspro_gen_ConfigClientReq(&clslot, bankd_ip, bankd_port);
	client_conn_send(conn, pdu);
#endif
}

static void clnt_st_connected_bk_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
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

static void clnt_st_connected_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rspro_client_conn *conn = fi->priv;
	switch (conn->comp_id.type) {
	case ComponentType_remsimClient:
		clnt_st_connected_cl_onenter(fi, prev_state);
		break;
	case ComponentType_remsimBankd:
		clnt_st_connected_bk_onenter(fi, prev_state);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void clnt_st_connected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct rspro_client_conn *conn = fi->priv;
	struct slotmaps *slotmaps = conn->srv->slotmaps;
	const struct RsproPDU_t *rx = NULL;
	struct slot_mapping *map, *map2;

	switch (event) {
	case CLNTC_E_CREATE_MAP_RES:
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
		break;
	case CLNTC_E_REMOVE_MAP_RES:
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
		break;
	case CLNTC_E_PUSH:
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
	struct rspro_client_conn *conn = fi->priv;

	switch (event) {
	case CLNTC_E_TCP_DOWN:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int server_client_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct rspro_client_conn *conn = fi->priv;

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
		.out_state_mask = S(CLNTC_ST_CONNECTED) | S(CLNTC_ST_WAIT_CONF_RES),
		.action = clnt_st_established,
	},
	[CLNTC_ST_WAIT_CONF_RES] = {
		.name = "WAIT_CONFIG_RES",
		.in_event_mask = S(CLNTC_E_CONFIG_CL_RES),
		.out_state_mask = S(CLNTC_ST_CONNECTED),
		.action = clnt_st_wait_cl_conf_res,
	},
	[CLNTC_ST_CONNECTED] = {
		.name = "CONNECTED",
		.in_event_mask = S(CLNTC_E_CREATE_MAP_RES) | S(CLNTC_E_REMOVE_MAP_RES) |
				 S(CLNTC_E_PUSH),
		.action = clnt_st_connected,
		.onenter = clnt_st_connected_onenter,
	},
};

static struct osmo_fsm remsim_server_client_fsm = {
	.name = "SERVER_CONN",
	.states = server_client_fsm_states,
	.num_states = ARRAY_SIZE(server_client_fsm_states),
	.allstate_event_mask = S(CLNTC_E_TCP_DOWN),
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
	case RsproPDUchoice_PR_configClientRes:
		osmo_fsm_inst_dispatch(conn->fi, CLNTC_E_CONFIG_CL_RES, (void *)pdu);
		break;
	default:
		LOGPFSML(conn->fi, LOGL_ERROR, "Received unknown/unimplemented RSPRO msg_type %d\n",
			 pdu->msg.present);
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
