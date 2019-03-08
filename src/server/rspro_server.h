#pragma once
#include <pthread.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/fsm.h>
#include <osmocom/abis/ipa.h>

#include "rspro_util.h"
#include "slotmap.h"

struct rspro_server {
	struct ipa_server_link *link;
	/* list of rspro_client_conn */
	struct llist_head connections;
	struct llist_head clients;
	struct llist_head banks;
	/* rwlock protecting any of the lists above */
	pthread_rwlock_t rwlock;

	struct slotmaps *slotmaps;

	/* our own (server) component identity */
	struct app_comp_id comp_id;
};

/* representing a single client connection to an RSPRO server */
struct rspro_client_conn {
	/* global list of connections */
	struct llist_head list;
	/* back-pointer to rspro_server */
	struct rspro_server *srv;
	/* reference to the underlying IPA server connection */
	struct ipa_server_conn *peer;
	/* FSM instance for this connection */
	struct osmo_fsm_inst *fi;
	/* remote component identity (after it has been received) */
	struct app_comp_id comp_id;
	/* keep-alive handling FSM */
	struct osmo_fsm_inst *keepalive_fi;

	struct {
		struct llist_head maps_new;
		struct llist_head maps_unack;
		struct llist_head maps_active;
		struct llist_head maps_delreq;
		struct llist_head maps_deleting;
		uint16_t bank_id;
		uint16_t num_slots;
	} bank;
	struct {
		struct client_slot slot;
	} client;
};

struct rspro_server *rspro_server_create(void *ctx, const char *host, uint16_t port);
void rspro_server_destroy(struct rspro_server *srv);
int event_fd_cb(struct osmo_fd *ofd, unsigned int what);

struct rspro_client_conn *_bankd_conn_by_id(struct rspro_server *srv, uint16_t bank_id);
struct rspro_client_conn *bankd_conn_by_id(struct rspro_server *srv, uint16_t bank_id);
