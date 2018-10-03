#pragma once

#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <pthread.h>

#include <wintypes.h>
#include <winscard.h>

#include <osmocom/core/linuxlist.h>

#include "rspro_util.h"

enum {
	DMAIN,
};

struct bankd;

struct bank_slot {
	uint16_t bank_id;
	uint16_t slot_nr;
};

static inline bool bank_slot_equals(const struct bank_slot *a, const struct bank_slot *b)
{
	if (a->bank_id == b->bank_id && a->slot_nr == b->slot_nr)
		return true;
	else
		return false;
}

struct client_slot {
	uint16_t client_id;
	uint16_t slot_nr;
};

static inline bool client_slot_equals(const struct client_slot *a, const struct client_slot *b)
{
	if (a->client_id == b->client_id && a->slot_nr == b->slot_nr)
		return true;
	else
		return false;
}

/* slot mappings are created / removed by the server */
struct bankd_slot_mapping {
	/* global lits of bankd slot mappings */
	struct llist_head list;
	/* slot on bank side */
	struct bank_slot bank;
	/* slot on client side */
	struct client_slot client;
};

/* thread-safe lookup of map by client:slot */
struct bankd_slot_mapping *bankd_slotmap_by_client(struct bankd *bankd,
						   const struct client_slot *client);

/* thread-safe lookup of map by bank:slot */
struct bankd_slot_mapping *bankd_slotmap_by_bank(struct bankd *bankd, const struct bank_slot *bank);

/* thread-safe creating of a new bank<->client map */
int bankd_slotmap_add(struct bankd *bankd, const struct bank_slot *bank,
		      const struct client_slot *client);

/* thread-safe removal of a bank<->client map */
void bankd_slotmap_del(struct bankd *bankd, struct bankd_slot_mapping *map);

enum bankd_worker_state {
	/* just started*/
	BW_ST_INIT,
	/* blocking in the accept() call on the server socket fd */
	BW_ST_ACCEPTING,
	/* TCP established, but peer not yet identified itself */
	BW_ST_CONN_WAIT_ID,
	/* TCP established, client has identified itself, no mapping */
	BW_ST_CONN_CLIENT,
	/* TCP established, client has identified itself, waiting for mapping */
	BW_ST_CONN_CLIENT_WAIT_MAP,
	/* TCP established, client has identified itself, mapping exists */
	BW_ST_CONN_CLIENT_MAPPED,
	/* TCP established, client identified, mapping exists, card opened */
	BW_ST_CONN_CLIENT_MAPPED_CARD,
};


/* bankd worker instance; one per card/slot, includes thread */
struct bankd_worker {
	/* global list of workers */
	struct llist_head list;
	/* back-pointer to bankd */
	struct bankd *bankd;

	/* thread number */
	unsigned int num;
	/* worker thread state */
	enum bankd_worker_state state;
	/* timeout to use for blocking read */
	unsigned int timeout;

	/* slot number we are representing */
	struct bank_slot slot;

	/* thread of this worker. */
	pthread_t thread;

	/* File descriptor of the TCP connection to the remsim-client (modem) */
	struct {
		int fd;
		struct sockaddr_storage peer_addr;
		socklen_t peer_addr_len;
		struct client_slot clslot;
	} client;

	struct {
		const char *name;
		union {
			struct {
				/* PC/SC context / application handle */
				SCARDCONTEXT hContext;
				/* PC/SC card handle */
				SCARDHANDLE hCard;
			} pcsc;
		};
	} reader;
};


/* global bank deamon */
struct bankd {
	struct {
		uint16_t bank_id;
	} cfg;

	struct app_comp_id comp_id;

	/* TCP socket at which we are listening */
	int accept_fd;

	/* list of slit mappings. only ever modified in main thread! */
	struct llist_head slot_mappings;
	pthread_rwlock_t slot_mappings_rwlock;

	/* list of bankd_workers. accessed/modified by multiple threads; protected by mutex */
	struct llist_head workers;
	pthread_mutex_t workers_mutex;

	struct llist_head pcsc_slot_names;
};

int bankd_pcsc_read_slotnames(struct bankd *bankd, const char *csv_file);
const char *bankd_pcsc_get_slot_name(struct bankd *bankd, const struct bank_slot *slot);
