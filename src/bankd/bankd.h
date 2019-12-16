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
#include "slotmap.h"
#include "rspro_client_fsm.h"
#include "debug.h"

extern struct value_string worker_state_names[];

#define LOGW(w, fmt, args...) \
	printf("[%03u %s] %s:%u " fmt, (w)->num, get_value_string(worker_state_names, (w)->state), \
		__FILE__, __LINE__, ## args)

struct bankd;

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
	/* TCP established, client identified, but mapping [meanwhile] removed */
	BW_ST_CONN_CLIENT_UNMAPPED
};


/* bankd worker instance; one per card/slot, includes thread */
struct bankd_worker {
	/* global list of workers */
	struct llist_head list;
	/* back-pointer to bankd */
	struct bankd *bankd;

	/* name of the worker */
	char *name;

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
	/* top talloc context for this worker/thread */
	void *tall_ctx;

	const struct bankd_driver_ops *ops;

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

	struct {
		uint8_t atr[MAX_ATR_SIZE];
		unsigned int atr_len;
	} card;
};

/* bankd card reader driver operations */
struct bankd_driver_ops {
	/* open a given card/slot: called once client + mapping exists */
	int (*open_card)(struct bankd_worker *worker);
	/* reset a given card/slot with either cold or warm reset */
	int (*reset_card)(struct bankd_worker *worker, bool cold_reset);
	int (*transceive)(struct bankd_worker *worker, const uint8_t *out, size_t out_len,
			  uint8_t *in, size_t *in_len);
	/* called at cleanup time of a worker thread: clear any driver related state */
	void (*cleanup)(struct bankd_worker *worker);
};

/* global bank deamon */
struct bankd {
	struct app_comp_id comp_id;
	/* RSPRO connection to the remsim-server */
	struct rspro_server_conn srvc;

	/* TCP socket at which we are listening */
	int accept_fd;

	/* list of slot mappings. only ever modified in main thread! */
	struct slotmaps *slotmaps;

	/* pthread ID of main thread */
	pthread_t main;

	/* list of bankd_workers. accessed/modified by multiple threads; protected by mutex */
	struct llist_head workers;
	pthread_mutex_t workers_mutex;

	struct llist_head pcsc_slot_names;
};

int bankd_pcsc_read_slotnames(struct bankd *bankd, const char *csv_file);
const char *bankd_pcsc_get_slot_name(struct bankd *bankd, const struct bank_slot *slot);

extern const struct bankd_driver_ops pcsc_driver_ops;
