#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <pthread.h>

#include <wintypes.h>
#include <winscard.h>
#include <pcsclite.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/linuxlist.h>

#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>

#include <asn1c/asn_application.h>
#include <osmocom/rspro/RsproPDU.h>

#include "bankd.h"

__thread void *talloc_asn1_ctx;

static void *worker_main(void *arg);

/***********************************************************************
* bankd core / main thread
***********************************************************************/

static void bankd_init(struct bankd *bankd)
{
	/* intialize members of 'bankd' */
	INIT_LLIST_HEAD(&bankd->slot_mappings);
	pthread_rwlock_init(&bankd->slot_mappings_rwlock, NULL);
	INIT_LLIST_HEAD(&bankd->workers);
	pthread_mutex_init(&bankd->workers_mutex, NULL);
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

int main(int argc, char **argv)
{
	struct bankd *bankd = talloc_zero(NULL, struct bankd);
	int i, rc;

	OSMO_ASSERT(bankd);
	bankd_init(bankd);

	/* create listening socket */
	rc = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 9999, OSMO_SOCK_F_BIND);
	if (rc < 0)
		exit(1);
	bankd->accept_fd = rc;

	/* create worker threads.  FIXME: one per reader/slot! */
	for (i = 0; i < 10; i++) {
		struct bankd_worker *w;
		w = bankd_create_worker(bankd, i);
		if (!w)
			exit(21);
	}

	while (1) {
		if (terminate)
			break;
	}

	talloc_free(bankd);
	exit(0);
}



/***********************************************************************
 * bankd worker thread
 ***********************************************************************/

#define PCSC_ERROR(rv, text) \
if (rv != SCARD_S_SUCCESS) { \
	fprintf(stderr, text ": %s (0x%lX)\n", pcsc_stringify_error(rv), rv); \
	goto end; \
} else { \
        printf(text ": OK\n\n"); \
}

#define LOGW(w, fmt, args...) \
	printf("[%u] " fmt, (w)->num, args)

struct value_string worker_state_names[] = {
	{ BW_ST_INIT, 			"INIT" },
	{ BW_ST_ACCEPTING,		"ACCEPTING" },
	{ BW_ST_CONN_WAIT_ID,		"CONN_WAIT_ID" },
	{ BW_ST_CONN_CLIENT,		"CONN_CLIENT" },
	{ BW_ST_CONN_CLIENT_MAPPED,	"CONN_CLIENT_MAPPED" },
	{ BW_ST_CONN_CLIENT_MAPPED_CARD,"CONN_CLIENT_MAPPED_CARD" },
	{ 0, NULL }
};

static void worker_set_state(struct bankd_worker *worker, enum bankd_worker_state new_state)
{
	LOGW(worker, "Changing state to %s\n", get_value_string(worker_state_names, new_state));
	worker->state = new_state;
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


#if 0
/* function running inside a worker thread; doing some initialization */
static void worker_init(struct bankd_worker *worker)
{
	int rc;

	/* push cleanup helper */
	pthread_cleanup_push(&worker_cleanup, worker);

	/* The PC/SC context must be created inside the thread where we'll later use it */
	rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &worker->reader.pcsc.hContext);
	PCSC_ERROR(rc, "SCardEstablishContext")

	rc = SCardConnect(worker->reader.pcsc.hContext, worker->reader.name, SCARD_SHARE_SHARED,
			  SCARD_PROTOCOL_T0, &worker->reader.pcsc.hCard, NULL);
	PCSC_ERROR(rc, "SCardConnect")

	return;
end:
	pthread_exit(NULL);
}
#endif


static int blocking_ipa_read(int fd, uint8_t *buf, unsigned int buf_size)
{
	struct ipaccess_head *hh;
	uint16_t len;
	int needed, rc;

	if (buf_size < sizeof(*hh))
		return -1;

	hh = (struct ipaccess_head *) buf;

	/* 1) blocking read from the socket (IPA header) */
	rc = read(fd, buf, sizeof(*hh));
	if (rc < sizeof(*hh))
		return -2;

	len = ntohs(hh->len);
	needed = len; //- sizeof(*hh);

	/* 2) blocking read from the socket (payload) */
	rc = read(fd, buf+sizeof(*hh), needed);
	if (rc < needed)
		return -3;

	return len;
}

/* handle one incoming RSPRO message from a client inside a worker thread */
static int worker_handle_rspro(struct bankd_worker *worker, const RsproPDU_t *pdu)
{
	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectClientReq:
		/* FIXME */
		break;
	case RsproPDUchoice_PR_tpduModemToCard:
		/* FIXME */
		break;
	case RsproPDUchoice_PR_clientSlotStatusInd:
		/* FIXME */
		break;
	default:
		return -100;
	}

	return 0;
}

/* body of the main transceive loop */
static int worker_transceive_loop(struct bankd_worker *worker)
{
	struct ipaccess_head *hh;
	struct ipaccess_head_ext *hh_ext;
	uint8_t buf[65536]; /* maximum length expressed in 16bit length field */
	asn_dec_rval_t rval;
	int data_len, rc;
	RsproPDU_t *pdu;

	/* 1) blocking read of entire IPA message from the socket */
	rc = blocking_ipa_read(worker->client.fd, buf, sizeof(buf));
	if (rc < 0)
		return rc;
	data_len = rc;

	hh = (struct ipaccess_head *) buf;
	if (hh->proto != IPAC_PROTO_OSMO)
		return -4;

	hh_ext = (struct ipaccess_head_ext *) buf + sizeof(*hh);
	if (data_len < sizeof(*hh_ext))
		return -5;
	data_len -= sizeof(*hh_ext);
	if (hh_ext->proto != IPAC_PROTO_EXT_RSPRO)
		return -6;

	/* 2) ASN1 BER decode of the message */
	rval = ber_decode(NULL, &asn_DEF_RsproPDU, (void **) &pdu, hh_ext->data, data_len);
	if (rval.code != RC_OK)
		return -7;

	/* 3) handling of the message, possibly resulting in PCSC commands */
	rc = worker_handle_rspro(worker, pdu);
	ASN_STRUCT_FREE(asn_DEF_RsproPDU, pdu);
	if (rc < 0)
		return rc;

	/* everything OK if we reach here */
	return 0;
}

/* worker thread main function */
static void *worker_main(void *arg)
{
	struct bankd_worker *worker = (struct bankd_worker *) arg;
	void *top_ctx;
	int rc;

	worker_set_state(worker, BW_ST_INIT);

	/* not permitted in multithreaded environment */
	talloc_disable_null_tracking();
	top_ctx = talloc_named_const(NULL, 0, "top");
	talloc_asn1_ctx = talloc_named_const(top_ctx, 0, "asn1");

	/* push cleanup helper */
	pthread_cleanup_push(&worker_cleanup, worker);

	/* we continuously perform the same loop here, recycling the worker thread
	 * once the client connection is gone or we have some trouble with the card/reader */
	while (1) {
		worker->client.peer_addr_len = sizeof(worker->client.peer_addr);

		worker_set_state(worker, BW_ST_ACCEPTING);
		/* first wait for an incoming TCP connection */
		rc = accept(worker->bankd->accept_fd, (struct sockaddr *) &worker->client.peer_addr,
			    &worker->client.peer_addr_len);
		if (rc < 0) {
			continue;
		}
		worker->client.fd = rc;
		worker_set_state(worker, BW_ST_CONN_WAIT_ID);

		/* run the main worker transceive loop body until there was some error */
		while (1) {
			rc = worker_transceive_loop(worker);
			if (rc < 0)
				break;
		}

		/* clean-up: reset to sane state */
		if (worker->reader.pcsc.hCard) {
			SCardDisconnect(worker->reader.pcsc.hCard, SCARD_UNPOWER_CARD);
			worker->reader.pcsc.hCard = 0;
		}
		if (worker->reader.pcsc.hContext) {
			SCardReleaseContext(worker->reader.pcsc.hContext);
			worker->reader.pcsc.hContext = 0;
		}
		if (worker->client.fd >= 0)
			close(worker->client.fd);
		worker->client.fd = -1;
	}

	pthread_cleanup_pop(1);
	talloc_free(top_ctx);
	pthread_exit(NULL);
}
