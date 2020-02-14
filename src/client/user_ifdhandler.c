/* (C) 2020 by Harald Welte <laforge@gnumonks.org>
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

/* This is a remsim-client that provides an IFD_Handler (reader driver)
 * towards the PC/SC services.  This effectively allows any local PC/SC client
 * application to use a remote smartcard via osmo-remsim.
 *
 * In order to use this, you will need an /etc/reader.conf.d/osmo-remsim-client
 * file with the following content:
 *
 * 	FRIENDLYNAME "osmo-remsim-client"
 * 	DEVICENAME   0:0:192.168.11.10:9998
 *	LIBPATH      /usr/lib/pcsc/drivers/serial/libifd_remsim_client.so
 *
 * Where  DEVICENAME has the following format:
 * 	[ClientID:[SlotNr:[ServerIp:[ServerPort]]]]
 *
 */

#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
extern int osmo_ctx_init(const char *id);

#include "client.h"

/* ensure this current thread has an osmo_ctx and hence can use OTC_GLOBAL and friends */
static void ensure_osmo_ctx(void)
{
	if (!osmo_ctx)
		osmo_ctx_init("");
}

/* inter-thread messages between IFD thread and remsim-client thread */
enum itmsg_type {
	ITMSG_TYPE_NONE,

	/* card present? */
	ITMSG_TYPE_CARD_PRES_REQ,
	ITMSG_TYPE_CARD_PRES_RESP,

	/* obtain ATR */
	ITMSG_TYPE_ATR_REQ,
	ITMSG_TYPE_ATR_RESP,

	/* transceive APDU: Send C-APDU, receive R-APDU */
	ITMSG_TYPE_C_APDU_REQ,
	ITMSG_TYPE_R_APDU_IND,

	/* power off the card */
	ITMSG_TYPE_POWER_OFF_REQ,
	ITMSG_TYPE_POWER_OFF_RESP,

	/* power on the card */
	ITMSG_TYPE_POWER_ON_REQ,
	ITMSG_TYPE_POWER_ON_RESP,

	/* reset the card */
	ITMSG_TYPE_RESET_REQ,
	ITMSG_TYPE_RESET_RESP,
};

struct itmsg {
	enum itmsg_type type;
	uint16_t status;	/* 0 == success */
	uint16_t len;		/* length of 'data' */
	uint8_t data[0];
};

/* allocate + initialize msgb-wrapped inter-thread message (struct itmsg) */
struct msgb *itmsg_alloc(enum itmsg_type type, uint16_t status, const uint8_t *data, uint16_t len)
{
	struct msgb *msg = msgb_alloc_c(OTC_GLOBAL, sizeof(struct itmsg)+len, "Tx itmsg");
	struct itmsg *im;

	if (!msg)
		return NULL;

	im = (struct itmsg *) msgb_put(msg, sizeof(struct itmsg) + len);
	im->type = type;
	im->status = status;
	im->len = len;
	if (len)
		memcpy(im->data, data, len);

	return msg;
}

/***********************************************************************
 * remsim_client thread
 ***********************************************************************/

void __thread *talloc_asn1_ctx;

struct client_thread {
	/* bankd client runningi inside this thread */
	struct bankd_client *bc;

	/* inter-thread osmo-fd; communication with IFD/PCSC thread */
	struct osmo_fd it_ofd;
	struct llist_head it_msgq;

	/* ATR as received from remsim-bankd */
	uint8_t atr[ATR_SIZE_MAX];
	uint8_t atr_len;
};

/* configuration of client thread; passed in from IFD thread */
struct client_thread_cfg {
	const char *name;
	const char *server_host;
	int server_port;
	int client_id;
	int client_slot;
	int it_sock_fd;
};

/* enqueue a msgb (containg 'struct itmsg') towards the IFD-handler thread */
static void enqueue_to_ifd(struct client_thread *ct, struct msgb *msg)
{
	if (!msg)
		return;

	msgb_enqueue(&ct->it_msgq, msg);
	ct->it_ofd.when |= OSMO_FD_WRITE;
}

/***********************************************************************
 * Incoming RSPRO messages from bank-daemon (SIM card)
 ***********************************************************************/

static int bankd_handle_tpduCardToModem(struct bankd_client *bc, const RsproPDU_t *pdu)
{
	const struct TpduCardToModem *card2modem;
	struct client_thread *ct = bc->data;
	struct msgb *msg;

	OSMO_ASSERT(pdu);
	OSMO_ASSERT(RsproPDUchoice_PR_tpduCardToModem == pdu->msg.present);

	card2modem = &pdu->msg.choice.tpduCardToModem;
	DEBUGP(DMAIN, "R-APDU: %s\n", osmo_hexdump(card2modem->data.buf, card2modem->data.size));
	/* enqueue towards IFD thread */
	msg = itmsg_alloc(ITMSG_TYPE_R_APDU_IND, 0, card2modem->data.buf, card2modem->data.size);
	OSMO_ASSERT(msg);
	enqueue_to_ifd(ct, msg);

	return 0;
}

static int bankd_handle_setAtrReq(struct bankd_client *bc, const RsproPDU_t *pdu)
{
	struct client_thread *ct = bc->data;
	RsproPDU_t *resp;
	unsigned int atr_len;

	OSMO_ASSERT(pdu);
	OSMO_ASSERT(RsproPDUchoice_PR_setAtrReq == pdu->msg.present);

	DEBUGP(DMAIN, "SET_ATR: %s\n", osmo_hexdump(pdu->msg.choice.setAtrReq.atr.buf,
						     pdu->msg.choice.setAtrReq.atr.size));

	/* store ATR in local data structure until somebody needs it */
	atr_len = pdu->msg.choice.setAtrReq.atr.size;
	if (atr_len > sizeof(ct->atr))
		atr_len = sizeof(ct->atr);
	memcpy(ct->atr, pdu->msg.choice.setAtrReq.atr.buf, atr_len);
	ct->atr_len = atr_len;

	resp = rspro_gen_SetAtrRes(ResultCode_ok);
	if (!resp)
		return -ENOMEM;
	server_conn_send_rspro(&bc->bankd_conn, resp);

	return 0;
}


int client_user_bankd_handle_rx(struct rspro_server_conn *bankdc, const RsproPDU_t *pdu)
{
	struct bankd_client *bc = bankdc2bankd_client(bankdc);

	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_tpduCardToModem:
		bankd_handle_tpduCardToModem(bc, pdu);
		break;
	case RsproPDUchoice_PR_setAtrReq:
		bankd_handle_setAtrReq(bc, pdu);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

/***********************************************************************
 * Incoming command from the user application
 ***********************************************************************/

/* handle a single msgb-wrapped 'struct itmsg' from the IFD-handler thread */
static void handle_it_msg(struct client_thread *ct, struct itmsg *itmsg)
{
	struct bankd_client *bc = ct->bc;
	struct msgb *tx = NULL;
	RsproPDU_t *pdu;
	BankSlot_t bslot;

	bank_slot2rspro(&bslot, &ct->bc->bankd_slot);

	switch (itmsg->type) {
	case ITMSG_TYPE_CARD_PRES_REQ:
		if (bc->bankd_conn.fi->state == 2 /*SRVC_ST_CONNECTED*/)
			tx = itmsg_alloc(ITMSG_TYPE_CARD_PRES_RESP, 0, NULL, 0);
		else
			tx = itmsg_alloc(ITMSG_TYPE_CARD_PRES_RESP, 0xffff, NULL, 0);
		OSMO_ASSERT(tx);
		break;

	case ITMSG_TYPE_ATR_REQ:
		/* respond to IFD */
		tx = itmsg_alloc(ITMSG_TYPE_ATR_RESP, 0, ct->atr, ct->atr_len);
		OSMO_ASSERT(tx);
		break;

	case ITMSG_TYPE_POWER_OFF_REQ:
		pdu = rspro_gen_ClientSlotStatusInd(bc->srv_conn.clslot, &bslot,
						    true, false, false, true);
		server_conn_send_rspro(&bc->bankd_conn, pdu);
		/* respond to IFD */
		tx = itmsg_alloc(ITMSG_TYPE_POWER_OFF_RESP, 0, NULL, 0);
		OSMO_ASSERT(tx);
		break;

	case ITMSG_TYPE_POWER_ON_REQ:
		pdu = rspro_gen_ClientSlotStatusInd(bc->srv_conn.clslot, &bslot,
						    false, true, true, true);
		server_conn_send_rspro(&bc->bankd_conn, pdu);
		/* respond to IFD */
		tx = itmsg_alloc(ITMSG_TYPE_POWER_ON_RESP, 0, NULL, 0);
		OSMO_ASSERT(tx);
		break;

	case ITMSG_TYPE_RESET_REQ:
		/* reset the [remote] card */
		pdu = rspro_gen_ClientSlotStatusInd(bc->srv_conn.clslot, &bslot,
						    true, true, true, true);
		server_conn_send_rspro(&bc->bankd_conn, pdu);
		/* and take it out of reset again */
		pdu = rspro_gen_ClientSlotStatusInd(bc->srv_conn.clslot, &bslot,
						    false, true, true, true);
		server_conn_send_rspro(&bc->bankd_conn, pdu);
		/* respond to IFD */
		tx = itmsg_alloc(ITMSG_TYPE_RESET_RESP, 0, NULL, 0);
		OSMO_ASSERT(tx);
		break;
	case ITMSG_TYPE_C_APDU_REQ:
		if (!bc->srv_conn.clslot) {
			LOGP(DMAIN, LOGL_ERROR, "Cannot send command; no client slot\n");
			/* FIXME: Response? */
			return;
		}

		/* Send CMD APDU to [remote] card */
		pdu = rspro_gen_TpduModem2Card(bc->srv_conn.clslot, &bslot, itmsg->data, itmsg->len);
		server_conn_send_rspro(&bc->bankd_conn, pdu);
		/* response will come in asynchronously */
		break;
	default:
		LOGP(DMAIN, LOGL_ERROR, "Unknown inter-thread msg type %u\n", itmsg->type);
		break;
	}

	if (tx)
		enqueue_to_ifd(ct, tx);

}

/* call-back function for inter-thread socket */
static int it_sock_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct client_thread *ct = ofd->data;
	int rc;

	if (what & OSMO_FD_READ) {
		struct msgb *msg = msgb_alloc_c(OTC_GLOBAL, 1024, "Rx it_fd");
		struct itmsg *itmsg;

		OSMO_ASSERT(msg);
		rc = read(ofd->fd, msg->tail, msgb_tailroom(msg));
		if (rc <= 0) {
			LOGP(DMAIN, LOGL_ERROR, "Error reading from inter-thread fd: %d\n", rc);
			pthread_exit(NULL);
		}
		msgb_put(msg, rc);
		itmsg = (struct itmsg *) msgb_data(msg);
		if (msgb_length(msg) < sizeof(*itmsg) ||
		    msgb_length(msg) < sizeof(*itmsg) + itmsg->len) {
			LOGP(DMAIN, LOGL_ERROR, "Dropping short inter-thread message\n");
		} else {
			handle_it_msg(ct, itmsg);
		}
		msgb_free(msg);
	}

	if (what & OSMO_FD_WRITE) {
		struct msgb *msg = msgb_dequeue(&ct->it_msgq);
		if (!msg) {
			/* last message: disable write events */
			ofd->when &= ~OSMO_FD_WRITE;
		} else {
			unsigned int len = msgb_length(msg);
			rc = write(ofd->fd, msgb_data(msg), len);
			msgb_free(msg);
			if (rc < len) {
				LOGP(DMAIN, LOGL_ERROR, "Short write on inter-thread fd: %d < %d\n",
				     rc, len);
			}
		}
	}


	return 0;
}

/* release all resources allocated by thread */
static void client_pthread_cleanup(void *arg)
{
	struct client_thread *ct = arg;

	LOGP(DMAIN, LOGL_INFO, "Cleaning up remsim-client thread\n");
	//FIXME remsim_client_destroy(ct->bc);
	ct->bc = NULL;
	msgb_queue_free(&ct->it_msgq);
	osmo_fd_unregister(&ct->it_ofd);
	close(ct->it_ofd.fd);
	ct->it_ofd.fd = -1;
	talloc_free(ct);
}

/* main function of remsim-client pthread */
static void *client_pthread_main(void *arg)
{
	struct client_thread_cfg *cfg = arg;
	struct client_thread *ct;
	int rc;

	osmo_select_init();
	rc = osmo_ctx_init("client");
	OSMO_ASSERT(rc == 0);

	ct = talloc_zero(OTC_GLOBAL, struct client_thread);
	OSMO_ASSERT(ct);

	if (!talloc_asn1_ctx)
	       talloc_asn1_ctx= talloc_named_const(ct, 0, "asn1");

	ct->bc = remsim_client_create(ct, cfg->name, "remsim_ifdhandler");
	OSMO_ASSERT(ct->bc);
	ct->bc->data = ct;
	remsim_client_set_clslot(ct->bc, cfg->client_id, cfg->client_slot);
	if (cfg->server_host)
		ct->bc->srv_conn.server_host = (char *) cfg->server_host;
	if (cfg->server_port >= 0)
		ct->bc->srv_conn.server_port = cfg->server_port;

	INIT_LLIST_HEAD(&ct->it_msgq);
	osmo_fd_setup(&ct->it_ofd, cfg->it_sock_fd, OSMO_FD_READ, &it_sock_fd_cb, ct, 0);
	osmo_fd_register(&ct->it_ofd);

	/* ensure we get properly cleaned up if cancelled */
	pthread_cleanup_push(client_pthread_cleanup, ct);

	osmo_fsm_inst_dispatch(ct->bc->srv_conn.fi, SRVC_E_ESTABLISH, NULL);

	while (1) {
		osmo_select_main(0);
	}

	pthread_cleanup_pop(1);
	return NULL;
}

/***********************************************************************
 * PC/SC ifd_handler API functions
 ***********************************************************************/

#include <ifdhandler.h>
#include <debuglog.h>

#include <sys/types.h>
#include <sys/socket.h>

static const struct value_string ifd_status_names[] = {
	OSMO_VALUE_STRING(IFD_SUCCESS),
	OSMO_VALUE_STRING(IFD_ERROR_TAG),
	OSMO_VALUE_STRING(IFD_ERROR_SET_FAILURE),
	OSMO_VALUE_STRING(IFD_ERROR_VALUE_READ_ONLY),
	OSMO_VALUE_STRING(IFD_ERROR_PTS_FAILURE),
	OSMO_VALUE_STRING(IFD_ERROR_NOT_SUPPORTED),
	OSMO_VALUE_STRING(IFD_PROTOCOL_NOT_SUPPORTED),
	OSMO_VALUE_STRING(IFD_ERROR_POWER_ACTION),
	OSMO_VALUE_STRING(IFD_ERROR_SWALLOW),
	OSMO_VALUE_STRING(IFD_ERROR_EJECT),
	OSMO_VALUE_STRING(IFD_ERROR_CONFISCATE),
	OSMO_VALUE_STRING(IFD_COMMUNICATION_ERROR),
	OSMO_VALUE_STRING(IFD_RESPONSE_TIMEOUT),
	OSMO_VALUE_STRING(IFD_NOT_SUPPORTED),
	OSMO_VALUE_STRING(IFD_ICC_PRESENT),
	OSMO_VALUE_STRING(IFD_ICC_NOT_PRESENT),
	OSMO_VALUE_STRING(IFD_NO_SUCH_DEVICE),
	OSMO_VALUE_STRING(IFD_ERROR_INSUFFICIENT_BUFFER),
	{ 0, NULL }
};

static const struct value_string ifd_tag_names[] = {
	OSMO_VALUE_STRING(TAG_IFD_ATR),
	OSMO_VALUE_STRING(TAG_IFD_SLOTNUM),
	OSMO_VALUE_STRING(TAG_IFD_SLOT_THREAD_SAFE),
	OSMO_VALUE_STRING(TAG_IFD_THREAD_SAFE),
	OSMO_VALUE_STRING(TAG_IFD_SLOTS_NUMBER),
	OSMO_VALUE_STRING(TAG_IFD_SIMULTANEOUS_ACCESS),
	OSMO_VALUE_STRING(TAG_IFD_POLLING_THREAD),
	OSMO_VALUE_STRING(TAG_IFD_POLLING_THREAD_KILLABLE),
	OSMO_VALUE_STRING(TAG_IFD_STOP_POLLING_THREAD),
	OSMO_VALUE_STRING(TAG_IFD_POLLING_THREAD_WITH_TIMEOUT),
	{ 0, NULL }
};

#define LOG_EXIT(Lun, r) \
	Log4(r == IFD_SUCCESS || r == IFD_ICC_NOT_PRESENT ? PCSC_LOG_DEBUG : PCSC_LOG_ERROR, \
	     "%s(0x%08lx) => %s\n", __func__, Lun, get_value_string(ifd_status_names, r))

#define LOG_EXITF(Lun, r, fmt, args...) \
	Log5(r == IFD_SUCCESS ? PCSC_LOG_DEBUG : PCSC_LOG_ERROR, \
	     "%s(0x%08lx) "fmt" => %s\n", __func__, Lun, ## args, get_value_string(ifd_status_names, r))

/* IFD side handle for a remsim-client [thread] */
struct ifd_client {
	/* the client pthread itself */
	pthread_t pthread;
	/* socket to talk to thread */
	int it_fd;
	/* configuration passed into the thread */
	struct client_thread_cfg cfg;
};

static struct msgb *ifd_xceive_client(struct ifd_client *ic, struct msgb *tx)
{
	struct msgb *rx = msgb_alloc_c(OTC_GLOBAL, 1024, "ifd_rx itmsg");
	struct itmsg *rx_it;
	int rc;

	rc = write(ic->it_fd, msgb_data(tx), msgb_length(tx));
	msgb_free(tx);
	if (rc < msgb_length(tx)) {
		Log2(PCSC_LOG_ERROR, "Short write IFD->client thread: %d\n", rc);
		msgb_free(rx);
		return NULL;
	}
	rc = read(ic->it_fd, rx->tail, msgb_tailroom(rx));
	if (rc <= 0) {
		Log2(PCSC_LOG_ERROR, "Short read IFD<-client thread: %d\n", rc);
		msgb_free(rx);
		return NULL;
	}
	msgb_put(rx, rc);
	rx_it = (struct itmsg *) msgb_data(rx);
	if (msgb_length(rx) < sizeof(*rx_it) + rx_it->len) {
		Log2(PCSC_LOG_ERROR, "Short itmsg IFD<-client thread: %d\n", msgb_length(rx));
		msgb_free(rx);
		return NULL;
	}
	return rx;
}

/* function called on IFD side to create socketpair + start remsim-client thread */
static struct ifd_client *create_ifd_client(const struct client_thread_cfg *cfg)
{
	struct ifd_client *ic = talloc_zero(OTC_GLOBAL, struct ifd_client);
	int sp[2];
	int rc;

	/* copy over configuration */
	ic->cfg = *cfg;

	/* create socket pair for communication between threads */
	rc = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp);
	if (rc != 0) {
		talloc_free(ic);
		return NULL;
	}

	ic->it_fd = sp[0];
	ic->cfg.it_sock_fd = sp[1];

	/* start the thread */
	rc = pthread_create(&ic->pthread, NULL, client_pthread_main, &ic->cfg);
	if (rc != 0) {
		Log1(PCSC_LOG_ERROR, "Error creating remsim-client pthread\n");
		close(sp[0]);
		close(sp[1]);
		talloc_free(ic);
		return NULL;
	}

	return ic;
}

/* function called on IFD side to destroy (terminate) remsim-client thread */
static void destroy_ifd_client(struct ifd_client *ic)
{
	if (!ic)
		return;

	pthread_cancel(ic->pthread);
	pthread_join(ic->pthread, NULL);
}

#define MAX_SLOTS	256
static struct ifd_client *ifd_client[MAX_SLOTS];

#define LUN2SLOT(lun) ((lun) & 0xffff)
#define LUN2RDR(lun) ((lun) >> 16)


RESPONSECODE IFDHCreateChannel(DWORD Lun, DWORD Channel)
{
	return IFD_COMMUNICATION_ERROR;
}

RESPONSECODE IFDHCreateChannelByName(DWORD Lun, LPSTR DeviceName)
{
	struct ifd_client *ic;
	struct client_thread_cfg cfg = {
		.name = "fixme-name",
		.server_host = "127.0.0.1",
		.server_port = -1,
		.client_id = 0,
		.client_slot = 0,
	};
	char *r, *client_id, *slot_nr, *host, *port;

	if (LUN2RDR(Lun) != 0)
		return IFD_NO_SUCH_DEVICE;

	if (LUN2SLOT(Lun) >= ARRAY_SIZE(ifd_client))
		return IFD_NO_SUCH_DEVICE;

	ensure_osmo_ctx();

	client_id = strtok_r(DeviceName, ":", &r);
	if (!client_id)
		goto end_parse;
	cfg.client_id = atoi(client_id);

	slot_nr = strtok_r(NULL, ":", &r);
	if (!slot_nr)
		goto end_parse;
	cfg.client_slot = atoi(slot_nr);

	host = strtok_r(NULL, ":", &r);
	if (!host)
		goto end_parse;
	cfg.server_host = strdup(host);

	port = strtok_r(NULL, ":", &r);
	cfg.server_port = atoi(port);


end_parse:
	LOGP(DMAIN, LOGL_NOTICE, "remsim-client C%d:%d bankd=%s:%d\n",
		cfg.client_id, cfg.client_slot, cfg.server_host, cfg.server_port);

	ic = create_ifd_client(&cfg);
	if (ic) {
		ifd_client[LUN2SLOT(Lun)] = ic;
		return IFD_SUCCESS;
	} else
		return IFD_COMMUNICATION_ERROR;
}

RESPONSECODE IFDHControl(DWORD Lun, DWORD dwControlCode, PUCHAR TxBuffer, DWORD TxLength,
			 PUCHAR RxBuffer, DWORD RxLength, LPDWORD pdwBytesReturned)
{
	RESPONSECODE r = IFD_COMMUNICATION_ERROR;

	ensure_osmo_ctx();

	if (LUN2RDR(Lun) != 0) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	if (LUN2SLOT(Lun) >= ARRAY_SIZE(ifd_client)) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	if (pdwBytesReturned)
		*pdwBytesReturned = 0;

	r = IFD_ERROR_NOT_SUPPORTED;
err:
	LOG_EXIT(Lun, r);
	return r;
}

RESPONSECODE IFDHCloseChannel(DWORD Lun)
{
	RESPONSECODE r = IFD_COMMUNICATION_ERROR;

	ensure_osmo_ctx();

	if (LUN2RDR(Lun) != 0) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	if (LUN2SLOT(Lun) >= ARRAY_SIZE(ifd_client)) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	destroy_ifd_client(ifd_client[LUN2SLOT(Lun)]);
	ifd_client[LUN2SLOT(Lun)] = NULL;

	r = IFD_SUCCESS;
err:
	LOG_EXIT(Lun, r);
	return r;
}

RESPONSECODE IFDHGetCapabilities(DWORD Lun, DWORD Tag, PDWORD Length, PUCHAR Value)
{
	RESPONSECODE r = IFD_COMMUNICATION_ERROR;
	struct ifd_client *ic;
	struct msgb *rx, *tx;
	struct itmsg *rx_it;

	ensure_osmo_ctx();

	if (LUN2RDR(Lun) != 0) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	if (LUN2SLOT(Lun) >= ARRAY_SIZE(ifd_client)) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	ic = ifd_client[LUN2SLOT(Lun)];
	if (!ic) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	if (!Length || !Value)
		goto err;

	switch (Tag) {
	case TAG_IFD_ATR:
		/* Return the ATR and its size */
		tx = itmsg_alloc(ITMSG_TYPE_ATR_REQ, 0, NULL, 0);
		OSMO_ASSERT(tx);
		rx = ifd_xceive_client(ic, tx);
		if (!rx) {
			r = IFD_NO_SUCH_DEVICE;
			goto err;
		}
		rx_it = (struct itmsg *)msgb_data(rx);
		if (*Length > rx_it->len)
			*Length = rx_it->len;
		memcpy(Value, rx_it->data, *Length);
		msgb_free(rx);
		break;
	case TAG_IFD_SIMULTANEOUS_ACCESS:
		/* Return the number of sessions (readers) the driver
		 * can handle in Value[0]. This is used for multiple
		 * readers sharing the same driver. */
		if (*Length < 1)
			goto err;
		*Value = 1;
		*Length = 1;
		break;
	case TAG_IFD_SLOTS_NUMBER:
		/* Return the number of slots in this reader in Value[0] */
		if (*Length < 1)
			goto err;
		*Value = 1;
		*Length = 1;
		break;
	case TAG_IFD_THREAD_SAFE:
		/* If the driver supports more than one reader (see
		 * TAG_IFD_SIMULTANEOUS_ACCESS above) this tag indicates
		 * if the driver supports access to multiple readers at
		 * the same time.  */
		if (*Length < 1)
			goto err;
		*Value = 0;
		*Length = 1;
		break;
	case TAG_IFD_SLOT_THREAD_SAFE:
		/* If the reader has more than one slot (see
		 * TAG_IFD_SLOTS_NUMBER above) this tag indicates if the
		 * driver supports access to multiple slots of the same
		 * reader at the same time. */
		if (*Length < 1)
			goto err;
		*Value = 0;
		*Length = 1;
		break;
	default:
		r = IFD_ERROR_TAG;
		goto err;
	}

	r = IFD_SUCCESS;

err:
	if (r != IFD_SUCCESS && Length)
		*Length = 0;

	LOG_EXITF(Lun, r, "%s", get_value_string(ifd_tag_names, Tag));
	return r;
}

RESPONSECODE IFDHSetCapabilities(DWORD Lun, DWORD Tag, DWORD Length, PUCHAR Value)
{
	ensure_osmo_ctx();

	if (LUN2RDR(Lun) != 0)
		return IFD_NO_SUCH_DEVICE;

	if (LUN2SLOT(Lun) >= ARRAY_SIZE(ifd_client))
		return IFD_NO_SUCH_DEVICE;


	LOG_EXIT(Lun, IFD_NOT_SUPPORTED);
	return IFD_NOT_SUPPORTED;
}

RESPONSECODE IFDHSetProtocolParameters(DWORD Lun, DWORD Protocol, UCHAR Flags, UCHAR PTS1,
					UCHAR PTS2, UCHAR PTS3)
{
	ensure_osmo_ctx();

	if (LUN2RDR(Lun) != 0)
		return IFD_NO_SUCH_DEVICE;

	if (LUN2SLOT(Lun) >= ARRAY_SIZE(ifd_client))
		return IFD_NO_SUCH_DEVICE;

	LOG_EXIT(Lun, IFD_SUCCESS);
	return IFD_SUCCESS;
}

RESPONSECODE IFDHPowerICC(DWORD Lun, DWORD Action, PUCHAR Atr, PDWORD AtrLength)
{
	RESPONSECODE r = IFD_COMMUNICATION_ERROR;
	struct ifd_client *ic;
	struct msgb *rx, *tx;

	ensure_osmo_ctx();

	if (LUN2RDR(Lun) != 0) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	if (LUN2SLOT(Lun) >= ARRAY_SIZE(ifd_client)) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	ic = ifd_client[LUN2SLOT(Lun)];
	if (!ic) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	switch (Action) {
	case IFD_POWER_DOWN:
		tx = itmsg_alloc(ITMSG_TYPE_POWER_OFF_REQ, 0, NULL, 0);
		break;
	case IFD_POWER_UP:
		tx = itmsg_alloc(ITMSG_TYPE_POWER_ON_REQ, 0, NULL, 0);
		break;
	case IFD_RESET:
		tx = itmsg_alloc(ITMSG_TYPE_RESET_REQ, 0, NULL, 0);
		break;
	default:
		r = IFD_NOT_SUPPORTED;
		goto err;
	}

	rx = ifd_xceive_client(ic, tx);
	if (!rx) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	r = IFD_SUCCESS;
	msgb_free(rx);

err:
	if (r != IFD_SUCCESS && AtrLength)
		*AtrLength = 0;
	else
		r = IFDHGetCapabilities(Lun, TAG_IFD_ATR, AtrLength, Atr);

	LOG_EXIT(Lun, r);
	return r;
}

RESPONSECODE IFDHTransmitToICC(DWORD Lun, SCARD_IO_HEADER SendPci, PUCHAR TxBuffer,
			       DWORD TxLength, PUCHAR RxBuffer, PDWORD RxLength,
			       PSCARD_IO_HEADER RecvPci)
{
	RESPONSECODE r = IFD_COMMUNICATION_ERROR;
	struct ifd_client *ic;
	struct msgb *rx, *tx;
	struct itmsg *rx_it;

	ensure_osmo_ctx();

	if (LUN2RDR(Lun) != 0) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	if (LUN2SLOT(Lun) >= ARRAY_SIZE(ifd_client)) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	ic = ifd_client[LUN2SLOT(Lun)];
	if (!ic) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	tx = itmsg_alloc(ITMSG_TYPE_C_APDU_REQ, 0, TxBuffer, TxLength);
	OSMO_ASSERT(tx);
	/* transmit C-APDU to remote reader + blocking wait for response from peer */
	rx = ifd_xceive_client(ic, tx);
	if (!rx) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}
	rx_it = (struct itmsg *) msgb_data(rx);
	if (*RxLength > rx_it->len)
		*RxLength = rx_it->len;
	memcpy(RxBuffer, rx_it->data, *RxLength);
	msgb_free(rx);

	r = IFD_SUCCESS;
err:
	if (r != IFD_SUCCESS && RxLength)
		*RxLength = 0;

	LOG_EXIT(Lun, r);
	return r;
}

RESPONSECODE IFDHICCPresence(DWORD Lun)
{
	RESPONSECODE r = IFD_COMMUNICATION_ERROR;
	struct ifd_client *ic;
	struct msgb *rx, *tx;
	struct itmsg *rx_it;

	ensure_osmo_ctx();

	if (LUN2RDR(Lun) != 0) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	if (LUN2SLOT(Lun) >= ARRAY_SIZE(ifd_client)) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	ic = ifd_client[LUN2SLOT(Lun)];
	if (!ic) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}

	tx = itmsg_alloc(ITMSG_TYPE_CARD_PRES_REQ, 0, NULL, 0);
	OSMO_ASSERT(tx);
	rx = ifd_xceive_client(ic, tx);
	if (!rx) {
		r = IFD_NO_SUCH_DEVICE;
		goto err;
	}
	rx_it = (struct itmsg *) msgb_data(rx);
	if (rx_it->status == 0)
		r = IFD_SUCCESS;
	else
		r = IFD_ICC_NOT_PRESENT;

err:
	LOG_EXIT(Lun, r);
	return r;
}

static __attribute__((constructor)) void on_dso_load_ifd(void)
{
	void *g_tall_ctx = NULL;
	ensure_osmo_ctx();
	osmo_init_logging2(g_tall_ctx, &log_info);
}
