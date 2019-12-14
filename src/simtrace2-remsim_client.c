/* (C) 2018-2019 by Harald Welte <laforge@gnumonks.org>
 * (C) 2018 by sysmocom - s.f.m.c. GmbH, Author: Kevin Redon
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

#include <unistd.h>
#include <stdio.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>

#include <libusb.h>

#include "simtrace2/libusb_util.h"
#include "simtrace2/simtrace_prot.h"
#include "simtrace2/simtrace_usb.h"
#include "simtrace2/apdu_dispatch.h"
#include "simtrace2/simtrace2-discovery.h"

#include <osmocom/core/gsmtap.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/msgb.h>
#include <osmocom/sim/class_tables.h>
#include <osmocom/sim/sim.h>

/* transport to a SIMtrace device */
struct st_transport {
	/* USB */
	struct libusb_device_handle *usb_devh;
	struct {
		uint8_t in;
		uint8_t out;
		uint8_t irq_in;
	} usb_ep;
};

/* a SIMtrace slot; communicates over a transport */
struct st_slot {
	/* transport through which the slot can be reached */
	struct st_transport *transp;
	/* number of the slot within the transport */
	uint8_t slot_nr;
};

/* One istance of card emulation */
struct cardem_inst {
	/* slot on which this card emulation instance runs */
	struct st_slot *slot;
};

/* global GSMTAP instance */
static struct gsmtap_inst *g_gti;

static struct bankd_client *g_client;
static void *g_tall_ctx;
void __thread *talloc_asn1_ctx;
int asn_debug;

__attribute__((unused)) static int gsmtap_send_sim(const uint8_t *apdu, unsigned int len)
{
	struct gsmtap_hdr *gh;
	unsigned int gross_len = len + sizeof(*gh);
	uint8_t *buf = malloc(gross_len);
	int rc;

	if (!buf)
		return -ENOMEM;

	memset(buf, 0, sizeof(*gh));
	gh = (struct gsmtap_hdr *) buf;
	gh->version = GSMTAP_VERSION;
	gh->hdr_len = sizeof(*gh)/4;
	gh->type = GSMTAP_TYPE_SIM;

	memcpy(buf + sizeof(*gh), apdu, len);

	rc = write(gsmtap_inst_fd(g_gti), buf, gross_len);
	if (rc < 0) {
		perror("write gsmtap");
		free(buf);
		return rc;
	}

	free(buf);
	return 0;
}

/***********************************************************************
 * SIMTRACE core protocol
 ***********************************************************************/

/*! \brief allocate a message buffer for simtrace use */
static struct msgb *st_msgb_alloc(void)
{
	return msgb_alloc_headroom(1024+32, 32, "SIMtrace");
}

#if 0
static void apdu_out_cb(uint8_t *buf, unsigned int len, void *user_data)
{
	printf("APDU: %s\n", osmo_hexdump(buf, len));
	gsmtap_send_sim(buf, len);
}
#endif

/*! \brief Transmit a given command to the SIMtrace2 device */
int st_transp_tx_msg(struct st_transport *transp, struct msgb *msg)
{
	int rc;

	printf("SIMtrace <- %s\n", msgb_hexdump(msg));

	int xfer_len;

	rc = libusb_bulk_transfer(transp->usb_devh, transp->usb_ep.out,
		msgb_data(msg), msgb_length(msg),
		&xfer_len, 1000);

	msgb_free(msg);
	return rc;
}

static struct simtrace_msg_hdr *st_push_hdr(struct msgb *msg, uint8_t msg_class, uint8_t msg_type,
					    uint8_t slot_nr)
{
	struct simtrace_msg_hdr *sh;

	sh = (struct simtrace_msg_hdr *) msgb_push(msg, sizeof(*sh));
	memset(sh, 0, sizeof(*sh));
	sh->msg_class = msg_class;
	sh->msg_type = msg_type;
	sh->slot_nr = slot_nr;
	sh->msg_len = msgb_length(msg);

	return sh;
}

/* transmit a given message to a specified slot. Expects all headers
 * present before calling the function */
int st_slot_tx_msg(struct st_slot *slot, struct msgb *msg,
		   uint8_t msg_class, uint8_t msg_type)
{
	st_push_hdr(msg, msg_class, msg_type, slot->slot_nr);

	return st_transp_tx_msg(slot->transp, msg);
}

/***********************************************************************
 * Card Emulation protocol
 ***********************************************************************/


/*! \brief Request the SIMtrace2 to generate a card-insert signal */
static int cardem_request_card_insert(struct cardem_inst *ci, bool inserted)
{
	struct msgb *msg = st_msgb_alloc();
	struct cardemu_usb_msg_cardinsert *cins;

	cins = (struct cardemu_usb_msg_cardinsert *) msgb_put(msg, sizeof(*cins));
	memset(cins, 0, sizeof(*cins));
	if (inserted)
		cins->card_insert = 1;

	return st_slot_tx_msg(ci->slot, msg, SIMTRACE_MSGC_CARDEM, SIMTRACE_MSGT_DT_CEMU_CARDINSERT);
}

/*! \brief Request the SIMtrace2 to transmit a Procedure Byte, then Rx */
static int cardem_request_pb_and_rx(struct cardem_inst *ci, uint8_t pb, uint8_t le)
{
	struct msgb *msg = st_msgb_alloc();
	struct cardemu_usb_msg_tx_data *txd;
	txd = (struct cardemu_usb_msg_tx_data *) msgb_put(msg, sizeof(*txd));

	printf("SIMtrace <= %s(%02x, %d)\n", __func__, pb, le);

	memset(txd, 0, sizeof(*txd));
	txd->data_len = 1;
	txd->flags = CEMU_DATA_F_PB_AND_RX;
	/* one data byte */
	msgb_put_u8(msg, pb);

	return st_slot_tx_msg(ci->slot, msg, SIMTRACE_MSGC_CARDEM, SIMTRACE_MSGT_DT_CEMU_TX_DATA);
}

/*! \brief Request the SIMtrace2 to transmit a Procedure Byte, then Tx */
static int cardem_request_pb_and_tx(struct cardem_inst *ci, uint8_t pb,
				    const uint8_t *data, uint16_t data_len_in)
{
	struct msgb *msg = st_msgb_alloc();
	struct cardemu_usb_msg_tx_data *txd;
	uint8_t *cur;

	txd = (struct cardemu_usb_msg_tx_data *) msgb_put(msg, sizeof(*txd));

	printf("SIMtrace <= %s(%02x, %s, %d)\n", __func__, pb,
		osmo_hexdump(data, data_len_in), data_len_in);

	memset(txd, 0, sizeof(*txd));
	txd->data_len = 1 + data_len_in;
	txd->flags = CEMU_DATA_F_PB_AND_TX;
	/* procedure byte */
	msgb_put_u8(msg, pb);
	/* data */
	cur = msgb_put(msg, data_len_in);
	memcpy(cur, data, data_len_in);

	return st_slot_tx_msg(ci->slot, msg, SIMTRACE_MSGC_CARDEM, SIMTRACE_MSGT_DT_CEMU_TX_DATA);
}

/*! \brief Request the SIMtrace2 to send a Status Word */
static int cardem_request_sw_tx(struct cardem_inst *ci, const uint8_t *sw)
{
	struct msgb *msg = st_msgb_alloc();
	struct cardemu_usb_msg_tx_data *txd;
	uint8_t *cur;

	txd = (struct cardemu_usb_msg_tx_data *) msgb_put(msg, sizeof(*txd));

	printf("SIMtrace <= %s(%02x %02x)\n", __func__, sw[0], sw[1]);

	memset(txd, 0, sizeof(*txd));
	txd->data_len = 2;
	txd->flags = CEMU_DATA_F_PB_AND_TX | CEMU_DATA_F_FINAL;
	cur = msgb_put(msg, 2);
	cur[0] = sw[0];
	cur[1] = sw[1];

	return st_slot_tx_msg(ci->slot, msg, SIMTRACE_MSGC_CARDEM, SIMTRACE_MSGT_DT_CEMU_TX_DATA);
}

// FIXME check if the ATR actually includes a checksum
__attribute__((unused)) static void atr_update_csum(uint8_t *atr, unsigned int atr_len)
{
	uint8_t csum = 0;
	int i;

	for (i = 1; i < atr_len - 1; i++)
		csum = csum ^ atr[i];

	atr[atr_len-1] = csum;
}

static int cardem_request_set_atr(struct cardem_inst *ci, const uint8_t *atr, unsigned int atr_len)
{
	struct msgb *msg = st_msgb_alloc();
	struct cardemu_usb_msg_set_atr *satr;
	uint8_t *cur;

	satr = (struct cardemu_usb_msg_set_atr *) msgb_put(msg, sizeof(*satr));

	printf("SIMtrace <= %s(%s)\n", __func__, osmo_hexdump(atr, atr_len));

	memset(satr, 0, sizeof(*satr));
	satr->atr_len = atr_len;
	cur = msgb_put(msg, atr_len);
	memcpy(cur, atr, atr_len);

	return st_slot_tx_msg(ci->slot, msg, SIMTRACE_MSGC_CARDEM, SIMTRACE_MSGT_DT_CEMU_SET_ATR);
}

/***********************************************************************
 * Modem Control protocol
 ***********************************************************************/

static int _modem_reset(struct st_slot *slot, uint8_t asserted, uint16_t pulse_ms)
{
	struct msgb *msg = st_msgb_alloc();
	struct st_modem_reset *sr ;

	sr = (struct st_modem_reset *) msgb_put(msg, sizeof(*sr));
	sr->asserted = asserted;
	sr->pulse_duration_msec = pulse_ms;

	return st_slot_tx_msg(slot, msg, SIMTRACE_MSGC_MODEM, SIMTRACE_MSGT_DT_MODEM_RESET);
}

/*! \brief pulse the RESET line of the modem for \a duration_ms milli-seconds*/
int st_modem_reset_pulse(struct st_slot *slot, uint16_t duration_ms)
{
	return _modem_reset(slot, 2, duration_ms);
}

/*! \brief assert the RESET line of the modem */
int st_modem_reset_active(struct st_slot *slot)
{
	return _modem_reset(slot, 1, 0);
}

/*! \brief de-assert the RESET line of the modem */
int st_modem_reset_inactive(struct st_slot *slot)
{
	return _modem_reset(slot, 0, 0);
}

static int _modem_sim_select(struct st_slot *slot, uint8_t remote_sim)
{
	struct msgb *msg = st_msgb_alloc();
	struct st_modem_sim_select *ss;

	ss = (struct st_modem_sim_select *) msgb_put(msg, sizeof(*ss));
	ss->remote_sim = remote_sim;

	return st_slot_tx_msg(slot, msg, SIMTRACE_MSGC_MODEM, SIMTRACE_MSGT_DT_MODEM_SIM_SELECT);
}

/*! \brief select local (physical) SIM for given slot */
int st_modem_sim_select_local(struct st_slot *slot)
{
	return _modem_sim_select(slot, 0);
}

/*! \brief select remote (emulated/forwarded) SIM for given slot */
int st_modem_sim_select_remote(struct st_slot *slot)
{
	return _modem_sim_select(slot, 1);
}

/*! \brief Request slot to send us status information about the modem */
int st_modem_get_status(struct st_slot *slot)
{
	struct msgb *msg = st_msgb_alloc();

	return st_slot_tx_msg(slot, msg, SIMTRACE_MSGC_MODEM, SIMTRACE_MSGT_BD_MODEM_STATUS);
}


/***********************************************************************
 * Incoming Messages
 ***********************************************************************/

/*! \brief Process a STATUS message from the SIMtrace2 */
static int process_do_status(struct cardem_inst *ci, uint8_t *buf, int len)
{
	struct cardemu_usb_msg_status *status;
	status = (struct cardemu_usb_msg_status *) buf;

	printf("SIMtrace => STATUS: flags=0x%x, fi=%u, di=%u, wi=%u wtime=%u\n",
		status->flags, status->fi, status->di, status->wi,
		status->waiting_time);

	return 0;
}

/*! \brief Process a PTS indication message from the SIMtrace2 */
static int process_do_pts(struct cardem_inst *ci, uint8_t *buf, int len)
{
	struct cardemu_usb_msg_pts_info *pts;
	pts = (struct cardemu_usb_msg_pts_info *) buf;

	printf("SIMtrace => PTS req: %s\n", osmo_hexdump(pts->req, sizeof(pts->req)));

	return 0;
}

/*! \brief Process a ERROR indication message from the SIMtrace2 */
__attribute__((unused)) static int process_do_error(struct cardem_inst *ci, uint8_t *buf, int len)
{
	struct cardemu_usb_msg_error *err;
	err = (struct cardemu_usb_msg_error *) buf;

	printf("SIMtrace => ERROR: %u/%u/%u: %s\n",
		err->severity, err->subsystem, err->code,
		err->msg_len ? (char *)err->msg : "");

	return 0;
}

static struct apdu_context ac; // this will hold the complete APDU (across calls)

/*! \brief Process a RX-DATA indication message from the SIMtrace2 */
static int process_do_rx_da(struct cardem_inst *ci, uint8_t *buf, int len)
{
	struct cardemu_usb_msg_rx_data *data = (struct cardemu_usb_msg_rx_data *) buf; // cast the data from the USB message
	int rc;

	printf("SIMtrace => DATA: flags=%x, %s: ", data->flags,
		osmo_hexdump(data->data, data->data_len));

	rc = apdu_segment_in(&ac, data->data, data->data_len,
			     data->flags & CEMU_DATA_F_TPDU_HDR); // parse the APDU data in the USB message

	if (rc & APDU_ACT_TX_CAPDU_TO_CARD) { // there is no pending data coming from the modem
		uint8_t apdu_command[sizeof(ac.hdr) + ac.lc.tot]; // to store the APDU command to send
		memcpy(apdu_command, &ac.hdr, sizeof(ac.hdr)); // copy APDU command header
		if (ac.lc.tot) {
			memcpy(apdu_command + sizeof(ac.hdr), ac.dc, ac.lc.tot); // copy APDU command data 
		}
		// send APDU to card
		BankSlot_t bslot;
		bank_slot2rspro(&bslot, &g_client->bankd_slot);
		RsproPDU_t *pdu = rspro_gen_TpduModem2Card(g_client->srv_conn.clslot, &bslot, apdu_command, sizeof(ac.hdr) + ac.lc.tot); // create RSPRO packet
		server_conn_send_rspro(&g_client->bankd_conn, pdu);
		// the response will come separately
	} else if (ac.lc.tot > ac.lc.cur) { // there is pending data from the modem
		cardem_request_pb_and_rx(ci, ac.hdr.ins, ac.lc.tot - ac.lc.cur); // send procedure byte to get remaining data
	}
	return 0;
}

#if 0
	case SIMTRACE_CMD_DO_ERROR
		rc = process_do_error(ci, buf, len);
		break;
#endif

/*! \brief Process an incoming message from the SIMtrace2 */
static int process_usb_msg(struct cardem_inst *ci, uint8_t *buf, int len)
{
	struct simtrace_msg_hdr *sh = (struct simtrace_msg_hdr *)buf;
	int rc;

	printf("SIMtrace -> %s\n", osmo_hexdump(buf, len));

	buf += sizeof(*sh);

	switch (sh->msg_type) {
	case SIMTRACE_MSGT_BD_CEMU_STATUS:
		rc = process_do_status(ci, buf, len);
		break;
	case SIMTRACE_MSGT_DO_CEMU_PTS:
		rc = process_do_pts(ci, buf, len);
		break;
	case SIMTRACE_MSGT_DO_CEMU_RX_DATA:
		rc = process_do_rx_da(ci, buf, len);
		break;
	default:
		printf("unknown simtrace msg type 0x%02x\n", sh->msg_type);
		rc = -1;
		break;
	}

	return rc;
}

static void run_mainloop(struct cardem_inst *ci)
{
	struct st_transport *transp = ci->slot->transp;
	unsigned int msg_count, byte_count = 0;
	uint8_t buf[16*265];
	int xfer_len;
	int rc;

	printf("Entering main loop\n");

	while (1) {
		/* read data from SIMtrace2 device (local or via USB) */
		rc = libusb_bulk_transfer(transp->usb_devh, transp->usb_ep.in,
			 buf, sizeof(buf), &xfer_len, 100);
		if (rc < 0 && rc != LIBUSB_ERROR_TIMEOUT &&
			rc != LIBUSB_ERROR_INTERRUPTED &&
			rc != LIBUSB_ERROR_IO) {
			fprintf(stderr, "BULK IN transfer error: %s\n", libusb_error_name(rc));
			return;
		}
		/* dispatch any incoming data */
		if (xfer_len > 0) {
			process_usb_msg(ci, buf, xfer_len);
			msg_count++;
			byte_count += xfer_len;
		}
		// handle remote SIM client fsm
		// TODO register the USB fd for this select
		osmo_select_main(true);
	}
}

static struct st_transport _transp;

static struct st_slot _slot = {
	.transp = &_transp,
	.slot_nr = 0,
};

struct cardem_inst _ci = {
	.slot = &_slot,
};

struct cardem_inst *ci = &_ci;

static void signal_handler(int signal)
{
	switch (signal) {
	case SIGINT:
		cardem_request_card_insert(ci, false);
		exit(0);
		break;
	default:
		break;
	}
}

/** remsim_client **/

static int bankd_handle_tpduCardToModem(struct bankd_client *bc, const RsproPDU_t *pdu)
{
	OSMO_ASSERT(pdu);
	OSMO_ASSERT(RsproPDUchoice_PR_tpduCardToModem == pdu->msg.present);

	const struct TpduCardToModem *card2modem = &pdu->msg.choice.tpduCardToModem;
	if (card2modem->data.size < 2) { // at least the two SW bytes are needed
		return -1;
	}

	// save SW to our current APDU context
	ac.sw[0] = card2modem->data.buf[card2modem->data.size - 2];
	ac.sw[1] = card2modem->data.buf[card2modem->data.size - 1];
	printf("SIMtrace <= SW=0x%02x%02x, len_rx=%d\n", ac.sw[0], ac.sw[1], card2modem->data.size - 2);
	if (card2modem->data.size > 2) { // send PB and data to modem
		cardem_request_pb_and_tx(ci, ac.hdr.ins, card2modem->data.buf, card2modem->data.size - 2);
	}
	cardem_request_sw_tx(ci, ac.sw); // send SW to modem

	return 0;
}

static int bankd_handle_setAtrReq(struct bankd_client *bc, const RsproPDU_t *pdu)
{
	RsproPDU_t *resp;
	int rc;

	OSMO_ASSERT(pdu);
	OSMO_ASSERT(RsproPDUchoice_PR_setAtrReq == pdu->msg.present);

	/* FIXME: is this permitted at any time by the SIMtrace2 cardemfirmware? */
	rc = cardem_request_set_atr(ci, pdu->msg.choice.setAtrReq.atr.buf,
				    pdu->msg.choice.setAtrReq.atr.size);
	if (rc == 0)
		resp = rspro_gen_SetAtrRes(ResultCode_ok);
	else
		resp = rspro_gen_SetAtrRes(ResultCode_cardTransmissionError);
	if (!resp)
		return -ENOMEM;
	server_conn_send_rspro(&g_client->bankd_conn, resp);

	return 0;
}

/* handle incoming message from bankd */
static int bankd_handle_rx(struct rspro_server_conn *bankdc, const RsproPDU_t *pdu)
{
	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectClientRes:
		/* Store 'identity' of bankd to in peer_comp_id */
		rspro_comp_id_retrieve(&bankdc->peer_comp_id, &pdu->msg.choice.connectClientRes.identity);
		osmo_fsm_inst_dispatch(bankdc->fi, SRVC_E_CLIENT_CONN_RES, (void *) pdu);
		break;
	case RsproPDUchoice_PR_tpduCardToModem: // APDU response from card received
		bankd_handle_tpduCardToModem(g_client, pdu);
		break;
	case RsproPDUchoice_PR_setAtrReq:
		bankd_handle_setAtrReq(g_client, pdu);
		break;
	default:
		LOGPFSML(bankdc->fi, LOGL_ERROR, "Unknown/Unsuppoerted RSPRO PDU %s\n",
			 rspro_msgt_name(pdu));
		return -1;
	}

	return 0;
}

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
		if (!g_client->bankd_conn.clslot)
			g_client->bankd_conn.clslot = talloc_zero(g_client, ClientSlot_t);
		*g_client->bankd_conn.clslot = *g_client->srv_conn.clslot;
		/* send response to server */
		resp = rspro_gen_ConfigClientIdRes(ResultCode_ok);
		server_conn_send_rspro(srvc, resp);
		break;
	case RsproPDUchoice_PR_configClientBankReq:
		/* store/set the bankd ip/port as instructed by the server */
		osmo_talloc_replace_string(g_client, &g_client->bankd_conn.server_host,
					   rspro_IpAddr2str(&pdu->msg.choice.configClientBankReq.bankd.ip));
		rspro2bank_slot(&g_client->bankd_slot, &pdu->msg.choice.configClientBankReq.bankSlot);
		g_client->bankd_conn.server_port = pdu->msg.choice.configClientBankReq.bankd.port;
		/* instruct bankd FSM to connect */
		osmo_fsm_inst_dispatch(g_client->bankd_conn.fi, SRVC_E_ESTABLISH, NULL);
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

static void print_welcome(void)
{
	printf("simtrace2-remsim-client - Remote SIM card client for SIMtrace\n"
	       "(C) 2010-2017, Harald Welte <laforge@gnumonks.org>\n"
	       "(C) 2018, sysmocom -s.f.m.c. GmbH, Author: Kevin Redon <kredon@sysmocom.de>\n\n");
}

static void print_help(void)
{
	printf( "\t-s\t--server-host HOST\n"
		"\t-p\t--server-port PORT\n"
		"\t-c\t--client-id <0-65535>\n"
		"\t-n\t--client-slot <0-65535>\n"
		"\t-h\t--help\n"
		"\t-v\t--version\n"
		"\t-i\t--gsmtap-ip\tA.B.C.D\n"
		"\t-k\t--keep-running\n"
		"\t-V\t--usb-vendor\tVENDOR_ID\n"
		"\t-P\t--usb-product\tPRODUCT_ID\n"
		"\t-C\t--usb-config\tCONFIG_ID\n"
		"\t-I\t--usb-interface\tINTERFACE_ID\n"
		"\t-S\t--usb-altsetting ALTSETTING_ID\n"
		"\t-A\t--usb-address\tADDRESS\n"
		"\t-H\t--usb-path\tPATH\n"
		"\t-a\t--atr\tATR\n"
		"\n"
		);
}

static const struct option opts[] = {
	{ "server-host", 1, 0, 's' },
	{ "server-port", 1, 0, 'p' },
	{ "client-id", 1, 0, 'c' },
	{ "client-slot", 1, 0, 'n' },
	{ "help", 0, 0, 'h' },
	{ "version", 0, 0, 'v' },
	{ "gsmtap-ip", 1, 0, 'i' },
	{ "keep-running", 0, 0, 'k' },
	{ "usb-vendor", 1, 0, 'V' },
	{ "usb-product", 1, 0, 'P' },
	{ "usb-config", 1, 0, 'C' },
	{ "usb-interface", 1, 0, 'I' },
	{ "usb-altsetting", 1, 0, 'S' },
	{ "usb-address", 1, 0, 'A' },
	{ "usb-path", 1, 0, 'H' },
	{ "atr", 1, 0, 'a' },
	{ NULL, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	struct rspro_server_conn *srvc, *bankdc;
	struct st_transport *transp = ci->slot->transp;
	char *gsmtap_host = "127.0.0.1";
	int rc;
	int c, ret = 1;
	int keep_running = 0;
	int server_port = 9998;
	int if_num = 0, vendor_id = -1, product_id = -1;
	int config_id = -1, altsetting = 0, addr = -1;
	int client_id = -1, client_slot = -1;
	char *server_host = "127.0.0.1";
	char *path = NULL;
	uint8_t atr_data[33] = { 0x3B, 0x00 }; // the shortest simplest ATR possible
	uint8_t atr_len = 2;

	print_welcome();

	while (1) {
		int option_index = 0;

		c = getopt_long(argc, argv, "s:p:c:n:hvi:kV:P:C:I:S:A:H:a:", opts, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 's':
			server_host = optarg;
			break;
		case 'p':
			server_port = atoi(optarg);
			break;
		case 'c':
			client_id = atoi(optarg);
			break;
		case 'n':
			client_slot = atoi(optarg);
			break;
		case 'h':
			print_help();
			exit(0);
			break;
		case 'v':
			printf("osmo-remsim-client version %s\n", VERSION);
			exit(0);
			break;
		case 'i':
			gsmtap_host = optarg;
			break;
		case 'k':
			keep_running = 1;
			break;
		case 'V':
			vendor_id = strtol(optarg, NULL, 16);
			break;
		case 'P':
			product_id = strtol(optarg, NULL, 16);
			break;
		case 'C':
			config_id = atoi(optarg);
			break;
		case 'I':
			if_num = atoi(optarg);
			break;
		case 'S':
			altsetting = atoi(optarg);
			break;
		case 'A':
			addr = atoi(optarg);
			break;
		case 'H':
			path = optarg;
			break;
		case 'a':
			rc = osmo_hexparse(optarg, atr_data, ARRAY_SIZE(atr_data));
			if (rc < 2 || rc > ARRAY_SIZE(atr_data)) {
				fprintf(stderr, "ATR matlformed\n");
				goto do_exit;
			}
			atr_len = rc;
			break;
		}
	}

	if (vendor_id < 0 || product_id < 0) {
		fprintf(stderr, "You have to specify the vendor and product ID\n");
		goto do_exit;
	}

	signal(SIGUSR1, handle_sig_usr1);

	g_tall_ctx = talloc_named_const(NULL, 0, "global");
	talloc_asn1_ctx = talloc_named_const(g_tall_ctx, 0, "asn1");
	msgb_talloc_ctx_init(g_tall_ctx, 0);
	osmo_init_logging2(g_tall_ctx, &log_info);

	rc = libusb_init(NULL);
	if (rc < 0) {
		fprintf(stderr, "libusb initialization failed\n");
		goto do_exit;
	}

	g_gti = gsmtap_source_init(gsmtap_host, GSMTAP_UDP_PORT, 0);
	if (!g_gti) {
		perror("unable to open GSMTAP");
		goto close_exit;
	}
	gsmtap_source_add_sink(g_gti);

	signal(SIGINT, &signal_handler);

	// initialize remote SIM client

	g_client = talloc_zero(g_tall_ctx, struct bankd_client);

	if (client_id != -1) {
		/* default to client slot 0 */
		if (client_slot == -1)
			client_slot = 0;
		g_client->srv_conn.clslot = talloc_zero(g_client, ClientSlot_t);
		g_client->srv_conn.clslot->clientId = client_id;
		g_client->srv_conn.clslot->slotNr = client_slot;
		g_client->bankd_conn.clslot = talloc_zero(g_client, ClientSlot_t);
		*g_client->bankd_conn.clslot = *g_client->srv_conn.clslot;
	}

	srvc = &g_client->srv_conn;
	srvc->server_host = server_host;
	srvc->server_port = server_port;
	srvc->handle_rx = srvc_handle_rx;
	srvc->own_comp_id.type = ComponentType_remsimClient;
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.name, "simtrace2-remsim-client");
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.software, "remsim-client");
	OSMO_STRLCPY_ARRAY(srvc->own_comp_id.sw_version, PACKAGE_VERSION);
	rc = server_conn_fsm_alloc(g_client, srvc);
	if (rc < 0) {
		fprintf(stderr, "Unable to create Server conn FSM: %s\n", strerror(errno));
		exit(1);
	}
	osmo_fsm_inst_dispatch(srvc->fi, SRVC_E_ESTABLISH, NULL);

	bankdc = &g_client->bankd_conn;
	/* server_host / server_port are configured from remsim-server */
	bankdc->handle_rx = bankd_handle_rx;
	memcpy(&bankdc->own_comp_id, &srvc->own_comp_id, sizeof(bankdc->own_comp_id));
	rc = server_conn_fsm_alloc(g_client, bankdc);
	if (rc < 0) {
		fprintf(stderr, "Unable to create bankd conn FSM: %s\n", strerror(errno));
		exit(1);
	}
	osmo_fsm_inst_update_id(bankdc->fi, "bankd");

	asn_debug = 0;

	// connect to SIMtrace2 cardem
	do {
		struct usb_interface_match _ifm, *ifm = &_ifm;
		ifm->vendor = vendor_id;
		ifm->product = product_id;
		ifm->configuration = config_id;
		ifm->interface = if_num;
		ifm->altsetting = altsetting;
		ifm->addr = addr;
		if (path)
			osmo_strlcpy(ifm->path, path, sizeof(ifm->path));
		transp->usb_devh = usb_open_claim_interface(NULL, ifm);
		if (!transp->usb_devh) {
			fprintf(stderr, "can't open USB device\n");
			goto close_exit;
		}

		rc = libusb_claim_interface(transp->usb_devh, if_num);
		if (rc < 0) {
			fprintf(stderr, "can't claim interface %d; rc=%d\n", if_num, rc);
			goto close_exit;
		}

		rc = get_usb_ep_addrs(transp->usb_devh, if_num, &transp->usb_ep.out,
				      &transp->usb_ep.in, &transp->usb_ep.irq_in);
		if (rc < 0) {
			fprintf(stderr, "can't obtain EP addrs; rc=%d\n", rc);
			goto close_exit;
		}

		// switch modem SIM port to emulated SIM on OWHW
		if (USB_VENDOR_OPENMOKO == ifm->vendor && USB_PRODUCT_OWHW_SAM3 == ifm->product) { // we are on the OWHW
			int modem = -1;
			switch (ifm->interface) { // the USB interface indicates for which modem we want to emulate the SIM
			case 0:
				modem = 1;
				break;
			case 1:
				modem = 2;
				break;
			default:
				fprintf(stderr, "unknown GPIO for SIMtrace interface %d\n", ifm->interface);
				goto close_exit;
			}
			//
			char gpio_path[PATH_MAX];
			snprintf(gpio_path, sizeof(gpio_path), "/dev/gpio/connect_st_usim%d/value", modem);
			int connec_st_usim = open(gpio_path, O_WRONLY);
			if (-1 == connec_st_usim) {
				fprintf(stderr, "can't open GPIO %s to switch modem %d to emulated USIM\n", gpio_path, modem);
				goto close_exit;
			}
			if (1 != write(connec_st_usim, "1", 1)) {
				fprintf(stderr, "can't write GPIO %s to switch modem %d to emulated USIM\n", gpio_path, modem);
				goto close_exit;
			}
			printf("switched modem %d to emulated USIM\n", modem);

			snprintf(gpio_path, sizeof(gpio_path), "/dev/gpio/mdm%d_rst/value", modem);
			int mdm_rst = open(gpio_path, O_WRONLY);
			if (-1 == mdm_rst) {
				fprintf(stderr, "can't open GPIO %s to reset modem %d\n", gpio_path, modem);
				goto close_exit;
			}
			if (1 != write(mdm_rst, "1", 1)) {
				fprintf(stderr, "can't write GPIO %s to reset modem %d\n", gpio_path, modem);
				goto close_exit;
			}
			sleep(1); // wait a bit to ensure reset is effective
			if (1 != write(mdm_rst, "0", 1)) {
				fprintf(stderr, "can't write GPIO %s to reset modem %d\n", gpio_path, modem);
				goto close_exit;
			}
			printf("modem %d reset\n", modem);
		}

		/* simulate card-insert to modem (owhw, not qmod) */
		cardem_request_card_insert(ci, true);

		/* select remote (forwarded) SIM */
		st_modem_sim_select_remote(ci->slot);

		/* set the ATR */
		//atr_update_csum(real_atr, sizeof(real_atr));
		cardem_request_set_atr(ci, atr_data, atr_len);

		/* select remote (forwarded) SIM */
		st_modem_reset_pulse(ci->slot, 300);

		run_mainloop(ci);
		ret = 0;

		libusb_release_interface(transp->usb_devh, 0);
close_exit:
		if (transp->usb_devh)
			libusb_close(transp->usb_devh);
		if (keep_running)
			sleep(1);
	} while (keep_running);

	libusb_exit(NULL);
do_exit:
	return ret;
}
