
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

#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <getopt.h>

#include <libusb.h>

#include "libusb_util.h"
#include "simtrace.h"
#include "simtrace_prot.h"
#include "apdu_dispatch.h"
#include "simtrace2-discovery.h"

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

	/* UDP */
	int udp_fd;
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

static int gsmtap_send_sim(const uint8_t *apdu, unsigned int len)
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
 * SIMTRACE pcore protocol
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

	printf("<- %s\n", msgb_hexdump(msg));

	if (transp->udp_fd < 0) {
		int xfer_len;

		rc = libusb_bulk_transfer(transp->usb_devh, transp->usb_ep.out,
					  msgb_data(msg), msgb_length(msg),
					  &xfer_len, 100000);
	} else {
		rc = write(transp->udp_fd, msgb_data(msg), msgb_length(msg));
	}

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

	printf("<= %s(%02x, %d)\n", __func__, pb, le);

	memset(txd, 0, sizeof(*txd));
	txd->data_len = 1;
	txd->flags = CEMU_DATA_F_PB_AND_RX;
	/* one data byte */
	msgb_put_u8(msg, pb);

	return st_slot_tx_msg(ci->slot, msg, SIMTRACE_MSGC_CARDEM, SIMTRACE_MSGT_DT_CEMU_TX_DATA);
}

/*! \brief Request the SIMtrace2 to transmit a Procedure Byte, then Tx */
static int cardem_request_pb_and_tx(struct cardem_inst *ci, uint8_t pb,
				    const uint8_t *data, uint8_t data_len_in)
{
	struct msgb *msg = st_msgb_alloc();
	struct cardemu_usb_msg_tx_data *txd;
	uint8_t *cur;

	txd = (struct cardemu_usb_msg_tx_data *) msgb_put(msg, sizeof(*txd));

	printf("<= %s(%02x, %s, %d)\n", __func__, pb,
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

	printf("<= %s(%02x %02x)\n", __func__, sw[0], sw[1]);

	memset(txd, 0, sizeof(*txd));
	txd->data_len = 2;
	txd->flags = CEMU_DATA_F_PB_AND_TX | CEMU_DATA_F_FINAL;
	cur = msgb_put(msg, 2);
	cur[0] = sw[0];
	cur[1] = sw[1];

	return st_slot_tx_msg(ci->slot, msg, SIMTRACE_MSGC_CARDEM, SIMTRACE_MSGT_DT_CEMU_TX_DATA);
}

static void atr_update_csum(uint8_t *atr, unsigned int atr_len)
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

	printf("<= %s(%s)\n", __func__, osmo_hexdump(atr, atr_len));

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

	printf("=> STATUS: flags=0x%x, fi=%u, di=%u, wi=%u wtime=%u\n",
		status->flags, status->fi, status->di, status->wi,
		status->waiting_time);

	return 0;
}

/*! \brief Process a PTS indication message from the SIMtrace2 */
static int process_do_pts(struct cardem_inst *ci, uint8_t *buf, int len)
{
	struct cardemu_usb_msg_pts_info *pts;
	pts = (struct cardemu_usb_msg_pts_info *) buf;

	printf("=> PTS req: %s\n", osmo_hexdump(pts->req, sizeof(pts->req)));

	return 0;
}

/*! \brief Process a ERROR indication message from the SIMtrace2 */
static int process_do_error(struct cardem_inst *ci, uint8_t *buf, int len)
{
	struct cardemu_usb_msg_error *err;
	err = (struct cardemu_usb_msg_error *) buf;

	printf("=> ERROR: %u/%u/%u: %s\n",
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

	printf("=> DATA: flags=%x, %s: ", data->flags,
		osmo_hexdump(data->data, data->data_len));

	rc = apdu_segment_in(&ac, data->data, data->data_len,
			     data->flags & CEMU_DATA_F_TPDU_HDR); // parse the APDU data in the USB message

	if (rc & APDU_ACT_TX_CAPDU_TO_CARD) { // there is no pending data coming from the modem
		uint8_t* apdu_command = calloc(1, sizeof(ac.hdr) + ac.lc.tot); // to store the APDU command to send
		memcpy(apdu_command, &ac.hdr, sizeof(ac.hdr)); // copy APDU command header
		if (ac.lc.tot) {
			memcpy(apdu_command + sizeof(ac.hdr), ac.dc, ac.lc.tot); // copy APDU command data 
		}
		// send APDU to card
		RsproPDU_t *pdu = rspro_gen_TpduModem2Card(g_client->clslot, &(BankSlot_t){ .bankId = 0, .slotNr = 0}, apdu_command, sizeof(ac.hdr) + ac.lc.tot); // create RSPRO packet
		ipa_client_conn_send_rspro(g_client->bankd_conn, pdu); // send RSPRO packet
		// the response will come separately
		free(apdu_command);
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

	printf("-> %s\n", osmo_hexdump(buf, len));

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

static void print_welcome(void)
{
	printf("simtrace2-remsim - Remote SIM card forwarding\n"
	       "(C) 2010-2017, Harald Welte <laforge@gnumonks.org>\n"
	       "(C) 2018, sysmocom -s.f.m.c. GmbH, Author: Kevin Redon <kredon@sysmocom.de>\n\n");
}

static void print_help(void)
{
	printf( "\t-r\t--remote-udp-host HOST\n"
		"\t-p\t--remote-udp-port PORT\n"
		"\t-h\t--help\n"
		"\t-i\t--gsmtap-ip\tA.B.C.D\n"
		"\t-k\t--keep-running\n"
		"\t-V\t--usb-vendor\tVENDOR_ID\n"
		"\t-P\t--usb-product\tPRODUCT_ID\n"
		"\t-C\t--usb-config\tCONFIG_ID\n"
		"\t-I\t--usb-interface\tINTERFACE_ID\n"
		"\t-S\t--usb-altsetting ALTSETTING_ID\n"
		"\t-A\t--usb-address\tADDRESS\n"
		"\t-H\t--usb-path\tPATH\n"
		"\n"
		);
}

static const struct option opts[] = {
	{ "remote-udp-host", 1, 0, 'r' },
	{ "remote-udp-port", 1, 0, 'p' },
	{ "gsmtap-ip", 1, 0, 'i' },
	{ "help", 0, 0, 'h' },
	{ "keep-running", 0, 0, 'k' },
	{ "usb-vendor", 1, 0, 'V' },
	{ "usb-product", 1, 0, 'P' },
	{ "usb-config", 1, 0, 'C' },
	{ "usb-interface", 1, 0, 'I' },
	{ "usb-altsetting", 1, 0, 'S' },
	{ "usb-address", 1, 0, 'A' },
	{ "usb-path", 1, 0, 'H' },
	{ NULL, 0, 0, 0 }
};

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
			fprintf(stderr, "BULK IN transfer error; rc=%d\n", rc);
			return;
		}
		/* dispatch any incoming data */
		if (xfer_len > 0) {
			printf("URB: %s\n", osmo_hexdump(buf, xfer_len));
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

static void push_and_send(struct ipa_client_conn *ipa, struct msgb *msg_tx)
{
	ipa_prepend_header_ext(msg_tx, IPAC_PROTO_EXT_RSPRO);
	ipa_msg_push_header(msg_tx, IPAC_PROTO_OSMO);
	ipa_client_conn_send(ipa, msg_tx);
	/* msg_tx is now queued and will be freed. */
}

void ipa_client_conn_send_rspro(struct ipa_client_conn *ipa, RsproPDU_t *rspro)
{
	struct msgb *msg = rspro_enc_msg(rspro);
	OSMO_ASSERT(msg);
	push_and_send(ipa, msg);
}

static int bankd_handle_tpduCardToModem(struct bankd_client *bc, RsproPDU_t *pdu)
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
	printf("SW=0x%02x%02x, len_rx=%d\n", ac.sw[0], ac.sw[1], card2modem->data.size - 2);
	if (card2modem->data.size > 2) { // send PB and data to modem
		cardem_request_pb_and_tx(ci, ac.hdr.ins, card2modem->data.buf, card2modem->data.size - 2);
	}
	cardem_request_sw_tx(ci, ac.sw); // send SW to modem

	return 0;
}

static int bankd_handle_msg(struct bankd_client *bc, struct msgb *msg)
{
	RsproPDU_t *pdu = rspro_dec_msg(msg);
	if (!pdu) {
		fprintf(stderr, "Error decoding PDU\n");
		return -1;
	}

	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectClientRes:
		osmo_fsm_inst_dispatch(bc->bankd_fi, BDC_E_CLIENT_CONN_RES, pdu);
		break;
	case RsproPDUchoice_PR_tpduCardToModem: // APDU response from card received
		bankd_handle_tpduCardToModem(bc, pdu);
		break;
	default:
		fprintf(stderr, "Unknown/Unsuppoerted RSPRO PDU: %s\n", msgb_hexdump(msg));
		return -1;
	}

	return 0;
}

int bankd_read_cb(struct ipa_client_conn *conn, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct bankd_client *bc = conn->data;
	int rc;

	if (msgb_length(msg) < sizeof(*hh))
		goto invalid;
	msg->l2h = &hh->data[0];
	if (hh->proto != IPAC_PROTO_OSMO)
		goto invalid;
	if (!he || msgb_l2len(msg) < sizeof(*he))
		goto invalid;
	msg->l2h = &he->data[0];

	if (he->proto != IPAC_PROTO_EXT_RSPRO)
		goto invalid;

	printf("Received RSPRO %s\n", msgb_hexdump(msg));

	rc = bankd_handle_msg(bc, msg);

	return rc;

invalid:
	msgb_free(msg);
	return -1;
}

static const struct log_info_cat default_categories[] = {
	[DMAIN] = {
		.name = "DMAIN",
		.loglevel = LOGL_DEBUG,
		.enabled = 1,
	},
};

static const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	struct st_transport *transp = ci->slot->transp;
	char *gsmtap_host = "127.0.0.1";
	int rc;
	int c, ret = 1;
	int keep_running = 0;
	int remote_udp_port = 52342;
	int if_num = 0, vendor_id = -1, product_id = -1;
	int config_id = -1, altsetting = 0, addr = -1;
	char *remote_udp_host = NULL;
	char *path = NULL;

	print_welcome();

	while (1) {
		int option_index = 0;

		c = getopt_long(argc, argv, "r:p:hi:V:P:C:I:S:A:H:ak", opts, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'r':
			remote_udp_host = optarg;
			break;
		case 'p':
			remote_udp_port = atoi(optarg);
			break;
		case 'h':
			print_help();
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
		}
	}

	if (!remote_udp_host && (vendor_id < 0 || product_id < 0)) {
		fprintf(stderr, "You have to specify the vendor and product ID\n");
		goto do_exit;
	}

	transp->udp_fd = -1;

	if (!remote_udp_host) {
		rc = libusb_init(NULL);
		if (rc < 0) {
			fprintf(stderr, "libusb initialization failed\n");
			goto do_exit;
		}
	} else {
		transp->udp_fd = osmo_sock_init(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
						remote_udp_host, remote_udp_port+if_num,
						OSMO_SOCK_F_CONNECT);
		if (transp->udp_fd < 0) {
			fprintf(stderr, "error binding UDP port\n");
			goto do_exit;
		}
	}

	g_gti = gsmtap_source_init(gsmtap_host, GSMTAP_UDP_PORT, 0);
	if (!g_gti) {
		perror("unable to open GSMTAP");
		goto close_exit;
	}
	gsmtap_source_add_sink(g_gti);

	signal(SIGINT, &signal_handler);

	// initialize remote SIM client
	g_tall_ctx = talloc_named_const(NULL, 0, "global");

	osmo_fsm_register(&remsim_client_bankd_fsm);
	osmo_fsm_register(&remsim_client_server_fsm);

	g_client = talloc_zero(g_tall_ctx, struct bankd_client);
	g_client->bankd_host = "localhost";
	g_client->bankd_port = 9999;
	g_client->own_comp_id.type = ComponentType_remsimClient;
	g_client->clslot = &(ClientSlot_t){ .clientId = 23, .slotNr = 1 };
	OSMO_STRLCPY_ARRAY(g_client->own_comp_id.name, "fixme-name");
	OSMO_STRLCPY_ARRAY(g_client->own_comp_id.software, "remsim-client");
	OSMO_STRLCPY_ARRAY(g_client->own_comp_id.sw_version, PACKAGE_VERSION);

	asn_debug = 0;
	osmo_init_logging2(g_tall_ctx, &log_info);

	if (bankd_conn_fsm_alloc(g_client) < 0) {
		fprintf(stderr, "Unable to connect: %s\n", strerror(errno));
		exit(1);
	}

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

		/* simulate card-insert to modem (owhw, not qmod) */
		cardem_request_card_insert(ci, true);

		/* select remote (forwarded) SIM */
		st_modem_sim_select_remote(ci->slot);

		/* set the ATR */
		uint8_t real_atr[] = { 0x3B, 0x00 }; // the shortest simplest ATR possible
		atr_update_csum(real_atr, sizeof(real_atr));
		cardem_request_set_atr(ci, real_atr, sizeof(real_atr));

		/* select remote (forwarded) SIM */
		st_modem_reset_pulse(ci->slot, 300);

		run_mainloop(ci);
		ret = 0;

		if (transp->udp_fd < 0)
			libusb_release_interface(transp->usb_devh, 0);
close_exit:
		if (transp->usb_devh)
			libusb_close(transp->usb_devh);
		if (keep_running)
			sleep(1);
	} while (keep_running);

	if (transp->udp_fd < 0)
		libusb_exit(NULL);
do_exit:
	return ret;
}
