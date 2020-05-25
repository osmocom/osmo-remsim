/* (C) 2018-2020 by Harald Welte <laforge@gnumonks.org>
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

#include <stdio.h>
#include <errno.h>

#include <libusb.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/utils.h>

#include <osmocom/usb/libusb.h>

#include <osmocom/simtrace2/apdu_dispatch.h>
#include <osmocom/simtrace2/simtrace2_api.h>
#include <osmocom/simtrace2/simtrace_prot.h>

#include "client.h"
#include "debug.h"

#define LOGCI(ci, lvl, fmt, args ...) \
	LOGP(DST2, lvl, fmt, ## args)

/***********************************************************************
 * Incoming Messages from cardem firmware
 ***********************************************************************/

/*! \brief Process a STATUS message from the SIMtrace2 */
static int process_do_status(struct osmo_st2_cardem_inst *ci, uint8_t *buf, int len)
{
	struct cardemu_usb_msg_status *status;
	status = (struct cardemu_usb_msg_status *) buf;

	LOGCI(ci, LOGL_INFO, "SIMtrace => STATUS: flags=0x%x, fi=%u, di=%u, wi=%u wtime=%u\n",
		status->flags, status->fi, status->di, status->wi, status->waiting_time);

	return 0;
}

/*! \brief Process a PTS indication message from the SIMtrace2 */
static int process_do_pts(struct osmo_st2_cardem_inst *ci, uint8_t *buf, int len)
{
	struct cardemu_usb_msg_pts_info *pts = (struct cardemu_usb_msg_pts_info *) buf;
	struct bankd_client *bc = ci->priv;
	struct frontend_pts fpts = {
		.buf = pts->req,
		.len = sizeof(pts->req),
	};

	LOGCI(ci, LOGL_INFO, "SIMtrace => PTS req: %s\n", osmo_hexdump(pts->req, sizeof(pts->req)));

	osmo_fsm_inst_dispatch(bc->main_fi, MF_E_MDM_PTS_IND, &fpts);

	return 0;
}

/*! \brief Process a ERROR indication message from the SIMtrace2 */
__attribute__((unused)) static int process_do_error(struct osmo_st2_cardem_inst *ci, uint8_t *buf, int len)
{
	struct cardemu_usb_msg_error *err;
	err = (struct cardemu_usb_msg_error *) buf;

	LOGCI(ci, LOGL_ERROR, "SIMtrace => ERROR: %u/%u/%u: %s\n",
		err->severity, err->subsystem, err->code, err->msg_len ? (char *)err->msg : "");

	return 0;
}

static struct osmo_apdu_context ac; // this will hold the complete APDU (across calls)

/*! \brief Process a RX-DATA indication message from the SIMtrace2 */
static int process_do_rx_da(struct osmo_st2_cardem_inst *ci, uint8_t *buf, int len)
{
	struct cardemu_usb_msg_rx_data *data = (struct cardemu_usb_msg_rx_data *) buf;
	struct bankd_client *bc = ci->priv;
	struct frontend_tpdu ftpdu;
	int rc;

	LOGCI(ci, LOGL_DEBUG, "SIMtrace => DATA: flags=%x, %s\n", data->flags,
		osmo_hexdump(data->data, data->data_len));

 	/* parse the APDU data in the USB message */
	rc = osmo_apdu_segment_in(&ac, data->data, data->data_len,
				  data->flags & CEMU_DATA_F_TPDU_HDR);

	if (rc & APDU_ACT_TX_CAPDU_TO_CARD) {
		/* there is no pending data coming from the modem */
		uint8_t apdu_command[sizeof(ac.hdr) + ac.lc.tot];
		memcpy(apdu_command, &ac.hdr, sizeof(ac.hdr));
		if (ac.lc.tot)
			memcpy(apdu_command + sizeof(ac.hdr), ac.dc, ac.lc.tot);
		/* send APDU to card */
		ftpdu.buf = apdu_command;
		ftpdu.len = sizeof(ac.hdr) + ac.lc.tot;
		osmo_fsm_inst_dispatch(bc->main_fi, MF_E_MDM_TPDU, &ftpdu);
	} else if (ac.lc.tot > ac.lc.cur) {
		/* there is pending data from the modem: send procedure byte to get remaining data */
		osmo_st2_cardem_request_pb_and_rx(ci, ac.hdr.ins, ac.lc.tot - ac.lc.cur);
	}
	return 0;
}

#if 0
	case SIMTRACE_CMD_DO_ERROR
		rc = process_do_error(ci, buf, len);
		break;
#endif

/*! \brief Process an incoming message from the SIMtrace2 */
static int process_usb_msg(struct osmo_st2_cardem_inst *ci, uint8_t *buf, int len)
{
	struct simtrace_msg_hdr *sh = (struct simtrace_msg_hdr *)buf;
	int rc;

	LOGCI(ci, LOGL_DEBUG, "SIMtrace -> %s\n", osmo_hexdump(buf, len));

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
	case SIMTRACE_MSGT_BD_CEMU_CONFIG:
		/* firmware confirms configuration change; ignore */
		break;
	default:
		LOGCI(ci, LOGL_ERROR, "unknown simtrace msg type 0x%02x\n", sh->msg_type);
		rc = -1;
		break;
	}

	return rc;
}


/*! \brief Process a STATUS message on IRQ endpoint from the SIMtrace2 */
static int process_irq_status(struct osmo_st2_cardem_inst *ci, const uint8_t *buf, int len)
{
	const struct cardemu_usb_msg_status *status = (struct cardemu_usb_msg_status *) buf;
	struct bankd_client *bc = ci->priv;
	struct frontend_phys_status pstatus = {
		.flags = {
			.reset_active = status->flags & CEMU_STATUS_F_RESET_ACTIVE,
			.vcc_present = status->flags & CEMU_STATUS_F_VCC_PRESENT,
			.clk_active = status->flags & CEMU_STATUS_F_CLK_ACTIVE,
			.card_present = -1 /* FIXME: make this dependent on board */,
		},
		.voltage_mv = status->voltage_mv,
		.fi = status->fi,
		.di = status->di,
		.wi = status->wi,
		.waiting_time = status->waiting_time,
	};

	LOGCI(ci, LOGL_INFO, "SIMtrace IRQ STATUS: flags=0x%x, fi=%u, di=%u, wi=%u wtime=%u\n",
		status->flags, status->fi, status->di, status->wi,
		status->waiting_time);

	osmo_fsm_inst_dispatch(bc->main_fi, MF_E_MDM_STATUS_IND, &pstatus);
	return 0;
}

static int process_usb_msg_irq(struct osmo_st2_cardem_inst *ci, const uint8_t *buf, unsigned int len)
{
	struct simtrace_msg_hdr *sh = (struct simtrace_msg_hdr *)buf;
	int rc;

	LOGCI(ci, LOGL_INFO, "SIMtrace IRQ %s\n", osmo_hexdump(buf, len));

	buf += sizeof(*sh);

	switch (sh->msg_type) {
	case SIMTRACE_MSGT_BD_CEMU_STATUS:
		rc = process_irq_status(ci, buf, len);
		break;
	default:
		LOGCI(ci, LOGL_ERROR, "unknown simtrace msg type 0x%02x\n", sh->msg_type);
		rc = -1;
		break;
	}

	return rc;
}

static void usb_in_xfer_cb(struct libusb_transfer *xfer)
{
	struct osmo_st2_cardem_inst *ci = xfer->user_data;
	int rc;

	switch (xfer->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		/* hand the message up the stack */
		process_usb_msg(ci, xfer->buffer, xfer->actual_length);
		break;
	case LIBUSB_TRANSFER_NO_DEVICE:
		LOGCI(ci, LOGL_FATAL, "USB device disappeared\n");
		exit(1);
		break;
	default:
		LOGCI(ci, LOGL_FATAL, "USB IN transfer failed, status=%u\n", xfer->status);
		exit(1);
		break;
	}

	/* re-submit the IN transfer */
	rc = libusb_submit_transfer(xfer);
	OSMO_ASSERT(rc == 0);
}


static void allocate_and_submit_in(struct osmo_st2_cardem_inst *ci)
{
	struct osmo_st2_transport *transp = ci->slot->transp;
	struct libusb_transfer *xfer;
	int rc;

	xfer = libusb_alloc_transfer(0);
	OSMO_ASSERT(xfer);
	xfer->dev_handle = transp->usb_devh;
	xfer->flags = 0;
	xfer->type = LIBUSB_TRANSFER_TYPE_BULK;
	xfer->endpoint = transp->usb_ep.in;
	xfer->timeout = 0;
	xfer->user_data = ci;
	xfer->length = 16*256;

	xfer->buffer = libusb_dev_mem_alloc(xfer->dev_handle, xfer->length);
	OSMO_ASSERT(xfer->buffer);
	xfer->callback = usb_in_xfer_cb;

	/* submit the IN transfer */
	rc = libusb_submit_transfer(xfer);
	OSMO_ASSERT(rc == 0);
}


static void usb_irq_xfer_cb(struct libusb_transfer *xfer)
{
	struct osmo_st2_cardem_inst *ci = xfer->user_data;
	int rc;

	switch (xfer->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		process_usb_msg_irq(ci, xfer->buffer, xfer->actual_length);
		break;
	case LIBUSB_TRANSFER_NO_DEVICE:
		LOGCI(ci, LOGL_FATAL, "USB device disappeared\n");
		exit(1);
		break;
	default:
		LOGCI(ci, LOGL_FATAL, "USB IN transfer failed, status=%u\n", xfer->status);
		exit(1);
		break;
	}

	/* re-submit the IN transfer */
	rc = libusb_submit_transfer(xfer);
	OSMO_ASSERT(rc == 0);
}


static void allocate_and_submit_irq(struct osmo_st2_cardem_inst *ci)
{
	struct osmo_st2_transport *transp = ci->slot->transp;
	struct libusb_transfer *xfer;
	int rc;

	xfer = libusb_alloc_transfer(0);
	OSMO_ASSERT(xfer);
	xfer->dev_handle = transp->usb_devh;
	xfer->flags = 0;
	xfer->type = LIBUSB_TRANSFER_TYPE_INTERRUPT;
	xfer->endpoint = transp->usb_ep.irq_in;
	xfer->timeout = 0;
	xfer->user_data = ci;
	xfer->length = 64;

	xfer->buffer = libusb_dev_mem_alloc(xfer->dev_handle, xfer->length);
	OSMO_ASSERT(xfer->buffer);
	xfer->callback = usb_irq_xfer_cb;

	/* submit the IN transfer */
	rc = libusb_submit_transfer(xfer);
	OSMO_ASSERT(rc == 0);
}




/***********************************************************************
 * simtrace2 frontend code to remsim-client
 ***********************************************************************/

int frontend_request_card_insert(struct bankd_client *bc)
{
	struct osmo_st2_cardem_inst *ci = bc->cardem;
	return osmo_st2_cardem_request_card_insert(ci, true);
}

int frontend_request_sim_remote(struct bankd_client *bc)
{
	struct osmo_st2_cardem_inst *ci = bc->cardem;
	return osmo_st2_modem_sim_select_remote(ci->slot);
}

int frontend_request_modem_reset(struct bankd_client *bc)
{
	struct osmo_st2_cardem_inst *ci = bc->cardem;
	return osmo_st2_modem_reset_pulse(ci->slot, 300);
}

int frontend_handle_card2modem(struct bankd_client *bc, const uint8_t *data, size_t len)
{
	struct osmo_st2_cardem_inst *ci = bc->cardem;
	// save SW to our current APDU context
	ac.sw[0] = data[len-2];
	ac.sw[1] = data[len=1];

	LOGCI(ci, LOGL_DEBUG, "SIMtrace <= SW=0x%02x%02x, len_rx=%zu\n", ac.sw[0], ac.sw[1], len-2);
	if (len > 2) { // send PB and data to modem
		osmo_st2_cardem_request_pb_and_tx(ci, ac.hdr.ins, data, len-2);
	}
	osmo_st2_cardem_request_sw_tx(ci, ac.sw); // send SW to modem
	return 0;
}

int frontend_handle_set_atr(struct bankd_client *bc, const uint8_t *data, size_t len)
{
	struct osmo_st2_cardem_inst *ci = bc->cardem;
	return osmo_st2_cardem_request_set_atr(ci, data, len);
}

int frontend_handle_slot_status(struct bankd_client *bc, const SlotPhysStatus_t *sts)
{
	/* we currently don't propagate bankd status to cardem */
	return 0;
}

int frontend_append_script_env(struct bankd_client *bc, char **env, int i, size_t max_env)
{
	struct osmo_st2_cardem_inst *ci = bc->cardem;

	if (max_env < 4)
		return -ENOSPC;

	env[i++] = talloc_asprintf(env, "REMSIM_USB_PATH=%s", ci->usb_path);
	/* TODO: Configuration; Altsetting */
	env[i++] = talloc_asprintf(env, "REMSIM_USB_INTERFACE=%u", bc->cfg->usb.if_num);

	return i;
}

/* FIXME: This must be cleaned up */
static struct osmo_st2_transport _transp;
static struct osmo_st2_slot _slot = {
	.transp = &_transp,
	.slot_nr = 0,
};

int client_user_main(struct bankd_client *bc)
{
	struct usb_interface_match _ifm, *ifm = &_ifm;
	struct osmo_st2_transport *transp;
	struct osmo_st2_cardem_inst *ci;
	struct client_config *cfg = bc->cfg;
	int rc, i;

	rc = osmo_libusb_init(NULL);
	if (rc < 0) {
		fprintf(stderr, "libusb initialization failed\n");
		return rc;
	}

	ci = talloc_zero(bc, struct osmo_st2_cardem_inst);
	OSMO_ASSERT(ci);
	ci->slot = &_slot;
	transp = ci->slot->transp;
	ci->priv = bc;
	bc->cardem = ci;

	ifm->vendor = cfg->usb.vendor_id;
	ifm->product = cfg->usb.product_id;
	ifm->configuration = cfg->usb.config_id;
	ifm->interface = cfg->usb.if_num;
	ifm->altsetting = cfg->usb.altsetting;
	ifm->addr = cfg->usb.addr;
	if (cfg->usb.path)
		osmo_strlcpy(ifm->path, cfg->usb.path, sizeof(ifm->path));
	transp->udp_fd = -1;
	transp->usb_async = true;
	transp->usb_devh = osmo_libusb_open_claim_interface(NULL, NULL, ifm);
	if (!transp->usb_devh) {
		fprintf(stderr, "can't open USB device\n");
		return -1;
	}

	/* (re)determine the USB path of the opened device */
	talloc_free(ci->usb_path);
	ci->usb_path = osmo_libusb_dev_get_path_c(ci, libusb_get_device(transp->usb_devh));

	rc = libusb_claim_interface(transp->usb_devh, cfg->usb.if_num);
	if (rc < 0) {
		fprintf(stderr, "can't claim interface %d; rc=%d\n", cfg->usb.if_num, rc);
		goto close_exit;
	}

	rc = osmo_libusb_get_ep_addrs(transp->usb_devh, cfg->usb.if_num, &transp->usb_ep.out,
					&transp->usb_ep.in, &transp->usb_ep.irq_in);
	if (rc < 0) {
		fprintf(stderr, "can't obtain EP addrs; rc=%d\n", rc);
		goto close_exit;
	}

	allocate_and_submit_irq(ci);
	/* submit multiple IN URB in order to work around OS#4409 */
	for (i = 0; i < 4; i++)
		allocate_and_submit_in(ci);

	/* request firmware to generate STATUS on IRQ endpoint */
	osmo_st2_cardem_request_config(ci, CEMU_FEAT_F_STATUS_IRQ);

	while (1) {
		osmo_select_main(0);
	}

	return 0;

close_exit:
	if (transp->usb_devh)
		libusb_close(transp->usb_devh);
	osmo_libusb_exit(NULL);

	return -1;
}
