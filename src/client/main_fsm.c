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
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/exec.h>

#include "rspro_util.h"
#include "client.h"
#include "debug.h"

#define S(x)	(1 << (x))

/***********************************************************************/

/* build the (additional) environment for executing a script */
static char **build_script_env(struct bankd_client *bc, const char *cause)
{
	char **env = talloc_zero_size(bc, 256*sizeof(char *));
	int rc, i = 0;

	if (!env)
		return NULL;

	env[i++] = talloc_asprintf(env, "REMSIM_CLIENT_VERSION=%s", VERSION);

	env[i++] = talloc_asprintf(env, "REMSIM_SERVER_ADDR=%s:%u",
				   bc->srv_conn.server_host, bc->srv_conn.server_port);
	env[i++] = talloc_asprintf(env, "REMSIM_SERVER_STATE=%s",
				   osmo_fsm_inst_state_name(bc->srv_conn.fi));

	env[i++] = talloc_asprintf(env, "REMSIM_BANKD_ADDR=%s:%u",
				   bc->bankd_conn.server_host, bc->bankd_conn.server_port);
	env[i++] = talloc_asprintf(env, "REMSIM_BANKD_STATE=%s",
				   osmo_fsm_inst_state_name(bc->bankd_conn.fi));


	if (bc->srv_conn.clslot) {
		env[i++] = talloc_asprintf(env, "REMSIM_CLIENT_SLOT=%lu:%lu",
					   bc->srv_conn.clslot->clientId,
					   bc->srv_conn.clslot->slotNr);
	}
	env[i++] = talloc_asprintf(env, "REMSIM_BANKD_SLOT=%u:%u",
				   bc->bankd_slot.bank_id, bc->bankd_slot.slot_nr);

	env[i++] = talloc_asprintf(env, "REMSIM_SIM_VCC=%u", bc->last_status.flags.vcc_present);
	env[i++] = talloc_asprintf(env, "REMSIM_SIM_RST=%u", bc->last_status.flags.reset_active);
	env[i++] = talloc_asprintf(env, "REMSIM_SIM_CLK=%u", bc->last_status.flags.clk_active);

	env[i++] = talloc_asprintf(env, "REMSIM_CAUSE=%s", cause);

	/* ask frontend to append any frontend-specific additional environment vars */
	rc = frontend_append_script_env(bc, env, i, 256-i-1);
	if (rc > 0)
		i = rc;

	/* terminate last entry */
	env[i++] = NULL;
	return env;
}

static int call_script(struct bankd_client *bc, const char *cause)
{
	char **env, *cmd;
	int rc;

	if (!bc->cfg->event_script)
		return 0;

	env = build_script_env(bc, cause);
	if (!env)
		return -ENOMEM;

	cmd = talloc_asprintf(env, "%s %s", bc->cfg->event_script, cause);
	if (!cmd) {
		talloc_free(env);
		return -ENOMEM;
	}

	rc = osmo_system_nowait(cmd, osmo_environment_whitelist, env);
	talloc_free(env);

	return rc;
}


/***********************************************************************/


enum main_fsm_state {
	MF_ST_INIT,
	MF_ST_UNCONFIGURED,	/* waiting for configuration from server */
	MF_ST_WAIT_BANKD,	/* configured; waiting for bankd conn */
	MF_ST_OPERATIONAL,	/* fully operational (configured + bankd conn live */
};

static const struct value_string main_fsm_event_names[] = {
	OSMO_VALUE_STRING(MF_E_SRVC_CONNECTED),
	OSMO_VALUE_STRING(MF_E_SRVC_LOST),
	OSMO_VALUE_STRING(MF_E_SRVC_CONFIG_BANK),
	OSMO_VALUE_STRING(MF_E_SRVC_RESET_REQ),
	OSMO_VALUE_STRING(MF_E_BANKD_CONNECTED),
	OSMO_VALUE_STRING(MF_E_BANKD_LOST),
	OSMO_VALUE_STRING(MF_E_BANKD_TPDU),
	OSMO_VALUE_STRING(MF_E_BANKD_ATR),
	OSMO_VALUE_STRING(MF_E_BANKD_SLOT_STATUS),
	OSMO_VALUE_STRING(MF_E_MDM_STATUS_IND),
	OSMO_VALUE_STRING(MF_E_MDM_PTS_IND),
	OSMO_VALUE_STRING(MF_E_MDM_TPDU),
	{ 0, NULL }
};

static void main_st_operational(struct osmo_fsm_inst *fi, uint32_t event, void *data);

static void main_st_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bankd_client *bc = (struct bankd_client *) fi->priv;

	switch (event) {
	case MF_E_SRVC_CONNECTED:
		osmo_fsm_inst_state_chg(fi, MF_ST_UNCONFIGURED, 0, 0);
		call_script(bc, "event-server-connect");
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void main_st_unconfigured_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bankd_client *bc = (struct bankd_client *) fi->priv;
	/* we might be called from a 'higher' state such as operational; clean up */
	osmo_fsm_inst_dispatch(bc->bankd_conn.fi, SRVC_E_DISCONNECT, NULL);
}

static void main_st_unconfigured(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case MF_E_SRVC_CONFIG_BANK:
		/* same treatment as below */
		main_st_operational(fi, event, data);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void main_st_wait_bankd(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bankd_client *bc = (struct bankd_client *) fi->priv;

	switch (event) {
	case MF_E_SRVC_CONFIG_BANK:
		/* same treatment as below */
		main_st_operational(fi, event, data);
		break;
	case MF_E_BANKD_CONNECTED:
		osmo_fsm_inst_state_chg(fi, MF_ST_OPERATIONAL, 0, 0);
		call_script(bc, "event-bankd-connect");
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void main_st_operational_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bankd_client *bc = (struct bankd_client *) fi->priv;

	/* Select remote (forwarded) SIM */
	frontend_request_sim_remote(bc);
	call_script(bc, "request-sim-remote");

	/* Set the ATR */
	frontend_handle_set_atr(bc, bc->cfg->atr.data, bc->cfg->atr.len);

	/* Simulate card insertion to modem */
	frontend_request_card_insert(bc);
	call_script(bc, "request-card-insert");

	/* Reset the modem */
	frontend_request_modem_reset(bc);
	call_script(bc, "request-modem-reset");
}

static void main_st_operational_onleave(struct osmo_fsm_inst *fi, uint32_t next_state)
{
	struct bankd_client *bc = (struct bankd_client *) fi->priv;

	/* Simulate a card-remval to modem */
	frontend_request_card_remove(bc);
	call_script(bc, "request-card-remove");

	/* Select local SIM */
	frontend_request_sim_local(bc);
	call_script(bc, "request-sim-local");

	/* Reset the modem */
	frontend_request_modem_reset(bc);
	call_script(bc, "request-modem-reset");
}

static void main_st_operational(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bankd_client *bc = (struct bankd_client *) fi->priv;
	struct frontend_phys_status *pstatus = NULL;
	struct frontend_pts *pts = NULL;
	struct frontend_tpdu *tpdu = NULL;
	RsproPDU_t *pdu_rx = NULL;
	RsproPDU_t *resp;
	BankSlot_t bslot;
	SlotPhysStatus_t *phys_status;

	switch (event) {
	case MF_E_BANKD_LOST:
		LOGPFSML(fi, LOGL_ERROR, "Connection to bankd lost\n");
		osmo_fsm_inst_state_chg(fi, MF_ST_WAIT_BANKD, 0, 0);
		break;
	case MF_E_SRVC_CONFIG_BANK:
		pdu_rx = data;
		OSMO_ASSERT(pdu_rx);
		OSMO_ASSERT(pdu_rx->msg.present == RsproPDUchoice_PR_configClientBankReq);
		/* store/set the bankd ip/port as instructed by the server */
		osmo_talloc_replace_string(bc, &bc->bankd_conn.server_host,
					   rspro_IpAddr2str(&pdu_rx->msg.choice.configClientBankReq.bankd.ip));
		bc->bankd_conn.server_port = pdu_rx->msg.choice.configClientBankReq.bankd.port;
		rspro2bank_slot(&bc->bankd_slot, &pdu_rx->msg.choice.configClientBankReq.bankSlot);
		LOGPFSML(fi, LOGL_INFO, "Rx configClientBankReq(%s:%u / B%u:%u)\n", bc->bankd_conn.server_host,
			 bc->bankd_conn.server_port, bc->bankd_slot.bank_id, bc->bankd_slot.slot_nr);
		/* bankd port 0 is a magic value to indicate "no bankd" */
		if (bc->bankd_conn.server_port == 0)
			osmo_fsm_inst_state_chg(fi, MF_ST_UNCONFIGURED, 0, 0);
		else {
			osmo_fsm_inst_state_chg(fi, MF_ST_WAIT_BANKD, 0, 0);
			/* TODO: do we need to disconnect before? */
			osmo_fsm_inst_dispatch(bc->bankd_conn.fi, SRVC_E_ESTABLISH, NULL);
		}
		/* send response to server */
		resp = rspro_gen_ConfigClientBankRes(ResultCode_ok);
		server_conn_send_rspro(&bc->srv_conn, resp);
		call_script(bc, "event-config-bankd");
		break;
	case MF_E_BANKD_TPDU:
		pdu_rx = data;
		OSMO_ASSERT(pdu_rx);
		OSMO_ASSERT(pdu_rx->msg.present == RsproPDUchoice_PR_tpduCardToModem);
		LOGPFSML(fi, LOGL_NOTICE, "Rx tpduCardToModem(%s)\n",
			 osmo_hexdump_nospc(pdu_rx->msg.choice.tpduCardToModem.data.buf,
					    pdu_rx->msg.choice.tpduCardToModem.data.size));
		/* forward to modem/cardem (via API) */
		frontend_handle_card2modem(bc, pdu_rx->msg.choice.tpduCardToModem.data.buf,
					   pdu_rx->msg.choice.tpduCardToModem.data.size);
		/* response happens indirectly via tpduModemToCard */
		break;
	case MF_E_BANKD_ATR:
		pdu_rx = data;
		OSMO_ASSERT(pdu_rx);
		OSMO_ASSERT(pdu_rx->msg.present == RsproPDUchoice_PR_setAtrReq);
		LOGPFSML(fi, LOGL_NOTICE, "Rx setAtrReq(%s)\n",
			 osmo_hexdump_nospc(pdu_rx->msg.choice.setAtrReq.atr.buf,
					    pdu_rx->msg.choice.setAtrReq.atr.size));
		if (bc->cfg->atr_ignore_rspro) {
			LOGPFSML(fi, LOGL_NOTICE, "Ignoring RSPRO setAtrReq\n");
		} else {
			/* forward to modem/cardem (via API) */
			frontend_handle_set_atr(bc, pdu_rx->msg.choice.setAtrReq.atr.buf,
						pdu_rx->msg.choice.setAtrReq.atr.size);
		}
		/* send response to bankd */
		resp = rspro_gen_SetAtrRes(ResultCode_ok);
		server_conn_send_rspro(&bc->bankd_conn, resp);
		break;
	case MF_E_BANKD_SLOT_STATUS:
		pdu_rx = data;
		OSMO_ASSERT(pdu_rx);
		OSMO_ASSERT(pdu_rx->msg.present == RsproPDUchoice_PR_bankSlotStatusInd);
		phys_status = &pdu_rx->msg.choice.bankSlotStatusInd.slotPhysStatus;
		LOGPFSML(fi, LOGL_NOTICE, "Rx bankSlotStatusInd(reset_act=%d, vcc_act=%d, clk_act=%d, "
			 "card_pres=%d)\n", phys_status->resetActive,
			 phys_status->vccPresent ? *phys_status->vccPresent : -1,
			 phys_status->clkActive ? *phys_status->clkActive : -1,
			 phys_status->cardPresent ? *phys_status->cardPresent : -1);
		/* forward to modem/cardem (via API) */
		frontend_handle_slot_status(bc, &pdu_rx->msg.choice.bankSlotStatusInd.slotPhysStatus);
		break;
	case MF_E_MDM_STATUS_IND:
		pstatus = data;
		OSMO_ASSERT(pstatus);
		LOGPFSML(fi, LOGL_NOTICE, "Tx clientSlotStatusInd(reset_act=%d, vcc_act=%d, clk_act=%d, "
			 "card_pres=%d)\n", pstatus->flags.reset_active, pstatus->flags.vcc_present,
			 pstatus->flags.clk_active, pstatus->flags.card_present);
		/* forward to bankd */
		bank_slot2rspro(&bslot, &bc->bankd_slot);
		resp = rspro_gen_ClientSlotStatusInd(bc->srv_conn.clslot, &bslot,
						     pstatus->flags.reset_active,
						     pstatus->flags.vcc_present,
						     pstatus->flags.clk_active,
						     pstatus->flags.card_present);
		server_conn_send_rspro(&bc->bankd_conn, resp);
		if (!memcmp(&bc->last_status.flags, &pstatus->flags, sizeof(pstatus->flags)))
			call_script(bc, "event-modem-status");
		bc->last_status = *pstatus;
		break;
	case MF_E_MDM_PTS_IND:
		pts = data;
		OSMO_ASSERT(pts);
		LOGPFSML(fi, LOGL_NOTICE, "PTS Indication (%s)\n", osmo_hexdump_nospc(pts->buf, pts->len));
		/* forward to bankd? */
		break;
	case MF_E_MDM_TPDU:
		tpdu = data;
		OSMO_ASSERT(tpdu);
		LOGPFSML(fi, LOGL_INFO, "Tx tpduModemToCard (%s)\n", osmo_hexdump_nospc(tpdu->buf, tpdu->len));
		/* forward to bankd */
		bank_slot2rspro(&bslot, &bc->bankd_slot);
		resp = rspro_gen_TpduModem2Card(bc->srv_conn.clslot, &bslot, tpdu->buf, tpdu->len);
		server_conn_send_rspro(&bc->bankd_conn, resp);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void main_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case MF_E_SRVC_LOST:
		/* should we do anything? The SRVC fsm will take care of reconnect, and we
		 * can continue to talk to the bankd without any trouble... */
		break;
	case MF_E_SRVC_RESET_REQ:
		osmo_fsm_inst_state_chg(fi, MF_ST_UNCONFIGURED, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}


static const struct osmo_fsm_state main_fsm_states[] = {
	[MF_ST_INIT] = {
		.name = "INIT",
		.in_event_mask = S(MF_E_SRVC_CONNECTED),
		.out_state_mask = S(MF_ST_UNCONFIGURED),
		.action = main_st_init,
	},
	[MF_ST_UNCONFIGURED] = {
		.name = "UNCONFIGURED",
		.in_event_mask = S(MF_E_SRVC_CONFIG_BANK),
		.out_state_mask = S(MF_ST_INIT) | S(MF_ST_WAIT_BANKD),
		.action = main_st_unconfigured,
		.onenter = main_st_unconfigured_onenter,
	},
	[MF_ST_WAIT_BANKD] = {
		.name = "WAIT_BANKD",
		.in_event_mask = S(MF_E_SRVC_CONFIG_BANK) | S(MF_E_BANKD_CONNECTED),
		.out_state_mask = S(MF_ST_INIT) | S(MF_ST_UNCONFIGURED) | S(MF_ST_OPERATIONAL),
		.action = main_st_wait_bankd,
	},
	[MF_ST_OPERATIONAL] = {
		.name = "OPERATIONAL",
		.in_event_mask = S(MF_E_SRVC_CONFIG_BANK) |
				 S(MF_E_BANKD_LOST) |
				 S(MF_E_BANKD_TPDU) |
				 S(MF_E_BANKD_ATR) |
				 S(MF_E_BANKD_SLOT_STATUS) |
				 S(MF_E_MDM_STATUS_IND) |
				 S(MF_E_MDM_PTS_IND) |
				 S(MF_E_MDM_TPDU),
		.out_state_mask = S(MF_ST_INIT) | S(MF_ST_UNCONFIGURED) | S(MF_ST_WAIT_BANKD),
		.action = main_st_operational,
		.onenter = main_st_operational_onenter,
		.onleave = main_st_operational_onleave,
	},
};

static struct osmo_fsm client_main_fsm = {
	.name = "CLIENT_MAIN",
	.states = main_fsm_states,
	.num_states = ARRAY_SIZE(main_fsm_states),
	.allstate_event_mask = S(MF_E_SRVC_LOST) | S(MF_E_SRVC_RESET_REQ),
	.allstate_action = main_allstate_action,
	.log_subsys = DMAIN,
	.event_names = main_fsm_event_names,
};

struct osmo_fsm_inst *main_fsm_alloc(void *ctx, struct bankd_client *bc)
{
	return osmo_fsm_inst_alloc(&client_main_fsm, ctx, bc, LOGL_DEBUG, "main");
}

static __attribute((constructor)) void on_dso_load_main_fsm(void)
{
	OSMO_ASSERT(osmo_fsm_register(&client_main_fsm) == 0);
}
