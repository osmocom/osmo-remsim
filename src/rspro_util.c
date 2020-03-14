/* (C) 2018-2019 by Harald Welte <laforge@gnumonks.org>
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


#include <netinet/in.h>
#include <arpa/inet.h>

#include <asn_application.h>
#include <der_encoder.h>

#include "asn1c_helpers.h"

#include <osmocom/core/msgb.h>
#include <osmocom/rspro/RsproPDU.h>

#include "rspro_util.h"

#define ASN_ALLOC_COPY(out, in) \
do {						\
	if (in)	 {				\
		out = CALLOC(1, sizeof(*in));	\
		OSMO_ASSERT(out);		\
		memcpy(out, in, sizeof(*in));	\
	}					\
} while (0)


const char *rspro_msgt_name(const RsproPDU_t *pdu)
{
	return asn_choice_name(&asn_DEF_RsproPDUchoice, &pdu->msg);
}

struct msgb *rspro_msgb_alloc(void)
{
	return msgb_alloc_headroom(1024, 8, "RSPRO");
}

/*! BER-Encode an RSPRO message into  msgb. 
 *  \param[in] pdu Structure describing RSPRO PDU. Is freed by this function on success
 *  \returns callee-allocated message buffer containing encoded RSPRO PDU; NULL on error.
 */
struct msgb *rspro_enc_msg(RsproPDU_t *pdu)
{
	struct msgb *msg = rspro_msgb_alloc();
	asn_enc_rval_t rval;

	if (!msg)
		return NULL;

	msg->l2h = msg->data;
	rval = der_encode_to_buffer(&asn_DEF_RsproPDU, pdu, msgb_data(msg), msgb_tailroom(msg));
	if (rval.encoded < 0) {
		fprintf(stderr, "Failed to encode %s\n", rval.failed_type->name);
		msgb_free(msg);
		return NULL;
	}
	msgb_put(msg, rval.encoded);

	ASN_STRUCT_FREE(asn_DEF_RsproPDU, pdu);

	return msg;
}

/* caller must make sure to free msg */
RsproPDU_t *rspro_dec_msg(struct msgb *msg)
{
	RsproPDU_t *pdu = NULL;
	asn_dec_rval_t rval;

	//printf("decoding %s\n", msgb_hexdump(msg));
	rval = ber_decode(NULL, &asn_DEF_RsproPDU, (void **) &pdu, msgb_l2(msg), msgb_l2len(msg));
	if (rval.code != RC_OK) {
		fprintf(stderr, "Failed to decode: %d. Consumed %zu of %u bytes\n",
			rval.code, rval.consumed, msgb_length(msg));
		return NULL;
	}

	return pdu;
}

static void fill_comp_id(ComponentIdentity_t *out, const struct app_comp_id *in)
{
	out->type = in->type;
	OCTET_STRING_fromString(&out->name, in->name);
	OCTET_STRING_fromString(&out->software, in->software);
	OCTET_STRING_fromString(&out->swVersion, in->sw_version);
	if (strlen(in->hw_manufacturer))
		out->hwManufacturer = OCTET_STRING_new_fromBuf(&asn_DEF_ComponentName,
								in->hw_manufacturer, -1);
	if (strlen(in->hw_model))
		out->hwModel = OCTET_STRING_new_fromBuf(&asn_DEF_ComponentName, in->hw_model, -1);
	if (strlen(in->hw_serial_nr))
		out->hwSerialNr = OCTET_STRING_new_fromBuf(&asn_DEF_ComponentName, in->hw_serial_nr, -1);
	if (strlen(in->hw_version))
		out->hwVersion = OCTET_STRING_new_fromBuf(&asn_DEF_ComponentName, in->hw_version, -1);
	if (strlen(in->fw_version))
		out->fwVersion = OCTET_STRING_new_fromBuf(&asn_DEF_ComponentName, in->fw_version, -1);
}

void string_fromOCTET_STRING(char *out, size_t out_size, const OCTET_STRING_t *in)
{
	if (!in) {
		out[0] = '\0';
		return;
	}
	memcpy(out, in->buf, out_size < in->size ? out_size : in->size);
	if (in->size < out_size)
		out[in->size] = '\0';
	else
		out[out_size-1] = '\0';
}
#define string_fromOCTET_STRING_ARRAY(out, in) string_fromOCTET_STRING(out, ARRAY_SIZE(out), in)


void rspro_comp_id_retrieve(struct app_comp_id *out, const ComponentIdentity_t *in)
{
	memset(out, 0, sizeof(*out));
	out->type = in->type;
	string_fromOCTET_STRING_ARRAY(out->name, &in->name);
	string_fromOCTET_STRING_ARRAY(out->software, &in->software);
	string_fromOCTET_STRING_ARRAY(out->sw_version, &in->swVersion);
	string_fromOCTET_STRING_ARRAY(out->hw_manufacturer, in->hwManufacturer);
	string_fromOCTET_STRING_ARRAY(out->hw_serial_nr, in->hwSerialNr);
	string_fromOCTET_STRING_ARRAY(out->hw_version, in->hwVersion);
	string_fromOCTET_STRING_ARRAY(out->fw_version, in->fwVersion);
}

const char *rspro_IpAddr2str(const IpAddress_t *in)
{
	static char buf[128];

	switch (in->present) {
	case IpAddress_PR_ipv4:
		return inet_ntop(AF_INET, in->choice.ipv4.buf, buf, sizeof(buf));
	case IpAddress_PR_ipv6:
		return inet_ntop(AF_INET6, in->choice.ipv6.buf, buf, sizeof(buf));
	default:
		return NULL;
	}
}

static void fill_ip4_port(IpPort_t *out, uint32_t ip, uint16_t port)
{
	uint32_t ip_n = htonl(ip);
	out->ip.present = IpAddress_PR_ipv4;
	OCTET_STRING_fromBuf(&out->ip.choice.ipv4, (const char *) &ip_n, 4);
	out->port = port;
}


RsproPDU_t *rspro_gen_ConnectBankReq(const struct app_comp_id *a_cid,
					uint16_t bank_id, uint16_t num_slots)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_connectBankReq;
	fill_comp_id(&pdu->msg.choice.connectBankReq.identity, a_cid);
	pdu->msg.choice.connectBankReq.bankId = bank_id;
	pdu->msg.choice.connectBankReq.numberOfSlots = num_slots;

	return pdu;
}

RsproPDU_t *rspro_gen_ConnectBankRes(const struct app_comp_id *a_cid, e_ResultCode res)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_connectBankRes;
	fill_comp_id(&pdu->msg.choice.connectBankRes.identity, a_cid);
	pdu->msg.choice.connectBankRes.result = res;

	return pdu;
}

RsproPDU_t *rspro_gen_ConnectClientReq(const struct app_comp_id *a_cid, const ClientSlot_t *client)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_connectClientReq;
	fill_comp_id(&pdu->msg.choice.connectClientReq.identity, a_cid);
	if (client)
		ASN_ALLOC_COPY(pdu->msg.choice.connectClientReq.clientSlot, client);

	return pdu;
}

RsproPDU_t *rspro_gen_ConnectClientRes(const struct app_comp_id *a_cid, e_ResultCode res)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->tag = 2342;
	pdu->msg.present = RsproPDUchoice_PR_connectClientRes;
	fill_comp_id(&pdu->msg.choice.connectClientRes.identity, a_cid);
	pdu->msg.choice.connectClientRes.result = res;

	return pdu;
}

RsproPDU_t *rspro_gen_CreateMappingReq(const ClientSlot_t *client, const BankSlot_t *bank)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_createMappingReq;
	pdu->msg.choice.createMappingReq.client = *client;
	pdu->msg.choice.createMappingReq.bank = *bank;

	return pdu;
}

RsproPDU_t *rspro_gen_CreateMappingRes(e_ResultCode res)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_createMappingRes;
	pdu->msg.choice.createMappingRes.result = res;

	return pdu;
}

RsproPDU_t *rspro_gen_RemoveMappingReq(const ClientSlot_t *client, const BankSlot_t *bank)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_removeMappingReq;
	pdu->msg.choice.removeMappingReq.client = *client;
	pdu->msg.choice.removeMappingReq.bank = *bank;

	return pdu;
}

RsproPDU_t *rspro_gen_RemoveMappingRes(e_ResultCode res)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_removeMappingRes;
	pdu->msg.choice.removeMappingRes.result = res;

	return pdu;
}

RsproPDU_t *rspro_gen_ConfigClientIdReq(const ClientSlot_t *client)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_configClientIdReq;
	pdu->msg.choice.configClientIdReq.clientSlot = *client;

	return pdu;
}

RsproPDU_t *rspro_gen_ConfigClientIdRes(e_ResultCode res)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_configClientIdRes;
	pdu->msg.choice.configClientIdRes.result = res;

	return pdu;
}

RsproPDU_t *rspro_gen_ConfigClientBankReq(const BankSlot_t *bank, uint32_t ip, uint16_t port)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_configClientBankReq;
	pdu->msg.choice.configClientBankReq.bankSlot = *bank;
	fill_ip4_port(&pdu->msg.choice.configClientBankReq.bankd, ip, port);

	return pdu;
}

RsproPDU_t *rspro_gen_ConfigClientBankRes(e_ResultCode res)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_configClientBankRes;
	pdu->msg.choice.configClientBankRes.result = res;

	return pdu;
}

RsproPDU_t *rspro_gen_SetAtrReq(uint16_t client_id, uint16_t slot_nr, const uint8_t *atr,
				unsigned int atr_len)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_setAtrReq;
	pdu->msg.choice.setAtrReq.slot.clientId = client_id;
	pdu->msg.choice.setAtrReq.slot.slotNr = slot_nr;
	OCTET_STRING_fromBuf(&pdu->msg.choice.setAtrReq.atr, (const char *)atr, atr_len);

	return pdu;
}

RsproPDU_t *rspro_gen_SetAtrRes(e_ResultCode res)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_setAtrRes;
	pdu->msg.choice.setAtrRes.result = res;

	return pdu;
}

RsproPDU_t *rspro_gen_TpduModem2Card(const ClientSlot_t *client, const BankSlot_t *bank,
				     const uint8_t *tpdu, unsigned int tpdu_len)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_tpduModemToCard;
	OSMO_ASSERT(client);
	pdu->msg.choice.tpduModemToCard.fromClientSlot = *client;
	OSMO_ASSERT(bank);
	pdu->msg.choice.tpduModemToCard.toBankSlot = *bank;
	/* TODO: flags? */
	OCTET_STRING_fromBuf(&pdu->msg.choice.tpduModemToCard.data, (const char *)tpdu, tpdu_len);

	return pdu;
}

RsproPDU_t *rspro_gen_TpduCard2Modem(const BankSlot_t *bank, const ClientSlot_t *client,
				     const uint8_t *tpdu, unsigned int tpdu_len)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_tpduCardToModem;
	OSMO_ASSERT(bank);
	pdu->msg.choice.tpduCardToModem.fromBankSlot = *bank;
	OSMO_ASSERT(client)
	pdu->msg.choice.tpduCardToModem.toClientSlot = *client;
	/* TODO: flags? */
	OCTET_STRING_fromBuf(&pdu->msg.choice.tpduCardToModem.data, (const char *)tpdu, tpdu_len);

	return pdu;
}

RsproPDU_t *rspro_gen_BankSlotStatusInd(const BankSlot_t *bank, const ClientSlot_t *client,
					bool rst_active, int vcc_present, int clk_active,
					int card_present)
{
	SlotPhysStatus_t *pstatus;
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_bankSlotStatusInd;
	OSMO_ASSERT(bank);
	pdu->msg.choice.bankSlotStatusInd.fromBankSlot = *bank;
	OSMO_ASSERT(client)
	pdu->msg.choice.bankSlotStatusInd.toClientSlot = *client;

	pstatus = &pdu->msg.choice.bankSlotStatusInd.slotPhysStatus;
	pstatus->resetActive = rst_active ? 1 : 0;

	if (vcc_present >= 0) {
		pstatus->vccPresent = CALLOC(1, sizeof(BOOLEAN_t));
		OSMO_ASSERT(pstatus->vccPresent);
		*pstatus->vccPresent = vcc_present;
	}

	if (clk_active >= 0) {
		pstatus->clkActive = CALLOC(1, sizeof(BOOLEAN_t));
		OSMO_ASSERT(pstatus->clkActive);
		*pstatus->clkActive = clk_active;
	}

	if (card_present >= 0) {
		pstatus->cardPresent = CALLOC(1, sizeof(BOOLEAN_t));
		OSMO_ASSERT(pstatus->cardPresent);
		*pstatus->cardPresent = card_present;
	}

	return pdu;
}

RsproPDU_t *rspro_gen_ClientSlotStatusInd(const ClientSlot_t *client, const BankSlot_t *bank,
					  bool rst_active, int vcc_present, int clk_active,
					  int card_present)
{
	SlotPhysStatus_t *pstatus;
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_clientSlotStatusInd;
	OSMO_ASSERT(client)
	pdu->msg.choice.clientSlotStatusInd.fromClientSlot = *client;
	OSMO_ASSERT(bank);
	pdu->msg.choice.clientSlotStatusInd.toBankSlot = *bank;

	pstatus = &pdu->msg.choice.clientSlotStatusInd.slotPhysStatus;
	pstatus->resetActive = rst_active ? 1 : 0;

	if (vcc_present >= 0) {
		pstatus->vccPresent = CALLOC(1, sizeof(BOOLEAN_t));
		OSMO_ASSERT(pstatus->vccPresent);
		*pstatus->vccPresent = vcc_present;
	}

	if (clk_active >= 0) {
		pstatus->clkActive = CALLOC(1, sizeof(BOOLEAN_t));
		OSMO_ASSERT(pstatus->clkActive);
		*pstatus->clkActive = clk_active;
	}

	if (card_present >= 0) {
		pstatus->cardPresent = CALLOC(1, sizeof(BOOLEAN_t));
		OSMO_ASSERT(pstatus->cardPresent);
		*pstatus->cardPresent = card_present;
	}

	return pdu;
}

RsproPDU_t *rspro_gen_ResetStateReq(void)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_resetStateReq;

	return pdu;
}

RsproPDU_t *rspro_gen_ResetStateRes(e_ResultCode res)
{
	RsproPDU_t *pdu = CALLOC(1, sizeof(*pdu));
	if (!pdu)
		return NULL;
	pdu->version = 2;
	pdu->msg.present = RsproPDUchoice_PR_resetStateRes;
	pdu->msg.choice.resetStateRes.result = res;

	return pdu;
}

e_ResultCode rspro_get_result(const RsproPDU_t *pdu)
{
	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_connectBankRes:
		return pdu->msg.choice.connectBankRes.result;
	case RsproPDUchoice_PR_connectClientRes:
		return pdu->msg.choice.connectClientRes.result;
	case RsproPDUchoice_PR_createMappingRes:
		return pdu->msg.choice.createMappingRes.result;
	case RsproPDUchoice_PR_removeMappingRes:
		return pdu->msg.choice.removeMappingRes.result;
	case RsproPDUchoice_PR_configClientIdRes:
		return pdu->msg.choice.configClientIdRes.result;
	case RsproPDUchoice_PR_configClientBankRes:
		return pdu->msg.choice.configClientBankRes.result;
	case RsproPDUchoice_PR_setAtrRes:
		return pdu->msg.choice.setAtrRes.result;
	case RsproPDUchoice_PR_resetStateRes:
		return pdu->msg.choice.resetStateRes.result;
	default:
		OSMO_ASSERT(0);
	}
}

void rspro2bank_slot(struct bank_slot *out, const BankSlot_t *in)
{
	out->bank_id = in->bankId;
	out->slot_nr = in->slotNr;
}

void bank_slot2rspro(BankSlot_t *out, const struct bank_slot *in)
{
	out->bankId = in->bank_id;
	out->slotNr = in->slot_nr;
}

void rspro2client_slot(struct client_slot *out, const ClientSlot_t *in)
{
	out->client_id = in->clientId;
	out->slot_nr = in->slotNr;
}

void client_slot2rspro(ClientSlot_t *out, const struct client_slot *in)
{
	out->clientId = in->client_id;
	out->slotNr = in->slot_nr;
}
