#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/rspro/RsproPDU.h>
#include <osmocom/rspro/ComponentType.h>

#define MAX_NAME_LEN 32
struct app_comp_id {
	enum ComponentType type;
	char name[MAX_NAME_LEN+1];
	char software[MAX_NAME_LEN+1];
	char sw_version[MAX_NAME_LEN+1];
	char hw_manufacturer[MAX_NAME_LEN+1];
	char hw_model[MAX_NAME_LEN+1];
	char hw_serial_nr[MAX_NAME_LEN+1];
	char hw_version[MAX_NAME_LEN+1];
	char fw_version[MAX_NAME_LEN+1];
};

const char *rspro_msgt_name(const RsproPDU_t *pdu);

struct msgb *rspro_msgb_alloc(void);
struct msgb *rspro_enc_msg(RsproPDU_t *pdu);
RsproPDU_t *rspro_dec_msg(struct msgb *msg);
RsproPDU_t *rspro_gen_ConnectBankReq(const struct app_comp_id *a_cid,
					uint16_t bank_id, uint16_t num_slots);
RsproPDU_t *rspro_gen_ConnectBankRes(const struct app_comp_id *a_cid, e_ResultCode res);
RsproPDU_t *rspro_gen_ConnectClientReq(const struct app_comp_id *a_cid, const ClientSlot_t *client);
RsproPDU_t *rspro_gen_ConnectClientRes(const struct app_comp_id *a_cid, e_ResultCode res);
RsproPDU_t *rspro_gen_CreateMappingReq(const ClientSlot_t *client, const BankSlot_t *bank);
RsproPDU_t *rspro_gen_CreateMappingRes(e_ResultCode res);
RsproPDU_t *rspro_gen_RemoveMappingReq(const ClientSlot_t *client, const BankSlot_t *bank);
RsproPDU_t *rspro_gen_RemoveMappingRes(e_ResultCode res);
RsproPDU_t *rspro_gen_ConfigClientIdReq(const ClientSlot_t *client);
RsproPDU_t *rspro_gen_ConfigClientIdRes(e_ResultCode res);
RsproPDU_t *rspro_gen_ConfigClientBankReq(const BankSlot_t *bank, uint32_t ip, uint16_t port);
RsproPDU_t *rspro_gen_ConfigClientBankRes(e_ResultCode res);
RsproPDU_t *rspro_gen_SetAtrReq(uint16_t client_id, uint16_t slot_nr, const uint8_t *atr,
				unsigned int atr_len);
RsproPDU_t *rspro_gen_TpduModem2Card(const ClientSlot_t *client, const BankSlot_t *bank,
				     const uint8_t *tpdu, unsigned int tpdu_len);
RsproPDU_t *rspro_gen_TpduCard2Modem(const BankSlot_t *bank, const ClientSlot_t *client,
				     const uint8_t *tpdu, unsigned int tpdu_len);

void rspro_comp_id_retrieve(struct app_comp_id *out, const ComponentIdentity_t *in);
const char *rspro_IpAddr2str(const IpAddress_t *in);

#include "slotmap.h"
void rspro2bank_slot(struct bank_slot *out, const BankSlot_t *in);
void bank_slot2rspro(BankSlot_t *out, const struct bank_slot *in);

void rspro2client_slot(struct client_slot *out, const ClientSlot_t *in);
void client_slot2rspro(ClientSlot_t *out, const struct client_slot *in);
