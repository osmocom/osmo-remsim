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

struct msgb *rspro_msgb_alloc(void);
struct msgb *rspro_enc_msg(RsproPDU_t *pdu);
RsproPDU_t *rspro_dec_msg(struct msgb *msg);
RsproPDU_t *rspro_gen_ConnectBankReq(const struct app_comp_id *a_cid,
					uint16_t bank_id, uint16_t num_slots);
RsproPDU_t *rspro_gen_ConnectClientReq(const struct app_comp_id *a_cid, const ClientSlot_t *client);
RsproPDU_t *rspro_gen_CreateMappingReq(const ClientSlot_t *client, const BankSlot_t *bank);
RsproPDU_t *rspro_gen_ConfigClientReq(const ClientSlot_t *client, uint32_t ip, uint16_t port);
RsproPDU_t *rspro_gen_SetAtrReq(uint16_t client_id, uint16_t slot_nr, const uint8_t *atr,
				unsigned int atr_len);
