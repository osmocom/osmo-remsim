#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/rspro/RsproPDU.h>

#include "rspro_util.h"
#include "rspro_client_fsm.h"
#include "slotmap.h"
#include "debug.h"

/***********************************************************************
 * frontend interface
 ***********************************************************************/

struct bankd_client;

struct frontend_phys_status {
	struct {
		/* all members can be 0 (inactive), 1 (active) or -1 (not supported/known) */
		int reset_active;
		int vcc_present;
		int clk_active;
		int card_present;
	} flags;
	uint16_t voltage_mv;
	uint8_t fi;
	uint8_t di;
	uint8_t wi;
	uint8_t waiting_time;
};

struct frontend_pts {
	const uint8_t *buf;
	size_t len;
};

struct frontend_tpdu {
	const uint8_t *buf;
	size_t len;
};

/* API from generic core to frontend (modem/cardem) */
int frontend_request_card_insert(struct bankd_client *bc);
int frontend_request_sim_remote(struct bankd_client *bc);
int frontend_request_modem_reset(struct bankd_client *bc);
int frontend_handle_card2modem(struct bankd_client *bc, const uint8_t *data, size_t len);
int frontend_handle_set_atr(struct bankd_client *bc, const uint8_t *data, size_t len);
int frontend_handle_slot_status(struct bankd_client *bc, const SlotPhysStatus_t *sts);
int frontend_append_script_env(struct bankd_client *bc, char **env, size_t max_env);

/* main.c */

struct osmo_st2_cardem_inst;

#define ATR_SIZE_MAX            55
struct client_config {
	char *server_host;
	int server_port;

	int client_id;
	int client_slot;

	char *gsmtap_host;
	bool keep_running;

	char *event_script;

	struct {
		uint8_t data[ATR_SIZE_MAX];
		uint8_t len;
	} atr;

	struct {
		int vendor_id;
		int product_id;
		int config_id;
		int if_num;
		int altsetting;
		int addr;
		char *path;
	} usb;
};

struct bankd_client {
	/* connection to the remsim-server (control) */
	struct rspro_server_conn srv_conn;
	/* connection to the remsim-bankd (data) */
	struct rspro_server_conn bankd_conn;
	/* CLIENT_MAIN fsm */
	struct osmo_fsm_inst *main_fi;

	/* remote component ID */
	struct app_comp_id peer_comp_id;

	struct bank_slot bankd_slot;

	struct client_config *cfg;
	struct osmo_st2_cardem_inst *cardem;
	struct frontend_phys_status last_status;
	void *data;
};

#define srvc2bankd_client(srvc)		container_of(srvc, struct bankd_client, srv_conn)
#define bankdc2bankd_client(bdc)	container_of(bdc, struct bankd_client, bankd_conn)

struct client_config *client_config_init(void *ctx);
struct bankd_client *remsim_client_create(void *ctx, const char *name, const char *software,
					  struct client_config *cfg);
void remsim_client_set_clslot(struct bankd_client *bc, int client_id, int slot_nr);

extern int client_user_main(struct bankd_client *g_client);


/***********************************************************************
 * main FSM
 ***********************************************************************/

enum main_fsm_event {
	MF_E_SRVC_CONNECTED,	/* connection to server established (TCP + RSPRO level) */
	MF_E_SRVC_LOST,		/* connection to server was lost */
	MF_E_SRVC_CONFIG_BANK,	/* server instructs us to connect to bankd/slot */
	MF_E_SRVC_RESET_REQ,	/* RsproPDUchoice_PR_ResetStateReq */

	MF_E_BANKD_CONNECTED,	/* connection to bankd established (TCP + RSPRO level) */
	MF_E_BANKD_LOST,	/* connection to bankd was lost */
	MF_E_BANKD_TPDU,	/* RsproPDUchoice_PR_tpduCardToModem */
	MF_E_BANKD_ATR,		/* RsproPDUchoice_PR_setAtrReq */
	MF_E_BANKD_SLOT_STATUS,	/* bankSlotStatusInd */

	MF_E_MDM_STATUS_IND,	/* status from modem/cardem */
	MF_E_MDM_PTS_IND,	/* PTS indication from modem/cardem */
	MF_E_MDM_TPDU,		/* TPDU from modem/cardem */
};
struct osmo_fsm_inst *main_fsm_alloc(void *ctx, struct bankd_client *bc);



