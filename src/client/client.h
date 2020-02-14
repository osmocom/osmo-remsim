#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/rspro/RsproPDU.h>

#include "rspro_util.h"
#include "rspro_client_fsm.h"
#include "slotmap.h"
#include "debug.h"

/* main.c */

struct cardem_inst;

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

	/* remote component ID */
	struct app_comp_id peer_comp_id;

	struct bank_slot bankd_slot;

	struct client_config *cfg;
	struct cardem_inst *cardem;
	void *data;
};

#define srvc2bankd_client(srvc)		container_of(srvc, struct bankd_client, srv_conn)
#define bankdc2bankd_client(bdc)	container_of(bdc, struct bankd_client, bankd_conn)

struct bankd_client *remsim_client_create(void *ctx, const char *name, const char *software);
void remsim_client_set_clslot(struct bankd_client *bc, int client_id, int slot_nr);


extern int client_user_bankd_handle_rx(struct rspro_server_conn *bankdc, const RsproPDU_t *pdu);

extern int client_user_main(struct bankd_client *g_client);
