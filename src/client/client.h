#pragma once

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
};
