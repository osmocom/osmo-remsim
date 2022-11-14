#pragma once
#include <stdint.h>
#include <osmocom/core/gsmtap.h>

int bankd_gsmtap_init(const char *gsmtap_host);
int bankd_gsmtap_send_apdu(uint8_t sub_type, const uint8_t *mdm_tpdu, unsigned int mdm_tpdu_len,
	const uint8_t *sim_tpdu, unsigned int sim_tpdu_len);
