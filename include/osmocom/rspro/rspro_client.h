/* Remote SIM Protocol client */

/* (C) 2018 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#pragma once

#include <osmocom/core/timer.h>

/* a loss of RSPRO is considered quite serious, let's try to recover as quickly as
 * possible.  Even one new connection attempt per second should be quite acceptable until the link is
 * re-established */
#define OSMO_RSPRO_CLIENT_RECONNECT_INTERVAL 1
#define OSMO_RSPRO_CLIENT_PING_INTERVAL 20

struct msgb;
struct ipa_client_conn;
struct osmo_rspro_client;

/* Expects message in msg->l2h */
typedef int (*osmo_rspro_client_read_cb_t)(struct osmo_rspro_client *rsproc, struct msgb *msg);

struct osmo_rspro_client {
	const char *unit_name;

	struct ipa_client_conn *link;
	osmo_rspro_client_read_cb_t read_cb;
	void *data;

	struct osmo_timer_list ping_timer;
	struct osmo_timer_list connect_timer;
	int is_connected;
	int got_ipa_pong;
};

struct osmo_rspro_client *osmo_rspro_client_create(void *talloc_ctx,
						 const char *unit_name,
						 const char *ip_addr,
						 unsigned int tcp_port,
						 osmo_rspro_client_read_cb_t read_cb);

void osmo_rspro_client_destroy(struct osmo_rspro_client *rsproc);
int osmo_rspro_client_send(struct osmo_rspro_client *rsproc, struct msgb *msg);
struct msgb *osmo_rspro_client_msgb_alloc(void);

