/* Generic Subscriber Update Protocol client */

/* (C) 2018 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/rspro/rspro_client.h>

#include <osmocom/abis/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <errno.h>
#include <string.h>

static void start_test_procedure(struct osmo_rspro_client *rsproc);

static void rspro_client_send_ping(struct osmo_rspro_client *rsproc)
{
	struct msgb *msg = osmo_rspro_client_msgb_alloc();

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = IPAC_MSGT_PING;
	ipa_msg_push_header(msg, IPAC_PROTO_IPACCESS);
	ipa_client_conn_send(rsproc->link, msg);
}

static int rspro_client_connect(struct osmo_rspro_client *rsproc)
{
	int rc;

	if (rsproc->is_connected)
		return 0;

	if (osmo_timer_pending(&rsproc->connect_timer)) {
		LOGP(DLRSPRO, LOGL_DEBUG,
		     "RSPRO connect: connect timer already running\n");
		osmo_timer_del(&rsproc->connect_timer);
	}

	if (osmo_timer_pending(&rsproc->ping_timer)) {
		LOGP(DLRSPRO, LOGL_DEBUG,
		     "RSPRO connect: ping timer already running\n");
		osmo_timer_del(&rsproc->ping_timer);
	}

	if (ipa_client_conn_clear_queue(rsproc->link) > 0)
		LOGP(DLRSPRO, LOGL_DEBUG, "RSPRO connect: discarded stored messages\n");

	rc = ipa_client_conn_open(rsproc->link);

	if (rc >= 0) {
		LOGP(DLRSPRO, LOGL_NOTICE, "RSPRO connecting to %s:%d\n",
		     rsproc->link->addr, rsproc->link->port);
		return 0;
	}

	LOGP(DLRSPRO, LOGL_ERROR, "RSPRO failed to connect to %s:%d: %s\n",
	     rsproc->link->addr, rsproc->link->port, strerror(-rc));

	if (rc == -EBADF || rc == -ENOTSOCK || rc == -EAFNOSUPPORT ||
	    rc == -EINVAL)
		return rc;

	osmo_timer_schedule(&rsproc->connect_timer,
			    OSMO_RSPRO_CLIENT_RECONNECT_INTERVAL, 0);

	LOGP(DLRSPRO, LOGL_INFO, "Scheduled timer to retry RSPRO connect to %s:%d\n",
	     rsproc->link->addr, rsproc->link->port);

	return 0;
}

static void connect_timer_cb(void *rsproc_)
{
	struct osmo_rspro_client *rsproc = rsproc_;

	if (rsproc->is_connected)
		return;

	rspro_client_connect(rsproc);
}

static void client_send(struct osmo_rspro_client *rsproc, int proto_ext,
			struct msgb *msg_tx)
{
	ipa_prepend_header_ext(msg_tx, proto_ext);
	ipa_msg_push_header(msg_tx, IPAC_PROTO_OSMO);
	ipa_client_conn_send(rsproc->link, msg_tx);
	/* msg_tx is now queued and will be freed. */
}

static void rspro_client_updown_cb(struct ipa_client_conn *link, int up)
{
	struct osmo_rspro_client *rsproc = link->data;

	LOGP(DLRSPRO, LOGL_INFO, "RSPRO link to %s:%d %s\n",
		     link->addr, link->port, up ? "UP" : "DOWN");

	rsproc->is_connected = up;

	if (up) {
		start_test_procedure(rsproc);
		osmo_timer_del(&rsproc->connect_timer);
	} else {
		osmo_timer_del(&rsproc->ping_timer);

		osmo_timer_schedule(&rsproc->connect_timer,
				    OSMO_RSPRO_CLIENT_RECONNECT_INTERVAL, 0);
	}
}

static int rspro_client_read_cb(struct ipa_client_conn *link, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct osmo_rspro_client *rsproc = (struct osmo_rspro_client *)link->data;
	int rc;
	struct ipaccess_unit ipa_dev = {
		/* see rspro_client_create() on const vs non-const */
		.unit_name = (char*)rsproc->unit_name,
	};

	OSMO_ASSERT(ipa_dev.unit_name);

	msg->l2h = &hh->data[0];

	rc = ipaccess_bts_handle_ccm(link, &ipa_dev, msg);

	if (rc < 0) {
		LOGP(DLRSPRO, LOGL_NOTICE,
		     "RSPRO received an invalid IPA/CCM message from %s:%d\n",
		     link->addr, link->port);
		/* Link has been closed */
		rsproc->is_connected = 0;
		msgb_free(msg);
		return -1;
	}

	if (rc == 1) {
		uint8_t msg_type = *(msg->l2h);
		/* CCM message */
		if (msg_type == IPAC_MSGT_PONG) {
			LOGP(DLRSPRO, LOGL_DEBUG, "RSPRO receiving PONG\n");
			rsproc->got_ipa_pong = 1;
		}

		msgb_free(msg);
		return 0;
	}

	if (hh->proto != IPAC_PROTO_OSMO)
		goto invalid;

	if (!he || msgb_l2len(msg) < sizeof(*he))
		goto invalid;

	msg->l2h = &he->data[0];

	if (he->proto == IPAC_PROTO_EXT_RSPRO) {
		OSMO_ASSERT(rsproc->read_cb != NULL);
		rsproc->read_cb(rsproc, msg);
		/* expecting read_cb() to free msg */
	} else
		goto invalid;

	return 0;

invalid:
	LOGP(DLRSPRO, LOGL_NOTICE,
	     "RSPRO received an invalid IPA message from %s:%d, size = %d\n",
	     link->addr, link->port, msgb_length(msg));

	msgb_free(msg);
	return -1;
}

static void ping_timer_cb(void *rsproc_)
{
	struct osmo_rspro_client *rsproc = rsproc_;

	LOGP(DLRSPRO, LOGL_INFO, "RSPRO ping callback (%s, %s PONG)\n",
	     rsproc->is_connected ? "connected" : "not connected",
	     rsproc->got_ipa_pong ? "got" : "didn't get");

	if (rsproc->got_ipa_pong) {
		start_test_procedure(rsproc);
		return;
	}

	LOGP(DLRSPRO, LOGL_NOTICE, "RSPRO ping timed out, reconnecting\n");
	ipa_client_conn_close(rsproc->link);
	rsproc->is_connected = 0;

	rspro_client_connect(rsproc);
}

static void start_test_procedure(struct osmo_rspro_client *rsproc)
{
	osmo_timer_setup(&rsproc->ping_timer, ping_timer_cb, rsproc);

	rsproc->got_ipa_pong = 0;
	osmo_timer_schedule(&rsproc->ping_timer, OSMO_RSPRO_CLIENT_PING_INTERVAL, 0);
	LOGP(DLRSPRO, LOGL_DEBUG, "RSPRO sending PING\n");
	rspro_client_send_ping(rsproc);
}

struct osmo_rspro_client *osmo_rspro_client_create(void *talloc_ctx,
						 const char *unit_name,
						 const char *ip_addr,
						 unsigned int tcp_port,
						 osmo_rspro_client_read_cb_t read_cb)
{
	struct osmo_rspro_client *rsproc;
	int rc;

	rsproc = talloc_zero(talloc_ctx, struct osmo_rspro_client);
	OSMO_ASSERT(rsproc);

	/* struct ipaccess_unit has a non-const unit_name, so let's copy to be
	 * able to have a non-const unit_name here as well. To not taint the
	 * public rspro_client API, let's store it in a const char* anyway. */
	rsproc->unit_name = talloc_strdup(rsproc, unit_name);
	OSMO_ASSERT(rsproc->unit_name);

	rsproc->link = ipa_client_conn_create(rsproc,
					     /* no e1inp */ NULL,
					     0,
					     ip_addr, tcp_port,
					     rspro_client_updown_cb,
					     rspro_client_read_cb,
					     /* default write_cb */ NULL,
					     rsproc);
	if (!rsproc->link)
		goto failed;

	osmo_timer_setup(&rsproc->connect_timer, connect_timer_cb, rsproc);

	rc = rspro_client_connect(rsproc);
	if (rc < 0)
		goto failed;

	rsproc->read_cb = read_cb;

	return rsproc;

failed:
	osmo_rspro_client_destroy(rsproc);
	return NULL;
}

void osmo_rspro_client_destroy(struct osmo_rspro_client *rsproc)
{
	osmo_timer_del(&rsproc->connect_timer);
	osmo_timer_del(&rsproc->ping_timer);

	if (rsproc->link) {
		ipa_client_conn_close(rsproc->link);
		ipa_client_conn_destroy(rsproc->link);
		rsproc->link = NULL;
	}
	talloc_free(rsproc);
}

int osmo_rspro_client_send(struct osmo_rspro_client *rsproc, struct msgb *msg)
{
	if (!rsproc || !rsproc->is_connected) {
		LOGP(DLRSPRO, LOGL_ERROR, "RSPRO not connected, unable to send %s\n", msgb_hexdump(msg));
		msgb_free(msg);
		return -ENOTCONN;
	}

	client_send(rsproc, IPAC_PROTO_EXT_RSPRO, msg);

	return 0;
}

struct msgb *osmo_rspro_client_msgb_alloc(void)
{
	return msgb_alloc_headroom(4000, 64, __func__);
}
