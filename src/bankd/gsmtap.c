/* gsmtap - How to encapsulate SIM protocol traces in GSMTAP
 *
 * (C) 2016-2019 by Harald Welte <hwelte@hmw-consulting.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/* among other things, bring in GNU-specific strerror_r() */
#define _GNU_SOURCE

#include <osmocom/core/gsmtap.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/core/logging.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/uio.h>

#include "debug.h"

/*! global GSMTAP instance */
static struct gsmtap_inst *g_gti;

/*! initialize the global GSMTAP instance for SIM traces
 *
 * \param[in] gsmtap_host Hostname to send GSMTAP packets
 *
 * \return 0 on success, non-zero on error
 */
int bankd_gsmtap_init(const char *gsmtap_host)
{
	if (g_gti)
		return -EEXIST;

	errno = 0;
	g_gti = gsmtap_source_init(gsmtap_host, GSMTAP_UDP_PORT, 0);
	if (!g_gti) {
		LOGP(DGSMTAP, LOGL_ERROR, "unable to initialize GSMTAP\n");
		return -EIO;
	}
	gsmtap_source_add_sink(g_gti);

	LOGP(DGSMTAP, LOGL_INFO, "initialized GSMTAP to %s\n", gsmtap_host);

	return 0;
}

/*! Log one APDU via the global GSMTAP instance by concatenating mdm_tpdu and sim_tpdu.
 *
 *  \param[in] sub_type     GSMTAP sub-type (GSMTAP_SIM_* constant)
 *  \param[in] mdm_tpdu     User-provided buffer with ModemToCard TPDU to log. May be NULL.
 *  \param[in] mdm_tpdu_len Length of ModemToCard TPDU, in bytes.
 *  \param[in] sim_tpdu     User-provided buffer with CardToModem TPDU to log. May be NULL.
 *  \param[in] sim_tpdu_len Length of CardToModem TPDU, in bytes.
 *
 *  \return number of bytes sent on success, -1 on failure
 */
int bankd_gsmtap_send_apdu(uint8_t sub_type, const uint8_t *mdm_tpdu, unsigned int mdm_tpdu_len,
	const uint8_t *sim_tpdu, unsigned int sim_tpdu_len)
{
	const struct gsmtap_hdr gh = {
		.version = GSMTAP_VERSION,
		.hdr_len = sizeof(struct gsmtap_hdr)/4,
		.type = GSMTAP_TYPE_SIM,
		.sub_type = sub_type,
	};

	struct iovec iov[3];
	unsigned int cnt = 0;

	iov[cnt].iov_base = (void *)&gh;
	iov[cnt].iov_len = sizeof(gh);
	cnt++;

	if (mdm_tpdu && mdm_tpdu_len) {
		iov[cnt].iov_base = (void *)mdm_tpdu;
		iov[cnt].iov_len = mdm_tpdu_len;
		cnt++;
	}

	if (sim_tpdu && sim_tpdu_len) {
		iov[cnt].iov_base = (void *)sim_tpdu;
		iov[cnt].iov_len = sim_tpdu_len;
		cnt++;
	}

	LOGP(DGSMTAP, LOGL_DEBUG, "sending APDU sub_type=%u, mdm_tpdu len=%u, sim_tpdu len=%u, iov cnt=%u\n",
		sub_type, mdm_tpdu_len, sim_tpdu_len, cnt);

	const int rc = writev(gsmtap_inst_fd(g_gti), iov, cnt);
	if (rc < 0) {
		char errtxt[128];
		LOGP(DGSMTAP, LOGL_ERROR, "writev() failed with errno=%d: %s\n", errno, strerror_r(errno,
			errtxt, sizeof(errtxt)));
		return rc;
	}

	return 0;
}
