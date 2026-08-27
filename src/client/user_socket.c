#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>

#include "client.h"

/* This is a remsim-client with a unix socket to exchange APDUs. */

struct socket_state {
	struct osmo_fd ofd;
	struct sockaddr_un addr;
        socklen_t addr_len;
	struct bankd_client *bc;
};

/***********************************************************************
 * stdin frontend code to remsim-client
 ***********************************************************************/

int frontend_request_card_insert(struct bankd_client *bc)
{
	LOGP(DMAIN, LOGL_INFO, "SIM inseterd\n");
	return 0;
}

int frontend_request_card_remove(struct bankd_client *bc)
{
	LOGP(DMAIN, LOGL_INFO, "SIM removed\n");
	return 0;
}

int frontend_request_sim_remote(struct bankd_client *bc)
{
	return 0;
}

int frontend_request_sim_local(struct bankd_client *bc)
{
	return 0;
}

int frontend_request_modem_reset(struct bankd_client *bc)
{
	return 0;
}

int frontend_handle_card2modem(struct bankd_client *bc, const uint8_t *data, size_t len)
{
	struct socket_state *ss = bc->data;
	int rc;

	OSMO_ASSERT(data);

	LOGP(DMAIN, LOGL_INFO, "APDU response %s\n", osmo_hexdump(data, len));

	rc = sendto(ss->ofd.fd, data, len, 0, (struct sockaddr *)&ss->addr, ss->addr_len);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to write to socket (errno = %d).\n", errno);
		return rc;
	}

	return 0;
}

int frontend_handle_set_atr(struct bankd_client *bc, const uint8_t *data, size_t len)
{
	struct socket_state *ss = bc->data;
	int rc;

	OSMO_ASSERT(data);

	/* FIXME: Why do we get this weird ATR before the actual one. */
	if (len <= 2)
		return -EINVAL;

	LOGP(DMAIN, LOGL_INFO, "SET_ATR %s\n", osmo_hexdump(data, len));

	rc = sendto(ss->ofd.fd, data, len, 0, (struct sockaddr *)&ss->addr, ss->addr_len);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to write to socket (errno = %d).\n", errno);
		return rc;
	}
	return 0;
}

int frontend_handle_slot_status(struct bankd_client *bc, const SlotPhysStatus_t *sts)
{
	return 0;
}

int frontend_append_script_env(struct bankd_client *bc, char **env, int idx, size_t max_env)
{
	return idx;
}


/***********************************************************************
 * Incoming command from the user application (stdin shell in our case)
 ***********************************************************************/

/* call-back function for socket read. */
static int socket_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct socket_state *ss = ofd->data;
	struct frontend_tpdu ftpdu;
	uint8_t buf[1024];
	int rc;

	OSMO_ASSERT(what & OSMO_FD_READ);

        ss->addr_len = sizeof(ss->addr);
	rc = recvfrom(ss->ofd.fd, buf, sizeof(buf), 0, (struct sockaddr *)&ss->addr, &ss->addr_len);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to read from socket (errno = %d).\n", errno);
		return rc;
	}
	if (rc == 0) {
#if 0
		LOGP(DMAIN, LOGL_DEBUG, "Reset card\n");
		/* reset the [remote] card */
		struct frontend_phys_status pstatus = {
			.flags = {
				.reset_active = true,
				.vcc_present = false,
				.clk_active = false,
				.card_present = true,
			},
			.voltage_mv = 0,
			.fi = 0,
			.di = 0,
			.wi = 0,
			.waiting_time = 0,
		};
		osmo_fsm_inst_dispatch(ss->bc->main_fi, MF_E_MDM_STATUS_IND, &pstatus);
#endif
		return 0;
	}

	LOGP(DMAIN, LOGL_DEBUG, "APDU request %s\n", osmo_hexdump(buf, rc));
	ftpdu.buf = buf;
	ftpdu.len = rc;
	osmo_fsm_inst_dispatch(ss->bc->main_fi, MF_E_MDM_TPDU, &ftpdu);

	return 0;
}

/* main function */
int client_user_main(struct bankd_client *bc)
{
	struct client_config *cfg = bc->cfg;
	struct socket_state ss;
	int rc;

	memset(&ss, 0, sizeof(ss));
	ss.bc = bc;
	bc->data = &ss;

	if (!cfg->socket.name) {
		LOGP(DMAIN, LOGL_ERROR, "No socket name specified.\n");
		return -1;
	}
	rc = osmo_sock_unix_init(SOCK_DGRAM, 0, cfg->socket.name, OSMO_SOCK_F_BIND);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to create socket with name '%s' (errno = %d).\n",
		     cfg->socket.name, errno);
		return -1;
	}
	osmo_fd_setup(&ss.ofd, rc, OSMO_FD_READ, &socket_fd_cb, &ss, 0);

	rc = osmo_fd_register(&ss.ofd);
	if (rc < 0)
		return rc;

	while (1) {
		osmo_select_main(0);
	}
}
