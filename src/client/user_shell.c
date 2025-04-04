#include <errno.h>
#include <unistd.h>

#include <osmocom/core/select.h>

#include "client.h"

/* This is a remsim-client with an interactive 'shell', where the user
 * can type in C-APDUs in hex formats, which will be sent to the bankd /
 * SIM-card.  Responses received from SIM Card via bankd will be printed
 * in return. */


/***********************************************************************
 * stdin frontend code to remsim-client
 ***********************************************************************/

int frontend_request_card_insert(struct bankd_client *bc)
{
	return 0;
}

int frontend_request_card_remove(struct bankd_client *bc)
{
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
	OSMO_ASSERT(data);
	printf("R-APDU: %s\n", osmo_hexdump(data, len));
	fflush(stdout);

	return 0;
}

int frontend_handle_set_atr(struct bankd_client *bc, const uint8_t *data, size_t len)
{
	OSMO_ASSERT(data);

	printf("SET_ATR: %s\n", osmo_hexdump(data, len));
	fflush(stdout);

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

struct stdin_state {
	struct osmo_fd ofd;
	struct msgb *rx_msg;
	struct bankd_client *bc;
};

/* called every time a command on stdin was received */
static void handle_stdin_command(struct stdin_state *ss, char *cmd)
{
	struct bankd_client *bc = ss->bc;
	int rc;

	OSMO_ASSERT(ss->rx_msg);

	if (!strcasecmp(cmd, "RESET")) {
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
		osmo_fsm_inst_dispatch(bc->main_fi, MF_E_MDM_STATUS_IND, &pstatus);
	} else {
		struct frontend_tpdu ftpdu;
		uint8_t buf[1024];

		/* we assume the user has entered a C-APDU as hex string. parse + send */
		rc = osmo_hexparse(cmd, buf, sizeof(buf));
		if (rc < 0) {
			fprintf(stderr, "ERROR parsing C-APDU `%s'!\n", cmd);
			return;
		}
		if (!bc->srv_conn.clslot) {
			fprintf(stderr, "Cannot send command; no client slot\n");
			return;
		}

		/* Send CMD APDU to [remote] card */
		ftpdu.buf = buf;
		ftpdu.len = rc;
		osmo_fsm_inst_dispatch(bc->main_fi, MF_E_MDM_TPDU, &ftpdu);
	}
}

/* call-back function for stdin read. Gather bytes in buffer until CR/LF received */
static int stdin_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct stdin_state *ss = ofd->data;
	char *cur;
	int rc, i;

	OSMO_ASSERT(what & OSMO_FD_READ);

	if (!ss->rx_msg) {
		ss->rx_msg = msgb_alloc(1024, "stdin");
		OSMO_ASSERT(ss->rx_msg);
	}

	cur = (char *) ss->rx_msg->tail;
	rc = read(ofd->fd, cur, msgb_tailroom(ss->rx_msg));
	if (rc < 0)
		return rc;
	if (rc == 0) {
		fprintf(stderr, "STDIN was closed, terminating\n");
		exit(0);
	}
	msgb_put(ss->rx_msg, rc);

	for (i = 0; i < rc; i++) {
		if (cur[i] == '\r' || cur[i] == '\n') {
			cur[i] = '\0';
			/* dispatch the command */
			handle_stdin_command(ss, cur);
			/* FIXME: possibly other commands */
			msgb_free(ss->rx_msg);
			ss->rx_msg = NULL;
		}
	}

	return 0;
}



/* main function */
int client_user_main(struct bankd_client *bc)
{
	struct stdin_state ss;
	int rc;

	/* register stdin file descriptor with osmocom select loop abstraction */
	memset(&ss, 0, sizeof(ss));
	osmo_fd_setup(&ss.ofd, fileno(stdin), OSMO_FD_READ, &stdin_fd_cb, &ss, 0);
	rc = osmo_fd_register(&ss.ofd);
	if (rc < 0)
		return rc;

	ss.bc = bc;

	while (1) {
		osmo_select_main(0);
	}
}
