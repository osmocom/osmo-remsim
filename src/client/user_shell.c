#include <errno.h>
#include <unistd.h>

#include <osmocom/core/select.h>

#include "client.h"

/* This is a remsim-client with an interactive 'shell', where the user
 * can type in C-APDUs in hex formats, which will be sent to the bankd /
 * SIM-card.  Responses received from SIM Card via bankd will be printed
 * in return. */


/***********************************************************************
 * Incoming RSPRO messages from bank-daemon (SIM card)
 ***********************************************************************/

static int bankd_handle_tpduCardToModem(struct bankd_client *bc, const RsproPDU_t *pdu)
{
	OSMO_ASSERT(pdu);
	OSMO_ASSERT(RsproPDUchoice_PR_tpduCardToModem == pdu->msg.present);

	const struct TpduCardToModem *card2modem = &pdu->msg.choice.tpduCardToModem;

	printf("R-APDU: %s\n", osmo_hexdump(card2modem->data.buf, card2modem->data.size));
	fflush(stdout);

	return 0;
}

static int bankd_handle_setAtrReq(struct bankd_client *bc, const RsproPDU_t *pdu)
{
	RsproPDU_t *resp;

	OSMO_ASSERT(pdu);
	OSMO_ASSERT(RsproPDUchoice_PR_setAtrReq == pdu->msg.present);

	printf("SET_ATR: %s\n", osmo_hexdump(pdu->msg.choice.setAtrReq.atr.buf,
					     pdu->msg.choice.setAtrReq.atr.size));
	fflush(stdout);

	resp = rspro_gen_SetAtrRes(ResultCode_ok);
	if (!resp)
		return -ENOMEM;
	server_conn_send_rspro(&bc->bankd_conn, resp);

	return 0;
}


int client_user_bankd_handle_rx(struct rspro_server_conn *bankdc, const RsproPDU_t *pdu)
{
	struct bankd_client *client = bankdc2bankd_client(bankdc);
	switch (pdu->msg.present) {
	case RsproPDUchoice_PR_tpduCardToModem:
		bankd_handle_tpduCardToModem(client, pdu);
		break;
	case RsproPDUchoice_PR_setAtrReq:
		bankd_handle_setAtrReq(client, pdu);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
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
	RsproPDU_t *pdu;
	BankSlot_t bslot;
	uint8_t buf[1024];
	int rc;

	bank_slot2rspro(&bslot, &bc->bankd_slot);

	OSMO_ASSERT(ss->rx_msg);

	if (!strcasecmp(cmd, "RESET")) {
		/* reset the [remote] card */
		pdu = rspro_gen_ClientSlotStatusInd(bc->srv_conn.clslot, &bslot,
						    true, false, false, true);
		server_conn_send_rspro(&bc->bankd_conn, pdu);
	} else {
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
		pdu = rspro_gen_TpduModem2Card(bc->srv_conn.clslot, &bslot, buf, rc);
		server_conn_send_rspro(&bc->bankd_conn, pdu);
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

	/* register stdin file descriptor with osmocom select loop abstraction */
	memset(&ss, 0, sizeof(ss));
	osmo_fd_setup(&ss.ofd, fileno(stdin), OSMO_FD_READ, &stdin_fd_cb, &ss, 0);
	osmo_fd_register(&ss.ofd);
	ss.bc = bc;

	while (1) {
		osmo_select_main(0);
	}
}
