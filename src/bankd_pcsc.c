
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/logging.h>

#include <csv.h>

#include "bankd.h"
#include "rspro_util.h"

/***********************************************************************
 * RSPRO bank/slot-id <-> PCSC Reader name mapping
 ***********************************************************************/

struct pcsc_slot_name {
	struct llist_head list;
	/* RSPRO bank slot number */
	struct bank_slot slot;
	/* String name of the reader in PC/SC world */
	const char *name;
};

enum parser_state_name {
	ST_NONE,
	ST_BANK_NR,
	ST_SLOT_NR,
	ST_PCSC_NAME,
};
struct parser_state {
	struct bankd *bankd;
	enum parser_state_name state;
	struct pcsc_slot_name *cur;
};


static void parser_state_init(struct parser_state *ps)
{
	ps->state = ST_BANK_NR;
	ps->cur = NULL;
}

static void cb1(void *s, size_t len, void *data)
{
	char *field = (char *) s;
	struct parser_state *ps = data;

	switch (ps->state) {
	case ST_BANK_NR:
		OSMO_ASSERT(!ps->cur);
		ps->cur = talloc_zero(ps->bankd, struct pcsc_slot_name);
		OSMO_ASSERT(ps->cur);
		ps->cur->slot.bank_id = atoi(field);
		ps->state = ST_SLOT_NR;
		break;
	case ST_SLOT_NR:
		OSMO_ASSERT(ps->cur);
		ps->cur->slot.slot_nr = atoi(field);
		ps->state = ST_PCSC_NAME;
		break;
	case ST_PCSC_NAME:
		OSMO_ASSERT(ps->cur);
		ps->cur->name = talloc_strdup(ps->cur, field);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void cb2(int c, void *data)
{
	struct parser_state *ps = data;
	struct pcsc_slot_name *sn = ps->cur;

	printf("PC/SC slot name: %u/%u -> '%s'\n", sn->slot.bank_id, sn->slot.slot_nr, sn->name);
	llist_add_tail(&sn->list, &ps->bankd->pcsc_slot_names);

	ps->state = ST_BANK_NR;
	ps->cur = NULL;
}

int bankd_pcsc_read_slotnames(struct bankd *bankd, const char *csv_file)
{
	FILE *fp;
	struct csv_parser p;
	char buf[1024];
	size_t bytes_read;
	struct parser_state ps;

	if (csv_init(&p, CSV_APPEND_NULL) != 0)
		return -1;

	fp = fopen(csv_file, "rb");
	if (!fp)
		return -1;

	parser_state_init(&ps);
	ps.bankd = bankd;

	while ((bytes_read = fread(buf, 1, sizeof(buf), fp)) > 0) {
		if (csv_parse(&p, buf, bytes_read, cb1, cb2, &ps) != bytes_read) {
			fprintf(stderr, "Error parsing CSV: %s\n", csv_strerror(csv_error(&p)));
			fclose(fp);
			return -1;
		}
	}

	csv_fini(&p, cb1, cb2, &ps);
	fclose(fp);
	csv_free(&p);

	return 0;
}

const char *bankd_pcsc_get_slot_name(struct bankd *bankd, const struct bank_slot *slot)
{
	struct pcsc_slot_name *cur;

	llist_for_each_entry(cur, &bankd->pcsc_slot_names, list) {
		if (bank_slot_equals(&cur->slot, slot))
			return cur->name;
	}
	return NULL;
}


/***********************************************************************
 * SCard related FSM
 ***********************************************************************/

#define S(x)	(1 << (x))

#define T2_TIMEOUT_SECS		10
#define T1_TIMEOUT_SECS		10

enum sc_fsm_states {
	SC_ST_CARD_ABSENT,
	SC_ST_CARD_PRESENT,
};

static const struct value_string sc_fsm_event_names[] = {
	{ SC_E_CONNECT_CMD,	"CONNECT_CMD" },
	{ SC_E_DISCONNECT_CMD,	"DISCONNECT_CMD" },
	{ SC_E_TPDU_CMD,	"TPDU_CMD" },
	{ 0, NULL }
};

/* an attempt at SCardConnect */
static void attempt_sc_connect(struct osmo_fsm_inst *fi)
{
	struct bankd_worker *worker = fi->priv;
	LONG rc;
	DWORD protocol;

	/* another attempt at SCardConnect */
	rc = SCardConnect(worker->reader.pcsc.hContext, worker->reader.name,
			  SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0,
			  &worker->reader.pcsc.hCard, &protocol);
	if (rc == SCARD_S_SUCCESS) {
		osmo_fsm_inst_state_chg(fi, SC_ST_CARD_PRESENT, T2_TIMEOUT_SECS, 2);
		/* FIXME: inform client */
	} else {
		/* schedule the next SCardConnect request */
		osmo_timer_schedule(&fi->timer, T1_TIMEOUT_SECS, 1);
	}
}

/* no card currently present; attempt to re-connect via timer if asked to */
static void sc_st_card_absent(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bankd_worker *worker = fi->priv;
	const struct TpduModemToCard *mdm2sim;
	const RsproPDU_t *pdu, *pdu_resp;

	switch (event) {
	case SC_E_CONNECT_CMD:
		attempt_sc_connect(fi);
		break;
	case SC_E_TPDU_CMD:
		pdu = data;
		mdm2sim = &pdu->msg.choice.tpduModemToCard;
		/* reject transceiving the PDU; we're not connected */
#if 0
		pdu_resp = rspro_gen_TpduCard2Modem(&mdm2sim->toBankSlot, &mdm2sim->fromClientSlot,
						    rx_buf, rx_buf_len);
		worker_send_rspro(worker, pdu_resp);
#endif
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void sc_st_card_present(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bankd_worker *worker = fi->priv;
	const RsproPDU_t *pdu;
	LONG rc;

	switch (event) {
	case SC_E_TPDU_CMD:
		/* transceive an APDU */
		pdu = data;
		worker_handle_tpduModemToCard(worker, pdu);
		break;
	case SC_E_DISCONNECT_CMD:
		rc = SCardDisconnect(worker->reader.pcsc.hCard, SCARD_UNPOWER_CARD);
		/* FIXME: evaluate rc */
		osmo_fsm_inst_state_chg(fi, SC_ST_CARD_ABSENT, 0, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int sc_timer_cb(struct osmo_fsm_inst *fi)
{
	struct bankd_worker *worker = fi->priv;
	char reader_name[32];
	uint8_t atr[32];
	DWORD reader_state, protocol;
	DWORD atr_len = sizeof(atr);
	DWORD reader_name_len = sizeof(atr);
	LONG rc;

	switch (fi->T) {
	case 1:
		attempt_sc_connect(fi);
		break;
	case 2:
		/* another iteration of SCardStatus */
		rc = SCardStatus(worker->reader.pcsc.hCard, reader_name, &reader_name_len,
				 &reader_state, &protocol, atr, &atr_len);
		if (rc == SCARD_S_SUCCESS) {
			RsproPDU_t *pdu = NULL;
			/* Determine any changes in state, and if so, report to client */
			if (reader_state != worker->reader.pcsc.dwState) {
				worker->reader.pcsc.dwState = reader_state;
				/* FIXME: inform client */
				//pdu = rspro_gen_SetAtrReq(foo, bar, worker->atr, worker->atr_len);
				//worker_send_rspro(worker, pdu);
			}
			if (atr_len != worker->atr_len || memcmp(atr, worker->atr, atr_len)) {
				ClientSlot_t clslot = client_slot2asn(&worker->client.clslot);
				OSMO_ASSERT(atr_len < sizeof(worker->atr));
				memcpy(worker->atr, atr, atr_len);
				worker->atr_len = atr_len;
				/* inform client */
				pdu = rspro_gen_SetAtrReq(&clslot, worker->atr, worker->atr_len);
				worker_send_rspro(worker, pdu);
			}
			/* schedule the next SCardStatus request */
			osmo_timer_schedule(&fi->timer, T2_TIMEOUT_SECS, 0);
		} else
			osmo_fsm_inst_state_chg(fi, SC_ST_CARD_ABSENT, T1_TIMEOUT_SECS, 1);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static const struct osmo_fsm_state sc_fsm_states[] = {
	[SC_ST_CARD_ABSENT] = {
		.in_event_mask = S(SC_E_CONNECT_CMD) | S(SC_E_DISCONNECT_CMD) | S(SC_E_TPDU_CMD),
		.out_state_mask = S(SC_ST_CARD_PRESENT) | S(SC_ST_CARD_ABSENT),
		.name = "CARD_ABSENT",
		.action = sc_st_card_absent,
	},
	[SC_ST_CARD_PRESENT] = {
		.in_event_mask = S(SC_E_DISCONNECT_CMD) | S(SC_E_TPDU_CMD),
		.out_state_mask = S(SC_ST_CARD_PRESENT) | S(SC_ST_CARD_ABSENT),
		.name = "CART_PRESENT",
		.action = sc_st_card_present,
	},
};

static struct osmo_fsm sc_fsm = {
	.name = "SC",
	.states = sc_fsm_states,
	.num_states = ARRAY_SIZE(sc_fsm_states),
	.timer_cb = sc_timer_cb,
	.event_names = sc_fsm_event_names,
};

static bool fsm_initialized = false;

struct osmo_fsm_inst *sc_fsm_alloc(struct bankd_worker *worker)
{
	struct osmo_fsm_inst *fi;
	char num[8];

	if (!fsm_initialized) {
		osmo_fsm_register(&sc_fsm);
		fsm_initialized = true;
	}

	snprintf(num, 8, "%d", worker->num);

	fi = osmo_fsm_inst_alloc(&sc_fsm, worker, worker, LOGL_DEBUG, num);

	osmo_fsm_inst_dispatch(fi, SC_E_CONNECT_CMD, NULL);

	return fi;
}
