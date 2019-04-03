/* (C) 2018-2019 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */


#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <csv.h>

#include "bankd.h"

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


#include <wintypes.h>
#include <winscard.h>
#include <pcsclite.h>

#define PCSC_ERROR(w, rv, text) \
if (rv != SCARD_S_SUCCESS) { \
	LOGW((w), text ": %s (0x%lX)\n", pcsc_stringify_error(rv), rv); \
	goto end; \
} else { \
        LOGW((w), ": OK\n"); \
}

static int pcsc_open_card(struct bankd_worker *worker)
{
	long rc;

	if (!worker->reader.pcsc.hContext) {
		LOGW(worker, "Attempting to open PC/SC context\n");
		/* The PC/SC context must be created inside the thread where we'll later use it */
		rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &worker->reader.pcsc.hContext);
		PCSC_ERROR(worker, rc, "SCardEstablishContext")
	}

	if (!worker->reader.pcsc.hCard) {
		LOGW(worker, "Attempting to open card/slot '%s'\n", worker->reader.name);
		DWORD dwActiveProtocol;
		rc = SCardConnect(worker->reader.pcsc.hContext, worker->reader.name, SCARD_SHARE_SHARED,
				  SCARD_PROTOCOL_T0, &worker->reader.pcsc.hCard, &dwActiveProtocol);
		PCSC_ERROR(worker, rc, "SCardConnect")
	}

	/* use DWORD type as this is what the PC/SC API expects */
	char pbReader[MAX_READERNAME];
	DWORD dwReaderLen = sizeof(pbReader);
	DWORD dwAtrLen = worker->card.atr_len = sizeof(worker->card.atr);
	DWORD dwState, dwProt;
	rc = SCardStatus(worker->reader.pcsc.hCard, pbReader, &dwReaderLen, &dwState, &dwProt,
			 worker->card.atr, &dwAtrLen);
	PCSC_ERROR(worker, rc, "SCardStatus")
	worker->card.atr_len = dwAtrLen;
	LOGW(worker, "Card ATR: %s\n", osmo_hexdump_nospc(worker->card.atr, worker->card.atr_len));
end:
	return rc;
}

static int pcsc_transceive(struct bankd_worker *worker, const uint8_t *out, size_t out_len,
			   uint8_t *in, size_t *in_len)
{
	const SCARD_IO_REQUEST *pioSendPci = SCARD_PCI_T0;
	SCARD_IO_REQUEST pioRecvPci;
	long rc;

	rc = SCardTransmit(worker->reader.pcsc.hCard, pioSendPci, out, out_len, &pioRecvPci, in, in_len);
	PCSC_ERROR(worker, rc, "SCardTransmit");

end:
	return rc;
}

static void pcsc_cleanup(struct bankd_worker *worker)
{
	if (worker->reader.pcsc.hCard) {
		SCardDisconnect(worker->reader.pcsc.hCard, SCARD_UNPOWER_CARD);
		worker->reader.pcsc.hCard = 0;
	}
	if (worker->reader.pcsc.hContext) {
		SCardReleaseContext(worker->reader.pcsc.hContext);
		worker->reader.pcsc.hContext = 0;
	}
}

const struct bankd_driver_ops pcsc_driver_ops = {
	.open_card = pcsc_open_card,
	.transceive = pcsc_transceive,
	.cleanup = pcsc_cleanup,
};
