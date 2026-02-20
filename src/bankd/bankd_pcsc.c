/* (C) 2018-2020 by Harald Welte <laforge@gnumonks.org>
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
 */


#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <csv.h>
#include <regex.h>
#include <errno.h>

#include "bankd.h"

struct pcsc_slot_name {
	struct llist_head list;
	/* RSPRO bank slot number */
	struct bank_slot slot;
	/* String name of the reader in PC/SC world */
	const char *name_regex;
};

/* return a talloc-allocated string containing human-readable POSIX regex error */
static char *get_regerror(void *ctx, int errcode, regex_t *compiled)
{
	size_t len = regerror(errcode, compiled, NULL, 0);
	char *buffer = talloc_size(ctx, len);
	OSMO_ASSERT(buffer);
	regerror(errcode, compiled, buffer, len);
	return buffer;
}

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
		ps->cur->name_regex = talloc_strdup(ps->cur, field);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void cb2(int c, void *data)
{
	struct parser_state *ps = data;
	struct pcsc_slot_name *sn = ps->cur;
	regex_t compiled_name;
	int rc;

	LOGP(DMAIN, LOGL_INFO, "PC/SC slot name: %u/%u -> regex '%s'\n",
	     sn->slot.bank_id, sn->slot.slot_nr, sn->name_regex);

	if (!sn->name_regex) {
		LOGP(DMAIN, LOGL_ERROR, "B%d:%d: No reader name given. Maybe invalid csv.\n",
		     sn->slot.bank_id, sn->slot.slot_nr);
		talloc_free(sn);
		goto out;
	}

	memset(&compiled_name, 0, sizeof(compiled_name));

	rc = regcomp(&compiled_name, sn->name_regex, REG_EXTENDED);
	if (rc != 0) {
		char *errmsg = get_regerror(sn, rc, &compiled_name);
		LOGP(DMAIN, LOGL_ERROR, "B%d:%d: Error compiling regex '%s': %s - Ignoring\n",
		     sn->slot.bank_id, sn->slot.slot_nr, sn->name_regex, errmsg);
		talloc_free(errmsg);
		talloc_free(sn);
	} else {
		llist_add_tail(&sn->list, &ps->bankd->pcsc_slot_names);
	}
	regfree(&compiled_name);

out:
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

	if (csv_init(&p, CSV_APPEND_NULL) != 0) {
		LOGP(DMAIN, LOGL_FATAL, "Error during csv_init\n");
		return -1;
	}

	fp = fopen(csv_file, "rb");
	if (!fp) {
		LOGP(DMAIN, LOGL_FATAL, "Error opening %s: %s\n", csv_file, strerror(errno));
		return -1;
	}

	parser_state_init(&ps);
	ps.bankd = bankd;

	while ((bytes_read = fread(buf, 1, sizeof(buf), fp)) > 0) {
		if (csv_parse(&p, buf, bytes_read, cb1, cb2, &ps) != bytes_read) {
			LOGP(DMAIN, LOGL_FATAL, "Error parsing bankd PC/SC CSV: %s\n",
			     csv_strerror(csv_error(&p)));
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
			return cur->name_regex;
	}
	return NULL;
}


#include <wintypes.h>
#include <winscard.h>
#include <pcsclite.h>

#define LOGW_PCSC_ERROR(w, rv, text) \
	LOGW((w), text ": %s (0x%lX)\n", pcsc_stringify_error(rv), rv)

#define PCSC_ERROR(w, rv, text) \
if (rv != SCARD_S_SUCCESS) { \
	LOGW_PCSC_ERROR(w, rv, text); \
	goto end; \
} else { \
	LOGW((w), text ": OK\n"); \
}

static DWORD bankd_share_mode(struct bankd *bankd)
{
	if (bankd->cfg.permit_shared_pcsc)
		return SCARD_SHARE_SHARED;
	else
		return SCARD_SHARE_EXCLUSIVE;
}

static int pcsc_get_atr(struct bankd_worker *worker)
{
	long rc;
	char pbReader[MAX_READERNAME];
	/* use DWORD type as this is what the PC/SC API expects */
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


static int pcsc_connect_slot_regex(struct bankd_worker *worker)
{
	DWORD dwReaders = SCARD_AUTOALLOCATE;
	LPSTR mszReaders = NULL;
	regex_t compiled_name;
	int result = -1;
	LONG rc;
	char *p;

	LOGW(worker, "Attempting to find card/slot using regex '%s'\n", worker->reader.name);

	rc = regcomp(&compiled_name, worker->reader.name, REG_EXTENDED);
	if (rc != 0) {
		LOGW(worker, "Error compiling RegEx over name '%s'\n", worker->reader.name);
		return -EINVAL;
	}

	rc = SCardListReaders(worker->reader.pcsc.hContext, NULL, (LPSTR)&mszReaders, &dwReaders);
	if (rc != SCARD_S_SUCCESS) {
		LOGW_PCSC_ERROR(worker, rc, "SCardListReaders");
		goto out_regfree;
	}

	p = mszReaders;
	while (*p) {
		DWORD dwActiveProtocol;
		int r = regexec(&compiled_name, p, 0, NULL, 0);
		if (r == 0) {
			LOGW(worker, "Attempting to open card/slot '%s'\n", p);
			rc = SCardConnect(worker->reader.pcsc.hContext, p, bankd_share_mode(worker->bankd),
					  SCARD_PROTOCOL_T0, &worker->reader.pcsc.hCard,
					  &dwActiveProtocol);
			if (rc == SCARD_S_SUCCESS)
				result = 0;
			else {
				LOGW_PCSC_ERROR(worker, rc, "SCardConnect");
				goto out_readerfree;
			}
			break;
		}
		p += strlen(p) + 1;
	}

	if (result < 0)
		LOGW(worker, "Error: Cannot find PC/SC reader/slot matching using regex '%s'\n", worker->reader.name);

out_readerfree:
	SCardFreeMemory(worker->reader.pcsc.hContext, mszReaders);

out_regfree:
	regfree(&compiled_name);

	return result;
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
		rc = pcsc_connect_slot_regex(worker);
		if (rc != 0)
			goto end;
	}

	rc = pcsc_get_atr(worker);

end:
	return rc;
}

static int pcsc_reset_card(struct bankd_worker *worker, bool cold_reset)
{
	long rc;
	DWORD dwActiveProtocol;

	LOGW(worker, "Resetting card in '%s' (%s)\n", worker->reader.name,
		cold_reset ? "cold reset" : "warm reset");
	rc = SCardReconnect(worker->reader.pcsc.hCard, bankd_share_mode(worker->bankd), SCARD_PROTOCOL_T0,
			    cold_reset ? SCARD_UNPOWER_CARD : SCARD_RESET_CARD, &dwActiveProtocol);
	PCSC_ERROR(worker, rc, "SCardReconnect");

	rc = pcsc_get_atr(worker);
end:
	return rc;
}

static int pcsc_transceive(struct bankd_worker *worker, const uint8_t *out, size_t out_len,
			   uint8_t *in, size_t *in_len)
{
	const SCARD_IO_REQUEST *pioSendPci = SCARD_PCI_T0;
	SCARD_IO_REQUEST pioRecvPci;
	long rc;

	/* DWORD can be different from size_t */
	DWORD in_len_d = *in_len;

	rc = SCardTransmit(worker->reader.pcsc.hCard, pioSendPci, out, out_len, &pioRecvPci, in, &in_len_d);
	/* don't use PCSC_ERROR here as we don't want to log every successful SCardTransmit */
	if (rc != SCARD_S_SUCCESS)
		LOGW_PCSC_ERROR(worker, rc, "SCardTransmit");

	*in_len = in_len_d;
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
	.reset_card = pcsc_reset_card,
	.transceive = pcsc_transceive,
	.cleanup = pcsc_cleanup,
};
