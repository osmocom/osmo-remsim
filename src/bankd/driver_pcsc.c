/*! \file reader_pcsc.c
 * PC/SC Card reader backend for libosmosim. */
/*
 * (C) 2012 by Harald Welte <laforge@gnumonks.org>
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


#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include <talloc.h>
#include <osmocom/core/linuxlist.h>

#include <wintypes.h>
#include <winscard.h>

#include "internal.h"

#define PCSC_ERROR(rv, text) \
if (rv != SCARD_S_SUCCESS) { \
	fprintf(stderr, text ": %s (0x%lX)\n", pcsc_stringify_error(rv), rv); \
	goto end; \
} else { \
        printf(text ": OK\n\n"); \
}

static void pcsc_readers_probe(void *ctx)
{
	LONG rc;
	LPSTR mszReaders = NULL;
	DWORD dwReaders;
	SCARDCONTEXT hContext;
	unsigned int num_readers;
	char *ptr;

	rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	PCSC_ERROR(rc, "SCardEstablishContext");

	dwReaders = SCARD_AUTOALLOCATE;
	rc = SCardListReaders(hContext, NULL, (LPSTR)&mszReaders, &dwReaders);
	PCSC_ERROR(rc, "SCardListReaders");

	num_readers = 0;
	ptr = mszReaders;
	while (*ptr != '\0') {
		struct card_reader *cr;
		/* while CCID has the nice feature to distinguish between readers and slots, PC/SC
		 * doesn't have this distinction, so we end up having one "reader" per slot */
		cr = card_reader_alloc(ctx, ptr, NULL, NULL);
		card_reader_slot_alloc(cr, 0);
		ptr += strlen(ptr)+1;
		num_readers++;
	}

	printf("num_readers=%d\n", num_readers);

end:
	if (mszReaders)
		SCardFreeMemory(hContext, mszReaders);
}

static int pcsc_reader_open_slot(struct card_reader_slot *slot)
{
#if 0
	struct osim_card_hdl *card;
	LONG rc;

	if (proto != OSIM_PROTO_T0)
		return NULL;

	rc = SCardConnect(st->hContext, st->name, SCARD_SHARE_SHARED,
			  SCARD_PROTOCOL_T0, &st->hCard, &st->dwActiveProtocol);
	PCSC_ERROR(rc, "SCardConnect");

	st->pioSendPci = SCARD_PCI_T0;

	card = talloc_zero(rh, struct osim_card_hdl);
	INIT_LLIST_HEAD(&card->channels);
	card->reader = rh;
	rh->card = card;

end:
#endif
	return -1;
}


static const struct card_reader_driver_ops pcsc_driver_ops = {
	.probe = pcsc_readers_probe,
	.open_slot = pcsc_reader_open_slot,
	.close_slot = NULL,
	.transceive_apdu = NULL,
};

static struct card_reader_driver pcsc_driver = {
	.name = "PCSC",
	.ops = &pcsc_driver_ops,
};

__attribute__ ((constructor)) void pcsc_reader_init(void)
{
	card_reader_driver_register(&pcsc_driver);
}
