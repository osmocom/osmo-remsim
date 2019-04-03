/*! \file reader_pcsc.c
 * Card reader driver core */
/*
 * (C) 2018 by Harald Welte <laforge@gnumonks.org>
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

#include <stdio.h>
#include <talloc.h>
#include <osmocom/core/linuxlist.h>

#include "internal.h"

static LLIST_HEAD(g_card_reader_drivers);
static LLIST_HEAD(g_card_readers);

struct card_reader *card_reader_alloc(void *ctx, const char *name,
					const struct card_reader_driver *drv, void *drv_handle)
{
	struct card_reader *cr = talloc_zero(ctx, struct card_reader);
	if (!cr)
		return NULL;

	cr->name = talloc_strdup(ctx, name);
	cr->drv = drv;
	cr->drv_handle = drv_handle;
	INIT_LLIST_HEAD(&cr->slots);

	llist_add(&cr->list, &g_card_readers);

	printf("allocated reader '%s'\n", cr->name);

	return cr;
}

/* allocate a new slot in the given reader */ 
struct card_reader_slot *card_reader_slot_alloc(struct card_reader *cr, unsigned int slot_num)
{
	struct card_reader_slot *cs = talloc_zero(cr, struct card_reader_slot);
	if (!cs)
		return NULL;

	cs->reader = cr;
	llist_add(&cr->list, &cr->slots);
	cs->num = slot_num;

	return cs;
}


/* register a driver with the core, should typcially be called at start-up */
void card_reader_driver_register(struct card_reader_driver *drv)
{
	llist_add_tail(&drv->list, &g_card_reader_drivers);
}

/* probe all readers on all drivers */
void card_readers_probe(void *ctx)
{
	struct card_reader_driver *drv;

	llist_for_each_entry(drv, &g_card_reader_drivers, list) {
		printf("probing driver '%s' for drivers\n", drv->name);
		drv->ops->probe(ctx);
	}
}
