/*! \file main.c */
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

static void *g_ctx;
__thread void *talloc_asn1_ctx;
int asn_debug;

int main(int argc, char **argv)
{
	asn_debug = 0;
	g_ctx = talloc_named_const(NULL, 0, "main");
	talloc_asn1_ctx = talloc_named_const(g_ctx, 0, "asn1_context");
	card_readers_probe(g_ctx);
	return 0;
}
