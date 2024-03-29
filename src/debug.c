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
 */


#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include "debug.h"

static const struct log_info_cat default_categories[] = {
	[DMAIN] = {
		.name = "DMAIN",
		.loglevel = LOGL_INFO,
		.enabled = 1,
	},
	[DST2] = {
		.name = "DST2",
		.loglevel = LOGL_INFO,
		.enabled = 1,
	},
	[DRSPRO] = {
		.name = "DRSPRO",
		.loglevel = LOGL_INFO,
		.enabled = 1,
	},
	[DREST] = {
		.name = "DREST",
		.loglevel = LOGL_INFO,
		.enabled = 1,
	},
	[DSLOTMAP] = {
		.name = "DSLOTMAP",
		.loglevel = LOGL_INFO,
		.enabled = 1,
	},
	[DBANKDW] = {
		.name = "DBANKDW",
		.loglevel = LOGL_INFO,
		.enabled = 1,
	},
	[DGSMTAP] = {
		.name = "DGSMTAP",
		.loglevel = LOGL_INFO,
		.enabled = 1,
	},
};

const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};
