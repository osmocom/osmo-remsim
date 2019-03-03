#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include "debug.h"

static const struct log_info_cat default_categories[] = {
	[DMAIN] = {
		.name = "DMAIN",
		.loglevel = LOGL_DEBUG,
		.enabled = 1,
	},
};

const struct log_info log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};
