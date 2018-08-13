#pragma once

#include <osmocom/core/linuxlist.h>

struct card_reader_slot;

struct card_reader_driver_ops {
	/* probe system for card readers */
	void (*probe)(void *ctx);
	/* open a given slot, attempt to reset/start the card */
	int (*open_slot)(struct card_reader_slot *slot);
	/* close a given slot, power down the card */
	void (*close_slot)(struct card_reader_slot *slot);
	/* transceive an APDU */
	int (*transceive_apdu)(struct card_reader_slot *slot);
};

struct card_reader_driver {
	/* global list of drivers */
	struct llist_head list;
	/* name of the driver */
	char *name;
	const struct card_reader_driver_ops *ops;
};

struct card_reader {
	/* global list of card readers */
	struct llist_head list;
	/* name of this reader */
	char *name;
	/* driver providing access to this reader */
	const struct card_reader_driver *drv;
	void *drv_handle;
	/* list of card slots for this reader */
	struct llist_head slots;
};

enum card_slot_state {
	CARD_SLOT_OFF,
	CARD_SLOT_OPEN,
};

struct card_reader_slot {
	/* links to card_reader.slots */
	struct llist_head list;
	/* back-pointer to reader serving this slot */
	struct card_reader *reader;
	/* slot number */
	unsigned int num;
	/* state in which the slot is */
	enum card_slot_state state;
};


struct card_reader *card_reader_alloc(void *ctx, const char *name,
					const struct card_reader_driver *drv, void *drv_handle);
struct card_reader_slot *card_reader_slot_alloc(struct card_reader *cr, unsigned int slot_num);

void card_reader_driver_register(struct card_reader_driver *drv);
void card_readers_probe(void *ctx);
