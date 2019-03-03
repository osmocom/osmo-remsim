#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <osmocom/core/linuxlist.h>

struct bank_slot {
	uint16_t bank_id;
	uint16_t slot_nr;
};

static inline bool bank_slot_equals(const struct bank_slot *a, const struct bank_slot *b)
{
	if (a->bank_id == b->bank_id && a->slot_nr == b->slot_nr)
		return true;
	else
		return false;
}

struct client_slot {
	uint16_t client_id;
	uint16_t slot_nr;
};

static inline bool client_slot_equals(const struct client_slot *a, const struct client_slot *b)
{
	if (a->client_id == b->client_id && a->slot_nr == b->slot_nr)
		return true;
	else
		return false;
}

/* slot mappings are created / removed by the server */
struct slot_mapping {
	/* global lits of bankd slot mappings */
	struct llist_head list;
	/* slot on bank side */
	struct bank_slot bank;
	/* slot on client side */
	struct client_slot client;
};

/* collection of slot mappings */
struct slotmaps {
	struct llist_head mappings;
	pthread_rwlock_t rwlock;
};

/* thread-safe lookup of map by client:slot */
struct slot_mapping *slotmap_by_client(struct slotmaps *maps, const struct client_slot *client);

/* thread-safe lookup of map by bank:slot */
struct slot_mapping *slotmap_by_bank(struct slotmaps *maps, const struct bank_slot *bank);

/* thread-safe creating of a new bank<->client map */
int slotmap_add(struct slotmaps *maps, const struct bank_slot *bank, const struct client_slot *client);

/* thread-safe removal of a bank<->client map */
void slotmap_del(struct slotmaps *maps, struct slot_mapping *map);

/* initialize the entire map collection */
struct slotmaps *slotmap_init(void *ctx);
