#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <osmocom/core/linuxlist.h>

#define REMSIM_SERVER 1

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

enum slot_mapping_state {
	SLMAP_S_NEW,		/* created; not yet sent to bankd */
	SLMAP_S_UNACKNOWLEDGED,	/* created + sent to bankd but not yet acknowledge by bankd */
	SLMAP_S_ACTIVE,		/* fully active map; acknowledged by bankd */
	SLMAP_S_DELETE_REQ,	/* fully active map; REST has requested deletion */
	SLMAP_S_DELETING,	/* RSPRO has issued Remove to bankd, but bankd hasn't confirmed yet */
};
extern const struct value_string slot_map_state_name[];
static inline const char *slotmap_state_name(enum slot_mapping_state st)
{
	return get_value_string(slot_map_state_name, st);
}

/* slot mappings are created / removed by the server */
struct slot_mapping {
	/* global lits of bankd slot mappings */
	struct llist_head list;
	struct slotmaps *maps;

	/* slot on bank side */
	struct bank_slot bank;
	/* slot on client side */
	struct client_slot client;

#ifdef REMSIM_SERVER
	struct llist_head bank_list;
	enum slot_mapping_state state;
#endif
};

/* collection of slot mappings */
struct slotmaps {
	struct llist_head mappings;
	pthread_rwlock_t rwlock;
};

uint32_t slotmap_get_id(const struct slot_mapping *map);

/* thread-safe lookup of map by client:slot */
struct slot_mapping *slotmap_by_client(struct slotmaps *maps, const struct client_slot *client);

/* thread-safe lookup of map by bank:slot */
struct slot_mapping *slotmap_by_bank(struct slotmaps *maps, const struct bank_slot *bank);

/* thread-safe creating of a new bank<->client map */
struct slot_mapping *slotmap_add(struct slotmaps *maps, const struct bank_slot *bank, const struct client_slot *client);

/* thread-safe removal of a bank<->client map */
void slotmap_del(struct slotmaps *maps, struct slot_mapping *map);

/* initialize the entire map collection */
struct slotmaps *slotmap_init(void *ctx);

#ifdef REMSIM_SERVER
void _slotmap_state_change(struct slot_mapping *map, enum slot_mapping_state new_state,
			   struct llist_head *new_bank_list);
/* thread-safe way to change the state of given slot map */
void slotmap_state_change(struct slot_mapping *map, enum slot_mapping_state new_state,
			  struct llist_head *new_bank_list);
#endif
