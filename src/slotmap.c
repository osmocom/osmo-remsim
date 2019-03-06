
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <pthread.h>

#include <talloc.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>

#include "slotmap.h"

const struct value_string slot_map_state_name[] = {
	{ SLMAP_S_NEW,			"NEW" },
	{ SLMAP_S_UNACKNOWLEDGED,	"UNACKNOWLEDGED" },
	{ SLMAP_S_ACTIVE,		"ACTIVE" },
	{ SLMAP_S_DELETE_REQ,		"DELETE_REQ" },
	{ SLMAP_S_DELETING,		"DELETING" },
	{ 0, NULL }
};

const char *slotmap_name(char *buf, size_t buf_len, const struct slot_mapping *map)
{
	snprintf(buf, buf_len, "B(%u:%u) <-> C(%u:%u)",
		 map->bank.bank_id, map->bank.slot_nr, map->client.client_id, map->client.slot_nr);
	return buf;
}


/* thread-safe lookup of map by client:slot */
struct slot_mapping *slotmap_by_client(struct slotmaps *maps, const struct client_slot *client)
{
	struct slot_mapping *map;

	pthread_rwlock_rdlock(&maps->rwlock);
	llist_for_each_entry(map, &maps->mappings, list) {
		if (client_slot_equals(&map->client, client)) {
			pthread_rwlock_unlock(&maps->rwlock);
			return map;
		}
	}
	pthread_rwlock_unlock(&maps->rwlock);
	return NULL;
}

/* thread-safe lookup of map by bank:slot */
struct slot_mapping *slotmap_by_bank(struct slotmaps *maps, const struct bank_slot *bank)
{
	struct slot_mapping *map;

	pthread_rwlock_rdlock(&maps->rwlock);
	llist_for_each_entry(map, &maps->mappings, list) {
		if (bank_slot_equals(&map->bank, bank)) {
			pthread_rwlock_unlock(&maps->rwlock);
			return map;
		}
	}
	pthread_rwlock_unlock(&maps->rwlock);
	return NULL;

}

/* thread-safe creating of a new bank<->client map */
struct slot_mapping *slotmap_add(struct slotmaps *maps, const struct bank_slot *bank,
				 const struct client_slot *client)
{
	struct slot_mapping *map;
	char mapname[64];

	/* We assume a single thread (main thread) will ever update the mappings,
	 * and hence we don't have any races by first grabbing + releasing the read
	 * lock twice before grabbing the writelock below */

	map = slotmap_by_bank(maps, bank);
	if (map) {
		fprintf(stderr, "BANKD %u:%u already in use, cannot add new map\n",
			bank->bank_id, bank->slot_nr);
		return NULL;
	}

	map = slotmap_by_client(maps, client);
	if (map) {
		fprintf(stderr, "CLIENT %u:%u already in use, cannot add new map\n",
			client->client_id, client->slot_nr);
		return NULL;
	}

	/* allocate new mapping and add to list of mappings */
	map = talloc_zero(maps, struct slot_mapping);
	if (!map)
		return NULL;

	map->maps = maps;
	map->bank = *bank;
	map->client = *client;

	pthread_rwlock_wrlock(&maps->rwlock);
	llist_add_tail(&map->list, &maps->mappings);
#ifdef REMSIM_SERVER
	map->state = SLMAP_S_NEW;
	INIT_LLIST_HEAD(&map->bank_list); /* to ensure llist_del() always succeeds */
#endif
	pthread_rwlock_unlock(&maps->rwlock);

	printf("Slot Map %s added\n", slotmap_name(mapname, sizeof(mapname), map));

	return map;
}

/* thread-safe removal of a bank<->client map */
void slotmap_del(struct slotmaps *maps, struct slot_mapping *map)
{
	char mapname[64];

	printf("Slot Map %s deleted\n", slotmap_name(mapname, sizeof(mapname), map));

	pthread_rwlock_wrlock(&maps->rwlock);
	llist_del(&map->list);
#ifdef REMSIM_SERVER
	llist_del(&map->bank_list);
#endif
	pthread_rwlock_unlock(&maps->rwlock);

	talloc_free(map);
}

struct slotmaps *slotmap_init(void *ctx)
{
	struct slotmaps *sm = talloc_zero(ctx, struct slotmaps);

	INIT_LLIST_HEAD(&sm->mappings);
	pthread_rwlock_init(&sm->rwlock, NULL);

	return sm;
}

#ifdef REMSIM_SERVER

void _slotmap_state_change(struct slot_mapping *map, enum slot_mapping_state new_state,
			   struct llist_head *new_bank_list)
{
	char mapname[64];

	printf("Slot Map %s state change: %s -> %s\n", slotmap_name(mapname, sizeof(mapname), map),
		get_value_string(slot_map_state_name, map->state),
		get_value_string(slot_map_state_name, new_state));

	map->state = new_state;
#ifdef REMSIM_SERVER
	llist_del(&map->bank_list);
#endif
	if (new_bank_list)
		llist_add_tail(&map->bank_list, new_bank_list);
#ifdef REMSIM_SERVER
	else
		INIT_LLIST_HEAD(&map->bank_list);
#endif
}


void slotmap_state_change(struct slot_mapping *map, enum slot_mapping_state new_state,
			  struct llist_head *new_bank_list)
{
	pthread_rwlock_wrlock(&map->maps->rwlock);
	_slotmap_state_change(map, new_state, new_bank_list);
	pthread_rwlock_unlock(&map->maps->rwlock);
}

#endif
