
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <pthread.h>

#include <talloc.h>

#include <osmocom/core/linuxlist.h>

#include "slotmap.h"

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
int slotmap_add(struct slotmaps *maps, const struct bank_slot *bank, const struct client_slot *client)
{
	struct slot_mapping *map;

	/* We assume a single thread (main thread) will ever update the mappings,
	 * and hence we don't have any races by first grabbing + releasing the read
	 * lock twice before grabbing the writelock below */

	map = slotmap_by_bank(maps, bank);
	if (map) {
		fprintf(stderr, "BANKD %u:%u already in use, cannot add new map\n",
			bank->bank_id, bank->slot_nr);
		return -EBUSY;
	}

	map = slotmap_by_client(maps, client);
	if (map) {
		fprintf(stderr, "CLIENT %u:%u already in use, cannot add new map\n",
			client->client_id, client->slot_nr);
		return -EBUSY;
	}

	/* allocate new mapping and add to list of mappings */
	map = talloc_zero(maps, struct slot_mapping);
	if (!map)
		return -ENOMEM;

	map->bank = *bank;
	map->client = *client;

	pthread_rwlock_wrlock(&maps->rwlock);
	llist_add_tail(&map->list, &maps->mappings);
	pthread_rwlock_unlock(&maps->rwlock);

	printf("Added Slot Map C(%u:%u) <-> B(%u:%u)\n",
		map->client.client_id, map->client.slot_nr, map->bank.bank_id, map->bank.slot_nr);

	return 0;
}

/* thread-safe removal of a bank<->client map */
void slotmap_del(struct slotmaps *maps, struct slot_mapping *map)
{
	printf("Deleting Slot Map C(%u:%u) <-> B(%u:%u)\n",
		map->client.client_id, map->client.slot_nr, map->bank.bank_id, map->bank.slot_nr);

	pthread_rwlock_wrlock(&maps->rwlock);
	llist_del(&map->list);
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
