
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <pthread.h>

#include <talloc.h>

#include <osmocom/core/linuxlist.h>

#include "bankd.h"

/* thread-safe lookup of map by client:slot */
struct bankd_slot_mapping *bankd_slotmap_by_client(struct bankd *bankd, const struct client_slot *client)
{
	struct bankd_slot_mapping *map;

	pthread_rwlock_rdlock(&bankd->slot_mappings_rwlock);
	llist_for_each_entry(map, &bankd->slot_mappings, list) {
		if (client_slot_equals(&map->client, client)) {
			pthread_rwlock_unlock(&bankd->slot_mappings_rwlock);
			return map;
		}
	}
	pthread_rwlock_unlock(&bankd->slot_mappings_rwlock);
	return NULL;
}

/* thread-safe lookup of map by bank:slot */
struct bankd_slot_mapping *bankd_slotmap_by_bank(struct bankd *bankd, const struct bank_slot *bank)
{
	struct bankd_slot_mapping *map;

	pthread_rwlock_rdlock(&bankd->slot_mappings_rwlock);
	llist_for_each_entry(map, &bankd->slot_mappings, list) {
		if (bank_slot_equals(&map->bank, bank)) {
			pthread_rwlock_unlock(&bankd->slot_mappings_rwlock);
			return map;
		}
	}
	pthread_rwlock_unlock(&bankd->slot_mappings_rwlock);
	return NULL;

}

/* thread-safe creating of a new bank<->client map */
int bankd_slotmap_add(struct bankd *bankd, const struct bank_slot *bank, const struct client_slot *client)
{
	struct bankd_slot_mapping *map;

	/* We assume a single thread (main thread) will ever update the mappings,
	 * and hence we don't have any races by first grabbing + releasing the read
	 * lock twice before grabbing the writelock below */

	map = bankd_slotmap_by_bank(bankd, bank);
	if (map) {
		fprintf(stderr, "BANKD %u:%u already in use, cannot add new map\n",
			bank->bank_id, bank->slot_nr);
		return -EBUSY;
	}

	map = bankd_slotmap_by_client(bankd, client);
	if (map) {
		fprintf(stderr, "CLIENT %u:%u already in use, cannot add new map\n",
			client->client_id, client->slot_nr);
		return -EBUSY;
	}

	/* allocate new mapping and add to list of mappings */
	map = talloc_zero(bankd, struct bankd_slot_mapping);
	if (!map)
		return -ENOMEM;

	map->bank = *bank;
	map->client = *client;

	pthread_rwlock_wrlock(&bankd->slot_mappings_rwlock);
	llist_add_tail(&map->list, &bankd->slot_mappings);
	pthread_rwlock_unlock(&bankd->slot_mappings_rwlock);

	printf("Added Slot Map C(%u:%u) <-> B(%u:%u)\n",
		map->client.client_id, map->client.slot_nr, map->bank.bank_id, map->bank.slot_nr);

	return 0;
}

/* thread-safe removal of a bank<->client map */
void bankd_slotmap_del(struct bankd *bankd, struct bankd_slot_mapping *map)
{
	printf("Deleting Slot Map C(%u:%u) <-> B(%u:%u)\n",
		map->client.client_id, map->client.slot_nr, map->bank.bank_id, map->bank.slot_nr);

	pthread_rwlock_wrlock(&bankd->slot_mappings_rwlock);
	llist_del(&map->list);
	pthread_rwlock_unlock(&bankd->slot_mappings_rwlock);

	talloc_free(map);
}
