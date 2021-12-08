#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include <jansson.h>
#include <ulfius.h>
#include <orcania.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>

#define PREFIX	"/api/backend/v1"

#include "debug.h"
#include "rest_api.h"
#include "slotmap.h"
#include "rspro_server.h"

static json_t *comp_id2json(const struct app_comp_id *comp_id)
{
	json_t *ret = json_object();

	static const char *type_names[] = {
		[ComponentType_remsimClient] = "remsimClient",
		[ComponentType_remsimServer] = "remsimServer",
		[ComponentType_remsimBankd] = "remsimBankd"
	};

	json_object_set_new(ret, "type_", json_string(type_names[comp_id->type]));
	json_object_set_new(ret, "name", json_string(comp_id->name));
	json_object_set_new(ret, "software", json_string(comp_id->software));
	json_object_set_new(ret, "swVersion", json_string(comp_id->sw_version));
	if (strlen(comp_id->hw_manufacturer))
		json_object_set_new(ret, "hwManufacturer", json_string(comp_id->hw_manufacturer));
	if (strlen(comp_id->hw_model))
		json_object_set_new(ret, "hwModel", json_string(comp_id->hw_model));
	if (strlen(comp_id->hw_serial_nr))
		json_object_set_new(ret, "hwSerialNr", json_string(comp_id->hw_serial_nr));
	if (strlen(comp_id->hw_version))
		json_object_set_new(ret, "hwVersion", json_string(comp_id->hw_version));
	if (strlen(comp_id->fw_version))
		json_object_set_new(ret, "fwVersion", json_string(comp_id->fw_version));

	return ret;
}

static json_t *client2json(const struct rspro_client_conn *conn)
{
	json_t *ret = json_object();

	json_object_set_new(ret, "peer", json_string(conn->fi->id));
	json_object_set_new(ret, "state", json_string(osmo_fsm_inst_state_name(conn->fi)));
	/* FIXME: only in the right state */
	json_object_set_new(ret, "component_id", comp_id2json(&conn->comp_id));

	return ret;
}

static json_t *bank2json(const struct rspro_client_conn *conn)
{
	json_t *ret = client2json(conn);
	json_object_set_new(ret, "bankId", json_integer(conn->bank.bank_id));
	json_object_set_new(ret, "numberOfSlots", json_integer(conn->bank.num_slots));
	return ret;
}

static json_t *bank_slot2json(const struct bank_slot *bslot)
{
	json_t *ret = json_object();
	json_object_set_new(ret, "bankId", json_integer(bslot->bank_id));
	json_object_set_new(ret, "slotNr", json_integer(bslot->slot_nr));
	return ret;
}
static int json2bank_slot(struct bank_slot *bslot, json_t *in)
{
	json_t *jbank_id, *jslot_nr;

	if (!json_is_object(in))
		return -EINVAL;
	jbank_id = json_object_get(in, "bankId");
	if (!jbank_id || !json_is_integer(jbank_id))
		return -EINVAL;
	jslot_nr = json_object_get(in, "slotNr");
	if (!jslot_nr || !json_is_integer(jslot_nr))
		return -EINVAL;
	bslot->bank_id = json_integer_value(jbank_id);
	bslot->slot_nr = json_integer_value(jslot_nr);
	if (bslot->bank_id > 1023 || bslot->slot_nr > 1023)
		return -EINVAL;
	return 0;
}

static json_t *client_slot2json(const struct client_slot *bslot)
{
	json_t *ret = json_object();
	json_object_set_new(ret, "clientId", json_integer(bslot->client_id));
	json_object_set_new(ret, "slotNr", json_integer(bslot->slot_nr));
	return ret;
}
static int json2client_slot(struct client_slot *cslot, json_t *in)
{
	json_t *jclient_id, *jslot_nr;

	if (!json_is_object(in))
		return -EINVAL;
	jclient_id = json_object_get(in, "clientId");
	if (!jclient_id || !json_is_integer(jclient_id))
		return -EINVAL;
	jslot_nr = json_object_get(in, "slotNr");
	if (!jslot_nr || !json_is_integer(jslot_nr))
		return -EINVAL;
	cslot->client_id = json_integer_value(jclient_id);
	cslot->slot_nr = json_integer_value(jslot_nr);
	if (cslot->client_id > 1023 || cslot->slot_nr > 1023)
		return -EINVAL;
	return 0;
}

static json_t *slotmap2json(const struct slot_mapping *slotmap)
{
	json_t *ret = json_object();
	json_object_set_new(ret, "bank", bank_slot2json(&slotmap->bank));
	json_object_set_new(ret, "client", client_slot2json(&slotmap->client));
	json_object_set_new(ret, "state", json_string(slotmap_state_name(slotmap->state)));
	return ret;
}
static int json2slotmap(struct slot_mapping *out, json_t *in)
{
	json_t *jbank, *jclient;
	int rc;

	if (!json_is_object(in))
		return -EINVAL;
	jbank = json_object_get(in, "bank");
	if (!jbank || !json_is_object(jbank))
		return -EINVAL;
	jclient = json_object_get(in, "client");
	if (!jclient || !json_is_object(jclient))
		return -EINVAL;

	rc = json2bank_slot(&out->bank, jbank);
	if (rc < 0)
		return rc;
	return json2client_slot(&out->client, jclient);
}


extern struct rspro_server *g_rps;

static int api_cb_rest_ctr_get(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	return U_CALLBACK_CONTINUE;
}

static int api_cb_banks_get(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	struct rspro_client_conn *conn;
	json_t *json_body = json_object();
	json_t *json_banks = json_array();

	pthread_rwlock_rdlock(&g_rps->rwlock);
	llist_for_each_entry(conn, &g_rps->banks, list) {
		json_array_append_new(json_banks, bank2json(conn));
	}
	pthread_rwlock_unlock(&g_rps->rwlock);

	json_object_set_new(json_body, "banks", json_banks);
	ulfius_set_json_body_response(resp, 200, json_body);
	json_decref(json_body);

	return U_CALLBACK_COMPLETE;
}

static int api_cb_bank_get(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	const char *bank_id_str = u_map_get(req->map_url, "bank_id");
	struct rspro_client_conn *conn;
	json_t *json_body = NULL;
	unsigned long bank_id;
	int status;

	if (!bank_id_str) {
		status = 400;
		goto out_err;
	}

	bank_id = strtoul(bank_id_str, NULL, 10);
	if (bank_id > 0xffff) {
		status = 400;
		goto out_err;
	}

	pthread_rwlock_rdlock(&g_rps->rwlock);
	llist_for_each_entry(conn, &g_rps->banks, list) {
		if (conn->bank.bank_id == bank_id) {
			json_body = bank2json(conn);
			break;
		}
	}
	pthread_rwlock_unlock(&g_rps->rwlock);

	if (json_body) {
		ulfius_set_json_body_response(resp, 200, json_body);
		json_decref(json_body);
	} else {
		ulfius_set_json_body_response(resp, 404, json_body);
	}

	return U_CALLBACK_COMPLETE;

out_err:
	ulfius_set_empty_body_response(resp, status);
	return U_CALLBACK_COMPLETE;
}


static int api_cb_clients_get(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	struct rspro_client_conn *conn;
	json_t *json_body = json_object();
	json_t *json_clients = json_array();

	pthread_rwlock_rdlock(&g_rps->rwlock);
	llist_for_each_entry(conn, &g_rps->clients, list) {
		json_array_append_new(json_clients, client2json(conn));
	}
	pthread_rwlock_unlock(&g_rps->rwlock);

	json_object_set_new(json_body, "clients", json_clients);
	ulfius_set_json_body_response(resp, 200, json_body);
	json_decref(json_body);

	return U_CALLBACK_COMPLETE;
}

static int api_cb_client_get(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	const char *client_id_str = u_map_get(req->map_url, "client_id");
	struct rspro_client_conn *conn;
	json_t *json_body = NULL;
	unsigned long client_id;
	int status;

	if (!client_id_str) {
		status = 400;
		goto out_err;
	}

	client_id = strtoul(client_id_str, NULL, 10);
	if (client_id > 0xffff) {
		status = 400;
		goto out_err;
	}

	pthread_rwlock_rdlock(&g_rps->rwlock);
	llist_for_each_entry(conn, &g_rps->clients, list) {
		if (conn->bank.bank_id == client_id) { /* FIXME */
			json_body = client2json(conn);
			break;
		}
	}
	pthread_rwlock_unlock(&g_rps->rwlock);

	if (json_body) {
		ulfius_set_json_body_response(resp, 200, json_body);
		json_decref(json_body);
	} else {
		ulfius_set_json_body_response(resp, 404, json_body);
	}

	return U_CALLBACK_COMPLETE;

out_err:
	ulfius_set_empty_body_response(resp, status);
	return U_CALLBACK_COMPLETE;
}

static int api_cb_slotmaps_get(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	struct slot_mapping *map;
	json_t *json_body = json_object();
	json_t *json_maps = json_array();

	slotmaps_rdlock(g_rps->slotmaps);
	llist_for_each_entry(map, &g_rps->slotmaps->mappings, list) {
		json_array_append_new(json_maps, slotmap2json(map));
	}
	slotmaps_unlock(g_rps->slotmaps);

	json_object_set_new(json_body, "slotmaps", json_maps);
	ulfius_set_json_body_response(resp, 200, json_body);
	json_decref(json_body);

	return U_CALLBACK_COMPLETE;
}

extern struct osmo_fd g_event_ofd;
/* trigger our main thread select() loop */
static void trigger_main_thread_via_eventfd(void)
{
	uint64_t one = 1;
	int rc;

	rc = write(g_event_ofd.fd, &one, sizeof(one));
	if (rc < 8)
		LOGP(DREST, LOGL_ERROR, "Error writing to eventfd(): %d\n", rc);
}

static int api_cb_slotmaps_post(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	struct rspro_server *srv = g_rps;
	struct slot_mapping slotmap, *map;
	struct rspro_client_conn *conn;
	json_error_t json_err;
	json_t *json_req = NULL;
	int rc;

	json_req = ulfius_get_json_body_request(req, &json_err);
	if (!json_req) {
		LOGP(DREST, LOGL_NOTICE, "REST: No JSON Body\n");
		goto err;
	}

	rc = json2slotmap(&slotmap, json_req);
	if (rc < 0)
		goto err;
	map = slotmap_add(g_rps->slotmaps, &slotmap.bank, &slotmap.client);
	if (!map) {
		LOGP(DREST, LOGL_NOTICE, "REST: Cannot add slotmap\n");
		goto err;
	}
	slotmap_state_change(map, SLMAP_S_NEW, NULL);

	/* check if any already-connected bankd matches this new map. If yes, associate it */
	pthread_rwlock_rdlock(&srv->rwlock);
	llist_for_each_entry(conn, &srv->banks, list) {
		if (conn->bank.bank_id == slotmap.bank.bank_id) {
			slotmap_state_change(map, SLMAP_S_NEW, &conn->bank.maps_new);
			/* Notify the conn FSM about some new maps being available */
			trigger_main_thread_via_eventfd();
			break;
		}
	}
	pthread_rwlock_unlock(&srv->rwlock);


	json_decref(json_req);
	ulfius_set_empty_body_response(resp, 201);

	return U_CALLBACK_COMPLETE;
err:
	json_decref(json_req);
	ulfius_set_empty_body_response(resp, 400);
	return U_CALLBACK_COMPLETE;
}

/* caller is holding a write lock on slotmaps->rwlock */
static void _slotmap_mark_deleted(struct slot_mapping *map)
{
	struct rspro_client_conn *conn = bankd_conn_by_id(g_rps, map->bank.bank_id);

	/* delete map from global list to ensure it's not found by further lookups,
	 * particularly in case somebody wants to create a new map for the same bank/slot */
	llist_del(&map->list);
	/* safely initialize list head to avoid trouble when del_slotmap() does another llist_del() */
	INIT_LLIST_HEAD(&map->list);

	switch (map->state) {
	case SLMAP_S_NEW:
		/* new map, not yet sent to bank: we can remove it immediately */
		/* delete from bank list (if any) */
		llist_del(&map->bank_list);
		/* safely initialize list head to avoid trouble when del_slotmap() does another llist_del() */
		INIT_LLIST_HEAD(&map->bank_list);
		_slotmap_del(map->maps, map);
		break;
	case SLMAP_S_UNACKNOWLEDGED:
		/* map has been sent to bank already, but wasn't acknowledged yet */
		/* FIXME: what to do now? If we keep it unchanged, it will not be deleted.  If we
		 * move it to DELETE_REQ, */
		break;
	case SLMAP_S_ACTIVE:
		/* map is fully active. Need to move it to DELETE_REQ state + trigger rspro thread,
		 * so the deletion can propagate to the bankd */
		_slotmap_state_change(map, SLMAP_S_DELETE_REQ, &conn->bank.maps_delreq);
		trigger_main_thread_via_eventfd();
		break;
	case SLMAP_S_DELETE_REQ:
		/* REST had already requested deletion, but RSPRO thread hasn't issued the delete
		 * command to the bankd yet: Do nothing */
		break;
	case SLMAP_S_DELETING:
		/* we had already requested deletion of this map previously: Do nothing */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int api_cb_slotmaps_del(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	const char *slotmap_id_str = u_map_get(req->map_url, "slotmap_id");
	struct slot_mapping *map;
	int status = 404;
	unsigned long map_id;

	if (!slotmap_id_str) {
		status = 400;
		goto err;
	}
	map_id = strtoul(slotmap_id_str, NULL, 10);
	if (map_id < 0) {
		status = 400;
		goto err;
	}

	slotmaps_wrlock(g_rps->slotmaps);
	llist_for_each_entry(map, &g_rps->slotmaps->mappings, list) {
		if (slotmap_get_id(map) == map_id) {
			_slotmap_mark_deleted(map);
			status = 200;
			break;
		}
	}
	slotmaps_unlock(g_rps->slotmaps);
	trigger_main_thread_via_eventfd();


	ulfius_set_empty_body_response(resp, status);
	return U_CALLBACK_COMPLETE;
err:
	ulfius_set_empty_body_response(resp, status);
	return U_CALLBACK_COMPLETE;
}

static int api_cb_global_reset_post(const struct _u_request *req, struct _u_response *resp, void *user_data)
{
	struct slot_mapping *map, *map2;

	LOGP(DMAIN, LOGL_NOTICE, "Global RESET from REST API\n");

	/* mark all slot mappings as deleted */
	slotmaps_wrlock(g_rps->slotmaps);
	llist_for_each_entry_safe(map, map2, &g_rps->slotmaps->mappings, list) {
		_slotmap_mark_deleted(map);
	}
	slotmaps_unlock(g_rps->slotmaps);
	trigger_main_thread_via_eventfd();

	ulfius_set_empty_body_response(resp, 200);
	return U_CALLBACK_COMPLETE;
}

static const struct _u_endpoint api_endpoints[] = {
	/* get the current restart counter */
	{ "GET",  PREFIX, "/restart-counter", 0, &api_cb_rest_ctr_get, NULL },
	/* get a list of SIM banks */
	{ "GET",  PREFIX, "/banks", 0, &api_cb_banks_get, NULL },
	{ "GET",  PREFIX, "/banks/:bank_id", 0, &api_cb_bank_get, NULL },
	/* get a list of SIM clients */
	{ "GET",  PREFIX, "/clients", 0, &api_cb_clients_get, NULL },
	{ "GET",  PREFIX, "/clients/:client_id", 0, &api_cb_client_get, NULL },
	/* get a list of mappings */
	{ "GET",  PREFIX, "/slotmaps", 0, &api_cb_slotmaps_get, NULL },
	{ "POST",  PREFIX, "/slotmaps", 0, &api_cb_slotmaps_post, NULL },
	{ "DELETE",  PREFIX, "/slotmaps/:slotmap_id", 0, &api_cb_slotmaps_del, NULL },
	{ "POST",  PREFIX, "/global-reset", 0, &api_cb_global_reset_post, NULL },
};

static struct _u_instance g_instance;
static pthread_mutex_t g_tall_lock = PTHREAD_MUTEX_INITIALIZER;
static void *g_tall_rest;

static void *my_o_malloc(size_t sz)
{
	void *obj;
	pthread_mutex_lock(&g_tall_lock);
	obj = talloc_size(g_tall_rest, sz);
	pthread_mutex_unlock(&g_tall_lock);
	return obj;
}

static void *my_o_realloc(void *obj, size_t sz)
{
	pthread_mutex_lock(&g_tall_lock);
	obj = talloc_realloc_size(g_tall_rest, obj, sz);
	pthread_mutex_unlock(&g_tall_lock);
	return obj;
}

static void my_o_free(void *obj)
{
	pthread_mutex_lock(&g_tall_lock);
	talloc_free(obj);
	pthread_mutex_unlock(&g_tall_lock);
}

int rest_api_init(void *ctx, uint16_t port)
{
	int i;

	g_tall_rest = ctx;
	o_set_alloc_funcs(my_o_malloc, my_o_realloc, my_o_free);

	if (ulfius_init_instance(&g_instance, port, NULL, NULL) != U_OK)
		return -1;
	g_instance.mhd_response_copy_data = 1;

	for (i = 0; i < ARRAY_SIZE(api_endpoints); i++)
		ulfius_add_endpoint(&g_instance, &api_endpoints[i]);

	if (ulfius_start_framework(&g_instance) != U_OK) {
		LOGP(DREST, LOGL_FATAL, "Cannot start REST API on port %u\n", port);
		return -1;
	}
	return 0;
}

void rest_api_fini(void)
{
	ulfius_stop_framework(&g_instance);
	ulfius_clean_instance(&g_instance);
}
