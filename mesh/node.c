/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <sys/time.h>

#include <ell/ell.h>
#include <json-c/json.h>
#include <stdio.h>

#include "mesh/mesh-defs.h"
#include "mesh/mesh.h"
#include "mesh/net.h"
#include "mesh/mesh-db.h"
#include "mesh/provision.h"
#include "mesh/storage.h"
#include "mesh/keyring.h"
#include "mesh/model.h"
#include "mesh/cfgmod.h"
#include "mesh/util.h"
#include "mesh/error.h"
#include "mesh/dbus.h"
#include "mesh/agent.h"
#include "mesh/node.h"

#define MIN_COMP_SIZE 14

#define MESH_NODE_PATH_PREFIX "/node"
#define MESH_ELEMENT_PATH_PREFIX "/ele"

/* Default values for a new locally created node */
#define DEFAULT_NEW_UNICAST 0x0001
#define DEFAULT_IV_INDEX 0x0000

/* Default element location: unknown */
#define DEFAULT_LOCATION 0x0000

#define DEFAULT_CRPL 10
#define DEFAULT_SEQUENCE_NUMBER 0

enum request_type {
	REQUEST_TYPE_JOIN = 0,
	REQUEST_TYPE_ATTACH,
	REQUEST_TYPE_CREATE,
	REQUEST_TYPE_IMPORT,
};

struct node_element {
	char *path;
	struct l_queue *models;
	uint16_t location;
	uint8_t idx;
};

struct node_composition {
	uint16_t cid;
	uint16_t pid;
	uint16_t vid;
	uint16_t crpl;
};

struct mesh_node {
	struct mesh_net *net;
	struct l_queue *elements;
	char *app_path;
	char *owner;
	char *path;
	void *jconfig;
	char *node_path;
	uint32_t disc_watch;
	time_t upd_sec;
	uint32_t seq_number;
	uint32_t seq_min_cache;
	bool provisioner;
	uint16_t primary;
	struct node_composition *comp;
	struct {
		uint16_t interval;
		uint8_t cnt;
		uint8_t mode;
	} relay;
	uint8_t uuid[16];
	uint8_t dev_key[16];
	uint8_t token[8];
	uint8_t num_ele;
	uint8_t ttl;
	uint8_t lpn;
	uint8_t proxy;
	uint8_t friend;
	uint8_t beacon;
};

struct managed_obj_request {
	void *data;
	void *cb;
	void *user_data;
	enum request_type type;
};

struct node_import_request {
	uint8_t uuid[16];
	uint8_t dev_key[16];
	uint8_t net_key[16];
	bool kr;
	uint16_t unicast;
	uint32_t iv_idx;
	bool iv_update;
	void *user_data;
};

static struct l_queue *nodes;

static bool match_node_unicast(const void *a, const void *b)
{
	const struct mesh_node *node = a;
	uint16_t dst = L_PTR_TO_UINT(b);

	return (dst >= node->primary &&
		dst <= (node->primary + node->num_ele - 1));
}

static bool match_device_uuid(const void *a, const void *b)
{
	const struct mesh_node *node = a;
	const uint8_t *uuid = b;

	return (memcmp(node->uuid, uuid, 16) == 0);
}

static bool match_token(const void *a, const void *b)
{
	const struct mesh_node *node = a;
	const uint64_t *token = b;
	const uint64_t tmp = l_get_be64(node->token);

	return *token == tmp;
}

static bool match_element_idx(const void *a, const void *b)
{
	const struct node_element *element = a;
	uint32_t index = L_PTR_TO_UINT(b);

	return (element->idx == index);
}

static bool match_model_id(const void *a, const void *b)
{
	const struct mesh_model *mod = a;
	uint32_t mod_id = L_PTR_TO_UINT(b);

	return mod_id == mesh_model_get_model_id(mod);
}

static bool match_element_path(const void *a, const void *b)
{
	const struct node_element *element = a;
	const char *path = b;

	if (!element->path)
		return false;

	return (!strcmp(element->path, path));
}

struct mesh_node *node_find_by_addr(uint16_t addr)
{
	if (!IS_UNICAST(addr))
		return NULL;

	return l_queue_find(nodes, match_node_unicast, L_UINT_TO_PTR(addr));
}

struct mesh_node *node_find_by_uuid(uint8_t uuid[16])
{
	return l_queue_find(nodes, match_device_uuid, uuid);
}

struct mesh_node *node_find_by_token(uint64_t token)
{
	return l_queue_find(nodes, match_token, (void *) &token);
}

uint8_t *node_uuid_get(struct mesh_node *node)
{
	if (!node)
		return NULL;
	return node->uuid;
}

struct mesh_node *node_new(const uint8_t uuid[16])
{
	struct mesh_node *node;

	node = l_new(struct mesh_node, 1);
	node->net = mesh_net_new(node);
	memcpy(node->uuid, uuid, sizeof(node->uuid));

	if (!nodes)
		nodes = l_queue_new();

	l_queue_push_tail(nodes, node);

	return node;
}

static void free_element_path(void *a, void *b)
{
	struct node_element *element = a;

	l_free(element->path);
	element->path = NULL;
}

static void element_free(void *data)
{
	struct node_element *element = data;

	l_queue_destroy(element->models, mesh_model_free);
	l_free(element->path);
	l_free(element);
}

static void free_node_resources(void *data)
{
	struct mesh_node *node = data;

	/* Unregister io callbacks */
	if (node->net)
		mesh_net_detach(node->net);
	mesh_net_free(node->net);

	l_queue_destroy(node->elements, element_free);
	l_free(node->comp);
	l_free(node->app_path);
	l_free(node->owner);
	l_free(node->node_path);

	if (node->disc_watch)
		l_dbus_remove_watch(dbus_get_bus(), node->disc_watch);

	if (node->path)
		l_dbus_object_remove_interface(dbus_get_bus(), node->path,
							MESH_NODE_INTERFACE);
	l_free(node->path);

	l_free(node);
}

/*
 * This function is called to free resources and remove the
 * configuration files for the specified node.
 */
void node_remove(struct mesh_node *node)
{
	if (!node)
		return;

	l_queue_remove(nodes, node);

	if (node->node_path)
		storage_remove_node_config(node);

	free_node_resources(node);
}

static bool add_models(struct mesh_node *node, struct node_element *ele,
						struct mesh_db_element *db_ele)
{
	const struct l_queue_entry *entry;

	if (!ele->models)
		ele->models = l_queue_new();

	entry = l_queue_get_entries(db_ele->models);
	for (; entry; entry = entry->next) {
		struct mesh_model *mod;
		struct mesh_db_model *db_mod;

		db_mod = entry->data;
		mod = mesh_model_setup(node, ele->idx, db_mod);
		if (!mod)
			return false;

		l_queue_push_tail(ele->models, mod);
	}

	return true;
}

static void add_internal_model(struct mesh_node *node, uint32_t mod_id,
								uint8_t ele_idx)
{
	struct node_element *ele;
	struct mesh_model *mod;
	struct mesh_db_model db_mod;

	ele = l_queue_find(node->elements, match_element_idx,
							L_UINT_TO_PTR(ele_idx));

	if (!ele)
		return;

	memset(&db_mod, 0, sizeof(db_mod));
	db_mod.id = mod_id;

	mod = mesh_model_setup(node, ele_idx, &db_mod);
	if (!mod)
		return;

	if (!ele->models)
		ele->models = l_queue_new();

	l_queue_push_tail(ele->models, mod);
}

static bool add_element(struct mesh_node *node, struct mesh_db_element *db_ele)
{
	struct node_element *ele;

	ele = l_new(struct node_element, 1);
	if (!ele)
		return false;

	ele->idx = db_ele->index;
	ele->location = db_ele->location;

	if (!db_ele->models || !add_models(node, ele, db_ele))
		return false;

	l_queue_push_tail(node->elements, ele);
	return true;
}

static bool add_elements(struct mesh_node *node, struct mesh_db_node *db_node)
{
	const struct l_queue_entry *entry;

	if (!node->elements)
		node->elements = l_queue_new();

	entry = l_queue_get_entries(db_node->elements);
	for (; entry; entry = entry->next)
		if (!add_element(node, entry->data))
			return false;

	return true;
}

bool node_init_from_storage(struct mesh_node *node, void *data)
{
	struct mesh_db_node *db_node = data;
	unsigned int num_ele;

	node->comp = l_new(struct node_composition, 1);
	node->comp->cid = db_node->cid;
	node->comp->pid = db_node->pid;
	node->comp->vid = db_node->vid;
	node->comp->crpl = db_node->crpl;
	node->lpn = db_node->modes.lpn;

	node->proxy = db_node->modes.proxy;
	node->lpn = db_node->modes.lpn;
	node->friend = db_node->modes.friend;
	node->relay.mode = db_node->modes.relay.state;
	node->relay.cnt = db_node->modes.relay.cnt;
	node->relay.interval = db_node->modes.relay.interval;
	node->beacon = db_node->modes.beacon;

	l_debug("relay %2.2x, proxy %2.2x, lpn %2.2x, friend %2.2x",
			node->relay.mode, node->proxy, node->friend, node->lpn);
	node->ttl = db_node->ttl;
	node->seq_number = db_node->seq_number;

	num_ele = l_queue_length(db_node->elements);
	if (num_ele > 0xff)
		return false;

	node->num_ele = num_ele;

	if (num_ele != 0 && !add_elements(node, db_node))
		return false;

	node->primary = db_node->unicast;

	/* Initialize configuration server model */
	mesh_config_srv_init(node, PRIMARY_ELE_IDX);

	return true;
}

static void cleanup_node(void *data)
{
	struct mesh_node *node = data;
	struct mesh_net *net = node->net;

	/* Save local node configuration */
	if (node->node_path) {

		/* Preserve the last sequence number */
		storage_write_sequence_number(net, mesh_net_get_seq_num(net));

		storage_save_config(node, true, NULL, NULL);
	}

	free_node_resources(node);
}

/*
 * This function is called to free resources and write the current
 * sequence numbers to the configuration file for each known node.
 */
void node_cleanup_all(void)
{
	l_queue_destroy(nodes, cleanup_node);
	l_dbus_unregister_interface(dbus_get_bus(), MESH_NODE_INTERFACE);
}

bool node_is_provisioned(struct mesh_node *node)
{
	return (!IS_UNASSIGNED(node->primary));
}

bool node_app_key_delete(struct mesh_net *net, uint16_t addr,
				uint16_t net_idx, uint16_t app_idx)
{
	struct mesh_node *node;
	const struct l_queue_entry *entry;

	node = node_find_by_addr(addr);
	if (!node)
		return false;

	entry = l_queue_get_entries(node->elements);
	for (; entry; entry = entry->next) {
		struct node_element *ele = entry->data;

		mesh_model_app_key_delete(node, ele->models, app_idx);
	}
	return true;
}

uint16_t node_get_primary(struct mesh_node *node)
{
	if (!node)
		return UNASSIGNED_ADDRESS;
	else
		return node->primary;
}

void node_set_device_key(struct mesh_node *node, uint8_t key[16])
{
	memcpy(node->dev_key, key, 16);
}

const uint8_t *node_get_device_key(struct mesh_node *node)
{
	if (!node)
		return NULL;
	else
		return node->dev_key;
}

void node_set_token(struct mesh_node *node, uint8_t token[8])
{
	memcpy(node->token, token, 8);
}

const uint8_t *node_get_token(struct mesh_node *node)
{
	if (!node)
		return NULL;
	else
		return node->token;
}

uint8_t node_get_num_elements(struct mesh_node *node)
{
	return node->num_ele;
}

struct l_queue *node_get_element_models(struct mesh_node *node,
						uint8_t ele_idx, int *status)
{
	struct node_element *ele;

	if (!node) {
		if (status)
			*status = MESH_STATUS_INVALID_ADDRESS;
		return NULL;
	}

	ele = l_queue_find(node->elements, match_element_idx,
							L_UINT_TO_PTR(ele_idx));
	if (!ele) {
		if (status)
			*status = MESH_STATUS_INVALID_ADDRESS;
		return NULL;
	}

	if (status)
		*status = MESH_STATUS_SUCCESS;

	return ele->models;
}

uint8_t node_default_ttl_get(struct mesh_node *node)
{
	if (!node)
		return DEFAULT_TTL;
	return node->ttl;
}

bool node_default_ttl_set(struct mesh_node *node, uint8_t ttl)
{
	bool res;

	if (!node)
		return false;

	res = storage_set_ttl(node, ttl);

	if (res) {
		node->ttl = ttl;
		mesh_net_set_default_ttl(node->net, ttl);
	}

	return res;
}

bool node_set_sequence_number(struct mesh_node *node, uint32_t seq)
{
	struct timeval write_time;

	if (!node)
		return false;

	node->seq_number = seq;

	/*
	 * Holistically determine worst case 5 minute sequence consumption
	 * so that we typically (once we reach a steady state) rewrite the
	 * local node file with a new seq cache value no more than once every
	 * five minutes (or more)
	 */
	gettimeofday(&write_time, NULL);
	if (node->upd_sec) {
		uint32_t elapsed = write_time.tv_sec - node->upd_sec;

		if (elapsed < MIN_SEQ_CACHE_TIME) {
			uint32_t ideal = node->seq_min_cache;

			l_debug("Old Seq Cache: %d", node->seq_min_cache);

			ideal *= (MIN_SEQ_CACHE_TIME / elapsed);

			if (ideal > node->seq_min_cache + MIN_SEQ_CACHE)
				node->seq_min_cache = ideal;
			else
				node->seq_min_cache += MIN_SEQ_CACHE;

			l_debug("New Seq Cache: %d", node->seq_min_cache);
		}
	}

	node->upd_sec = write_time.tv_sec;

	return storage_write_sequence_number(node->net, seq);
}

uint32_t node_get_sequence_number(struct mesh_node *node)
{
	if (!node)
		return 0xffffffff;

	return node->seq_number;
}

uint32_t node_seq_cache(struct mesh_node *node)
{
	if (node->seq_min_cache < MIN_SEQ_CACHE)
		node->seq_min_cache = MIN_SEQ_CACHE;

	return node->seq_min_cache;
}

int node_get_element_idx(struct mesh_node *node, uint16_t ele_addr)
{
	uint16_t addr;
	uint8_t num_ele;

	if (!node)
		return -1;

	num_ele = node_get_num_elements(node);
	if (!num_ele)
		return -2;

	addr = node_get_primary(node);

	if (ele_addr < addr || ele_addr >= addr + num_ele)
		return -3;
	else
		return ele_addr - addr;
}

uint16_t node_get_crpl(struct mesh_node *node)
{
	if (!node)
		return 0;

	return node->comp->crpl;
}

uint8_t node_relay_mode_get(struct mesh_node *node, uint8_t *count,
							uint16_t *interval)
{
	if (!node) {
		*count = 0;
		*interval = 0;
		return MESH_MODE_DISABLED;
	}

	*count = node->relay.cnt;
	*interval = node->relay.interval;
	return node->relay.mode;
}

uint8_t node_lpn_mode_get(struct mesh_node *node)
{
	if (!node)
		return MESH_MODE_DISABLED;

	return node->lpn;
}

bool node_relay_mode_set(struct mesh_node *node, bool enable, uint8_t cnt,
							uint16_t interval)
{
	bool res;

	if (!node || node->relay.mode == MESH_MODE_UNSUPPORTED)
		return false;

	res = storage_set_relay(node, enable, cnt, interval);

	if (res) {
		node->relay.mode = enable ? MESH_MODE_ENABLED :
							MESH_MODE_DISABLED;
		node->relay.cnt = cnt;
		node->relay.interval = interval;
		mesh_net_set_relay_mode(node->net, enable, cnt, interval);
	}

	return res;
}

bool node_proxy_mode_set(struct mesh_node *node, bool enable)
{
	bool res;
	uint8_t proxy;

	if (!node || node->proxy == MESH_MODE_UNSUPPORTED)
		return false;

	proxy = enable ? MESH_MODE_ENABLED : MESH_MODE_DISABLED;
	res = storage_set_mode(node->jconfig, proxy, "proxy");

	if (res) {
		node->proxy = proxy;
		mesh_net_set_proxy_mode(node->net, enable);
	}

	return res;
}

uint8_t node_proxy_mode_get(struct mesh_node *node)
{
	if (!node)
		return MESH_MODE_DISABLED;

	return node->proxy;
}

bool node_beacon_mode_set(struct mesh_node *node, bool enable)
{
	bool res;
	uint8_t beacon;

	if (!node)
		return false;

	beacon = enable ? MESH_MODE_ENABLED : MESH_MODE_DISABLED;
	res = storage_set_mode(node->jconfig, beacon, "beacon");

	if (res) {
		node->beacon = beacon;
		mesh_net_set_beacon_mode(node->net, enable);
	}

	return res;
}

uint8_t node_beacon_mode_get(struct mesh_node *node)
{
	if (!node)
		return MESH_MODE_DISABLED;

	return node->beacon;
}

bool node_friend_mode_set(struct mesh_node *node, bool enable)
{
	bool res;
	uint8_t friend;

	if (!node || node->friend == MESH_MODE_UNSUPPORTED)
		return false;

	friend = enable ? MESH_MODE_ENABLED : MESH_MODE_DISABLED;
	res = storage_set_mode(node->jconfig, friend, "friend");

	if (res) {
		node->friend = friend;
		mesh_net_set_friend_mode(node->net, enable);
	}

	return res;
}

uint8_t node_friend_mode_get(struct mesh_node *node)
{
	if (!node)
		return MESH_MODE_DISABLED;

	return node->friend;
}

uint16_t node_generate_comp(struct mesh_node *node, uint8_t *buf, uint16_t sz)
{
	uint16_t n, features;
	const struct l_queue_entry *ele_entry;

	if (!node || !node->comp || sz < MIN_COMP_SIZE)
		return 0;

	n = 0;

	l_put_le16(node->comp->cid, buf + n);
	n += 2;
	l_put_le16(node->comp->pid, buf + n);
	n += 2;
	l_put_le16(node->comp->vid, buf + n);
	n += 2;
	l_put_le16(node->comp->crpl, buf + n);
	n += 2;

	features = 0;

	if (node->relay.mode != MESH_MODE_UNSUPPORTED)
		features |= FEATURE_RELAY;
	if (node->proxy != MESH_MODE_UNSUPPORTED)
		features |= FEATURE_PROXY;
	if (node->friend != MESH_MODE_UNSUPPORTED)
		features |= FEATURE_FRIEND;
	if (node->lpn != MESH_MODE_UNSUPPORTED)
		features |= FEATURE_LPN;

	l_put_le16(features, buf + n);
	n += 2;

	ele_entry = l_queue_get_entries(node->elements);
	for (; ele_entry; ele_entry = ele_entry->next) {
		struct node_element *ele = ele_entry->data;
		const struct l_queue_entry *mod_entry;
		uint8_t num_s = 0, num_v = 0;
		uint8_t *mod_buf;

		/* At least fit location and zeros for number of models */
		if ((n + 4) > sz)
			return n;

		l_put_le16(ele->location, buf + n);
		n += 2;

		/* Store models IDs, store num_s and num_v later */
		mod_buf = buf + n;
		n += 2;

		/* Get SIG models */
		mod_entry = l_queue_get_entries(ele->models);
		for (; mod_entry; mod_entry = mod_entry->next) {
			struct mesh_model *mod = mod_entry->data;
			uint32_t mod_id;

			mod_id = mesh_model_get_model_id(
					(const struct mesh_model *) mod);

			if ((mod_id & VENDOR_ID_MASK) == VENDOR_ID_MASK) {
				if (n + 2 > sz)
					goto element_done;

				l_put_le16((uint16_t) (mod_id & 0xffff),
								buf + n);
				n += 2;
				num_s++;
			}
		}

		/* Get vendor models */
		mod_entry = l_queue_get_entries(ele->models);
		for (; mod_entry; mod_entry = mod_entry->next) {
			struct mesh_model *mod = mod_entry->data;
			uint32_t mod_id;
			uint16_t vendor;

			mod_id = mesh_model_get_model_id(
					(const struct mesh_model *) mod);

			vendor = (uint16_t) (mod_id >> 16);
			if (vendor != 0xffff) {
				if (n + 4 > sz)
					goto element_done;

				l_put_le16(vendor, buf + n);
				n += 2;
				l_put_le16((uint16_t) (mod_id & 0xffff),
								buf + n);
				n += 2;
				num_v++;
			}

		}

element_done:
		mod_buf[0] = num_s;
		mod_buf[1] = num_v;

	}

	return n;
}


#define MIN_COMPOSITION_LEN 16

bool node_parse_composition(struct mesh_node *node, uint8_t *data,
			    uint16_t len)
{
	struct node_composition *comp;
	uint16_t features;
	uint8_t num_ele;
	bool mode;

	if (!len)
		return false;

	/* Skip page -- We only support Page Zero */
	data++;
	len--;

	if (len < MIN_COMPOSITION_LEN)
		return false;

	comp = l_new(struct node_composition, 1);
	if (!comp)
		return false;

	node->elements = l_queue_new();
	if (!node->elements) {
		l_free(comp);
		return false;
	}

	node->comp = l_new(struct node_composition, 1);
	comp->cid = l_get_le16(&data[0]);
	comp->pid = l_get_le16(&data[2]);
	comp->vid = l_get_le16(&data[4]);
	comp->crpl = l_get_le16(&data[6]);
	features = l_get_le16(&data[8]);
	data += 10;
	len -= 10;

	mode = !!(features & FEATURE_PROXY);
	node->proxy = mode ? MESH_MODE_DISABLED : MESH_MODE_UNSUPPORTED;

	mode = !!(features & FEATURE_LPN);
	node->lpn = mode ? MESH_MODE_DISABLED : MESH_MODE_UNSUPPORTED;

	mode = !!(features & FEATURE_FRIEND);
	node->friend = mode ? MESH_MODE_DISABLED : MESH_MODE_UNSUPPORTED;

	mode = !!(features & FEATURE_RELAY);
	node->relay.mode = mode ? MESH_MODE_DISABLED : MESH_MODE_UNSUPPORTED;

	num_ele = 0;

	do {
		uint8_t m, v;
		uint16_t mod_id;
		uint16_t vendor_id;
		struct node_element *ele;
		struct mesh_model *mod;

		ele = l_new(struct node_element, 1);
		if (!ele)
			return false;

		ele->idx = num_ele;
		ele->location = l_get_le16(data);
		len -= 2;
		data += 2;

		m = *data++;
		v = *data++;
		len -= 2;

		/* Parse SIG models */
		while (len >= 2 && m--) {
			mod_id = l_get_le16(data);
			mod = mesh_model_new(ele->idx, mod_id);
			if (!mod) {
				element_free(ele);
				goto fail;
			}

			l_queue_push_tail(ele->models, mod);
			data += 2;
			len -= 2;
		}

		if (v && len < 4) {
			element_free(ele);
			goto fail;
		}

		/* Parse vendor models */
		while (len >= 4 && v--) {
			mod_id = l_get_le16(data + 2);
			vendor_id = l_get_le16(data);
			mod_id |= (vendor_id << 16);
			mod = mesh_model_vendor_new(ele->idx, vendor_id,
						    mod_id);
			if (!mod) {
				element_free(ele);
				goto fail;
			}

			l_queue_push_tail(ele->models, mod);
			data += 4;
			len -= 4;
		}

		num_ele++;
		l_queue_push_tail(node->elements, ele);

	} while (len >= 6);

	/* Check the consistency for the remote node */
	if (node->num_ele > num_ele)
		goto fail;

	node->comp = comp;
	node->num_ele = num_ele;

	return true;

fail:
	l_queue_destroy(node->elements, element_free);
	l_free(comp);

	return false;
}
static void attach_io(void *a, void *b)
{
	struct mesh_node *node = a;
	struct mesh_io *io = b;

	if (node->net)
		mesh_net_attach(node->net, io);
}

/* Register callback for the node's io */
void node_attach_io(struct mesh_node *node, struct mesh_io *io)
{
	attach_io(node, io);
}

/* Register callbacks for all nodes io */
void node_attach_io_all(struct mesh_io *io)
{
	l_queue_foreach(nodes, attach_io, io);
}

/* Register node object with D-Bus */
static bool register_node_object(struct mesh_node *node)
{
	char uuid[33];

	if (!hex2str(node->uuid, sizeof(node->uuid), uuid, sizeof(uuid)))
		return false;

	node->path = l_strdup_printf(MESH_NODE_PATH_PREFIX "%s", uuid);

	if (!l_dbus_object_add_interface(dbus_get_bus(), node->path,
					MESH_NODE_INTERFACE, node))
		return false;

	return true;
}

static void app_disc_cb(struct l_dbus *bus, void *user_data)
{
	struct mesh_node *node = user_data;

	l_info("App %s disconnected (%u)", node->owner, node->disc_watch);

	node->disc_watch = 0;

	l_queue_foreach(node->elements, free_element_path, NULL);

	l_free(node->owner);
	node->owner = NULL;

	if (node->path) {
		l_dbus_object_remove_interface(dbus_get_bus(), node->path,
							MESH_NODE_INTERFACE);
		l_free(node->app_path);
		node->app_path = NULL;
	}
}


static bool validate_model_property(struct node_element *ele,
					struct l_dbus_message_iter *property,
					uint8_t *num_models, bool vendor)
{
	struct l_dbus_message_iter ids;
	uint16_t mod_id, vendor_id;
	uint8_t count;
	const char *signature = !vendor ? "aq" : "a(qq)";

	if (!l_dbus_message_iter_get_variant(property, signature, &ids)) {
		/* Allow empty elements */
		if (l_queue_length(ele->models) == 0) {
			*num_models = 0;
			return true;
		} else
			return false;
	}

	count = 0;
	if (!vendor) {
		/* Bluetooth SIG defined models */
		while (l_dbus_message_iter_next_entry(&ids, &mod_id)) {
			struct mesh_model *mod;

			/* Skip internally implemented models */
			if ((VENDOR_ID_MASK | mod_id) == CONFIG_SRV_MODEL)
				continue;

			mod = l_queue_find(ele->models, match_model_id,
					L_UINT_TO_PTR(VENDOR_ID_MASK | mod_id));
			if (!mod)
				return false;
			count++;
		}
	} else {
		/* Vendor defined models */
		while (l_dbus_message_iter_next_entry(&ids, &vendor_id,
								&mod_id)) {
			struct mesh_model *mod;

			mod = l_queue_find(ele->models, match_model_id,
				L_UINT_TO_PTR((vendor_id << 16) | mod_id));
			if (!mod)
				return false;
			count++;
		}
	}

	*num_models = count;
	return true;
}

static void get_models_from_properties(struct node_element *ele,
					struct l_dbus_message_iter *property,
								bool vendor)
{
	struct l_dbus_message_iter ids;
	uint16_t mod_id, vendor_id;
	const char *signature = !vendor ? "aq" : "a(qq)";

	if (!ele->models)
		ele->models = l_queue_new();

	if (!l_dbus_message_iter_get_variant(property, signature, &ids))
		return;

	/* Bluetooth SIG defined models */
	if (!vendor) {
		while (l_dbus_message_iter_next_entry(&ids, &mod_id)) {
			struct mesh_model *mod;

			/* Skip internally implemented models */
			if ((VENDOR_ID_MASK | mod_id) == CONFIG_SRV_MODEL)
				continue;

			mod = mesh_model_new(ele->idx, mod_id);
			l_queue_push_tail(ele->models, mod);
		}
		return;
	}

	/* Vendor defined models */
	while (l_dbus_message_iter_next_entry(&ids, &vendor_id, &mod_id)) {
		struct mesh_model *mod;

		mod = mesh_model_vendor_new(ele->idx, vendor_id, mod_id);
		l_queue_push_tail(ele->models, mod);
	}
}

static bool get_element_properties(struct mesh_node *node, const char *path,
					struct l_dbus_message_iter *properties,
								bool is_new)
{
	struct node_element *ele;
	const char *key;
	struct l_dbus_message_iter var;
	bool have_index = false;
	uint8_t idx, mod_cnt, vendor_cnt;

	l_debug("path %s", path);

	while (l_dbus_message_iter_next_entry(properties, &key, &var)) {
		if (!strcmp(key, "Index")) {
			if (!l_dbus_message_iter_get_variant(&var, "y", &idx))
				return false;
			have_index = true;
			break;
		}
	}

	if (!have_index) {
		l_debug("Mandatory property \"Index\" not found");
		return false;
	}

	if (!is_new) {
		/* Validate composition: check the element index */
		ele = l_queue_find(node->elements, match_element_idx,
							L_UINT_TO_PTR(idx));
		if (!ele) {
			l_debug("Element with index %u not found", idx);
			return false;
		}
	} else {
		ele = l_new(struct node_element, 1);
		ele->location = DEFAULT_LOCATION;
		ele->idx = idx;
	}

	mod_cnt = 0;
	vendor_cnt = 0;

	while (l_dbus_message_iter_next_entry(properties, &key, &var)) {
		if (!strcmp(key, "Location")) {
			uint8_t loc;

			l_dbus_message_iter_get_variant(&var, "q", &loc);

			/* Validate composition: location match */
			if (!is_new && (ele->location != loc))
				return false;

			ele->location = loc;

		} else if (!strcmp(key, "Models")) {

			if (is_new)
				get_models_from_properties(ele, &var, false);
			else if (!validate_model_property(ele, &var, &mod_cnt,
									false))
				return false;

		} else if (!strcmp(key, "VendorModels")) {

			if (is_new)
				get_models_from_properties(ele, &var, true);
			else if (!validate_model_property(ele, &var,
							&vendor_cnt, true))
				return false;

		}
	}

	if (is_new) {
		l_queue_push_tail(node->elements, ele);
	} else {
		/* Account for internal Configuration Server model */
		if (idx == 0)
			mod_cnt += 1;

		/* Validate composition: number of models must match */
		if (l_queue_length(ele->models) != (mod_cnt + vendor_cnt))
			return false;

		ele->path = l_strdup(path);
	}

	return true;
}

static void convert_node_to_storage(struct mesh_node *node,
						struct mesh_db_node *db_node)
{
	const struct l_queue_entry *entry;

	db_node->cid = node->comp->cid;
	db_node->pid = node->comp->pid;
	db_node->vid = node->comp->vid;
	db_node->crpl = node->comp->crpl;
	db_node->modes.lpn = node->lpn;
	db_node->modes.proxy = node->proxy;

	db_node->modes.friend = node->friend;
	db_node->modes.relay.state = node->relay.mode;
	db_node->modes.relay.cnt = node->relay.cnt;
	db_node->modes.relay.interval = node->relay.interval;
	db_node->modes.beacon = node->beacon;

	db_node->ttl = node->ttl;
	db_node->seq_number = node->seq_number;

	db_node->elements = l_queue_new();

	entry = l_queue_get_entries(node->elements);

	for (; entry; entry = entry->next) {
		struct node_element *ele = entry->data;
		struct mesh_db_element *db_ele;
		const struct l_queue_entry *mod_entry;

		db_ele = l_new(struct mesh_db_element, 1);

		db_ele->index = ele->idx;
		db_ele->location = ele->location;
		db_ele->models = l_queue_new();

		mod_entry = l_queue_get_entries(ele->models);

		for (; mod_entry; mod_entry = mod_entry->next) {
			struct mesh_model *mod = mod_entry->data;
			struct mesh_db_model *db_mod;
			uint32_t mod_id = mesh_model_get_model_id(mod);

			db_mod = l_new(struct mesh_db_model, 1);
			db_mod->id = mod_id;
			db_mod->vendor = ((mod_id & VENDOR_ID_MASK)
							!= VENDOR_ID_MASK);

			l_queue_push_tail(db_ele->models, db_mod);
		}
		l_queue_push_tail(db_node->elements, db_ele);
	}

}

static bool create_node_config(struct mesh_node *node)
{
	struct mesh_db_node db_node;
	const struct l_queue_entry *entry;
	bool res;

	convert_node_to_storage(node, &db_node);
	res = storage_create_node_config(node, &db_node);

	/* Free temporarily allocated resources */
	entry = l_queue_get_entries(db_node.elements);
	for (; entry; entry = entry->next) {
		struct mesh_db_element *db_ele = entry->data;

		l_queue_destroy(db_ele->models, l_free);
	}

	l_queue_destroy(db_node.elements, l_free);

	return res;
}

static void set_defaults(struct mesh_node *node)
{
	/* TODO: these values should come from mesh.conf */
	if (!node->comp)
		node->comp = l_new(struct node_composition, 1);

	node->comp->crpl = DEFAULT_CRPL;
	node->lpn = MESH_MODE_UNSUPPORTED;
	node->proxy = MESH_MODE_UNSUPPORTED;
	node->friend = MESH_MODE_UNSUPPORTED;
	node->beacon = MESH_MODE_DISABLED;
	node->relay.mode = MESH_MODE_DISABLED;
	node->ttl = DEFAULT_TTL;
	node->seq_number = DEFAULT_SEQUENCE_NUMBER;

	/* Add configuration server model on primary element */
	add_internal_model(node, CONFIG_SRV_MODEL, PRIMARY_ELE_IDX);
}

static bool get_app_properties(struct mesh_node *node, const char *path,
					struct l_dbus_message_iter *properties,
								bool is_new)
{
	const char *key;
	struct l_dbus_message_iter variant;
	uint16_t value;

	l_debug("path %s", path);

	if (is_new)
		node->comp = l_new(struct node_composition, 1);

	while (l_dbus_message_iter_next_entry(properties, &key, &variant)) {

		if (!strcmp(key, "CompanyID")) {
			if (!l_dbus_message_iter_get_variant(&variant, "q",
									&value))
				return false;

			if (!is_new && node->comp->cid != value)
				return false;

			node->comp->cid = value;

		} else if (!strcmp(key, "ProductID")) {
			if (!l_dbus_message_iter_get_variant(&variant, "q",
									&value))
				return false;

			if (!is_new && node->comp->pid != value)
				return false;

			node->comp->pid = value;

		} else if (!strcmp(key, "VersionID")) {
			if (!l_dbus_message_iter_get_variant(&variant, "q",
									&value))
				return false;

			if (!is_new && node->comp->vid != value)
				return false;

			node->comp->vid = value;
		}
	}

	return true;
}

static bool parse_imported_iv_index(json_object *jobj, uint32_t *idx,
								bool *update)
{
	int tmp;
	json_object *jvalue;

	if (!json_object_object_get_ex(jobj, "IVindex", &jvalue))
		return false;

	tmp = json_object_get_int(jvalue);
	*idx = (uint32_t) tmp;

	if (!json_object_object_get_ex(jobj, "IVupdate", &jvalue))
		return false;

	tmp = json_object_get_int(jvalue);
	*update = (bool)tmp;

	return true;
}

static bool parse_imported_unicast_addr(json_object *jobj, uint16_t *unicast)
{
	json_object *jvalue;
	char *str;

	if (!json_object_object_get_ex(jobj, "unicastAddress", &jvalue))
		return false;

	str = (char *)json_object_get_string(jvalue);

	if (sscanf(str, "%04hx", unicast) != 1)
		return false;

	return true;
}

static bool parse_imported_device_key(json_object *jobj, uint8_t key_buf[16])
{
	json_object *jvalue;
	char *str;

	if (!key_buf)
		return false;

	if (!json_object_object_get_ex(jobj, "deviceKey", &jvalue))
		return false;

	str = (char *)json_object_get_string(jvalue);

	if (!str2hex(str, strlen(str), key_buf, 16))
		return false;

	return true;
}

static bool parse_imported_net_key(json_object *jobj, uint8_t key_buf[16],
								bool *kr)
{
	json_object *jvalue;
	char *str;

	if (!key_buf)
		return false;

	if (!json_object_object_get_ex(jobj, "netKey", &jvalue))
		return false;

	str = (char *)json_object_get_string(jvalue);

	if (!str2hex(str, strlen(str), key_buf, 16))
		return false;

	/* Get key refresh */
	if (!json_object_object_get_ex(jobj, "keyRefresh", &jvalue))
		return false;

	*kr = (bool)json_object_get_boolean(jvalue);
	return true;
}


static bool add_local_node(struct mesh_node *node, uint16_t unicast, bool kr,
				bool ivu, uint32_t iv_idx, uint8_t dev_key[16],
				uint16_t net_key_idx, uint8_t net_key[16])
{
	if (!storage_set_iv_index(node->net, iv_idx, ivu))
		return false;

	mesh_net_set_iv_index(node->net, iv_idx, ivu);

	if (!mesh_db_write_uint16_hex(node->jconfig, "unicastAddress",
								unicast))
		return false;

	l_getrandom(node->token, sizeof(node->token));
	if (!mesh_db_write_token(node->jconfig, node->token))
		return false;

	memcpy(node->dev_key, dev_key, 16);
	if (!mesh_db_write_device_key(node->jconfig, dev_key))
		return false;

	node->primary = unicast;
	mesh_net_register_unicast(node->net, unicast, node->num_ele);

	if (mesh_net_add_key(node->net, net_key_idx, net_key) !=
							MESH_STATUS_SUCCESS)
		return false;

	if (kr) {
		/* Duplicate net key, if the key refresh is on */
		if (mesh_net_update_key(node->net, net_key_idx, net_key) !=
							MESH_STATUS_SUCCESS)
			return false;

		if (!mesh_db_net_key_set_phase(node->jconfig, net_key_idx,
							KEY_REFRESH_PHASE_TWO))
			return false;
	}

	storage_save_config(node, true, NULL, NULL);

	/* Initialize configuration server model */
	mesh_config_srv_init(node, PRIMARY_ELE_IDX);

	return true;
}

static void get_managed_objects_cb(struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_iter objects, interfaces;
	struct managed_obj_request *req = user_data;
	const char *path;
	struct mesh_node *node = NULL;
	void *agent = NULL;
	bool have_app = false;
	bool is_new;
	uint8_t num_ele;

	is_new = (req->type != REQUEST_TYPE_ATTACH);

	if (l_dbus_message_is_error(msg)) {
		l_error("Failed to get app's dbus objects");
		goto fail;
	}

	if (!l_dbus_message_get_arguments(msg, "a{oa{sa{sv}}}", &objects)) {
		l_error("Failed to parse app's dbus objects");
		goto fail;
	}

	if (is_new) {
		node = node_new(req->data);
		node->elements = l_queue_new();
	} else {
		node = req->data;
	}

	num_ele = 0;
	while (l_dbus_message_iter_next_entry(&objects, &path, &interfaces)) {
		struct l_dbus_message_iter properties;
		const char *interface;

		while (l_dbus_message_iter_next_entry(&interfaces, &interface,
								&properties)) {
			bool res;

			if (!strcmp(MESH_ELEMENT_INTERFACE, interface)) {

				if (num_ele == MAX_ELE_COUNT)
					goto fail;

				res = get_element_properties(node, path,
							&properties, is_new);
				if (!res)
					goto fail;

				num_ele++;

			} else if (!strcmp(MESH_APPLICATION_INTERFACE,
								interface)) {
				res = get_app_properties(node, path,
							&properties, is_new);
				if (!res)
					goto fail;

				have_app = true;

			} else if (!strcmp(MESH_PROVISION_AGENT_INTERFACE,
								interface)) {
				const char *sender;

				sender = l_dbus_message_get_sender(msg);
				agent = mesh_agent_create(path, sender,
								&properties);
				if (!agent)
					goto fail;
			} else if (!strcmp(MESH_PROVISIONER_INTERFACE,
								interface)) {
				node->provisioner = true;
			}
		}
	}

	if (!have_app) {
		l_error("Interface %s not found", MESH_APPLICATION_INTERFACE);
		goto fail;
	}

	if (num_ele == 0) {
		l_error("Interface %s not found", MESH_ELEMENT_INTERFACE);
		goto fail;
	}

	if (!l_queue_find(node->elements, match_element_idx,
				L_UINT_TO_PTR(PRIMARY_ELE_IDX))) {

		l_debug("Primary element not detected");
		goto fail;
	}

	if (req->type == REQUEST_TYPE_ATTACH) {
		node_ready_func_t cb = req->cb;

		if (num_ele != node->num_ele)
			goto fail;

		if (register_node_object(node)) {
			struct l_dbus *bus = dbus_get_bus();

			node->disc_watch = l_dbus_add_disconnect_watch(bus,
					node->owner, app_disc_cb, node, NULL);
			cb(req->user_data, MESH_ERROR_NONE, node);
		} else
			goto fail;

	} else if (req->type == REQUEST_TYPE_JOIN) {
		node_join_ready_func_t cb = req->cb;

		if (!agent) {
			l_error("Interface %s not found",
						MESH_PROVISION_AGENT_INTERFACE);
			goto fail;
		}

		node->num_ele = num_ele;
		set_defaults(node);
		memcpy(node->uuid, req->data, 16);

		if (!create_node_config(node))
			goto fail;

		cb(node, agent);

	} else if (req->type == REQUEST_TYPE_IMPORT) {

		node_ready_func_t cb = req->cb;
		struct node_import_request *import_data = req->user_data;
		struct keyring_net_key net_key;

		if (!agent) {
			l_error("Interface %s not found",
						MESH_PROVISION_AGENT_INTERFACE);
			goto fail;
		}

		node->num_ele = num_ele;
		set_defaults(node);
		memcpy(node->uuid, import_data->uuid, 16);

		if (!create_node_config(node))
			goto fail;

		if (!add_local_node(node, import_data->unicast, import_data->kr,
				import_data->iv_update, import_data->iv_idx,
				import_data->dev_key, PRIMARY_NET_IDX,
							import_data->net_key))
			goto fail;

		memcpy(net_key.old_key, import_data->net_key, 16);
		net_key.net_idx = PRIMARY_NET_IDX;
		net_key.phase = KEY_REFRESH_PHASE_NONE;

		if (!keyring_put_remote_dev_key(node, import_data->unicast,
						num_ele, import_data->dev_key))
			goto fail;

		if (!keyring_put_net_key(node, PRIMARY_NET_IDX, &net_key))
			goto fail;

		cb(import_data->user_data, MESH_ERROR_NONE, node);

	} else {
		/* Callback for create node request */
		node_ready_func_t cb = req->cb;
		struct keyring_net_key net_key;
		uint8_t dev_key[16];

		node->num_ele = num_ele;
		set_defaults(node);
		memcpy(node->uuid, req->data, 16);

		if (!create_node_config(node))
			goto fail;

		/* Generate device and primary network keys */
		l_getrandom(dev_key, sizeof(dev_key));
		l_getrandom(net_key.old_key, sizeof(net_key.old_key));
		net_key.net_idx = PRIMARY_NET_IDX;
		net_key.phase = KEY_REFRESH_PHASE_NONE;

		if (!add_local_node(node, DEFAULT_NEW_UNICAST, false, false,
						DEFAULT_IV_INDEX, dev_key,
						PRIMARY_NET_IDX,
						net_key.old_key))
			goto fail;

		if (!keyring_put_remote_dev_key(node, DEFAULT_NEW_UNICAST,
							num_ele, dev_key))
			goto fail;

		if (!keyring_put_net_key(node, PRIMARY_NET_IDX, &net_key))
			goto fail;

		cb(req->user_data, MESH_ERROR_NONE, node);
	}

	return;
fail:
	if (agent)
		mesh_agent_remove(agent);

	if (!is_new) {
		/* Handle failed Attach request */
		node_ready_func_t cb = req->cb;

		l_queue_foreach(node->elements, free_element_path, NULL);
		l_free(node->app_path);
		node->app_path = NULL;

		l_free(node->owner);
		node->owner = NULL;
		cb(req->user_data, MESH_ERROR_FAILED, node);

	} else {
		/* Handle failed Join and Create requests */
		if (node)
			free_node_resources(node);

		if (req->type == REQUEST_TYPE_JOIN) {
			node_join_ready_func_t cb = req->cb;

			cb(NULL, NULL);
		} else {
			node_ready_func_t cb = req->cb;

			cb(req->user_data, MESH_ERROR_FAILED, NULL);
		}
	}
}

/* Establish relationship between application and mesh node */
int node_attach(const char *app_path, const char *sender, uint64_t token,
					node_ready_func_t cb, void *user_data)
{
	struct managed_obj_request *req;
	struct mesh_node *node;

	node = l_queue_find(nodes, match_token, (void *) &token);
	if (!node)
		return MESH_ERROR_NOT_FOUND;

	/* Check if the node is already in use */
	if (node->owner) {
		l_warn("The node is already in use");
		return MESH_ERROR_ALREADY_EXISTS;
	}

	node->app_path = l_strdup(app_path);
	node->owner = l_strdup(sender);

	req = l_new(struct managed_obj_request, 1);
	req->data = node;
	req->cb = cb;
	req->user_data = user_data;
	req->type = REQUEST_TYPE_ATTACH;

	l_dbus_method_call(dbus_get_bus(), sender, app_path,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"GetManagedObjects", NULL,
					get_managed_objects_cb,
					req, l_free);
	return MESH_ERROR_NONE;

}


/* Create a temporary pre-provisioned node */
void node_join(const char *app_path, const char *sender, const uint8_t *uuid,
						node_join_ready_func_t cb)
{
	struct managed_obj_request *req;

	l_debug("");

	req = l_new(struct managed_obj_request, 1);
	req->data = (void *) uuid;
	req->cb = cb;
	req->type = REQUEST_TYPE_JOIN;

	l_dbus_method_call(dbus_get_bus(), sender, app_path,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"GetManagedObjects", NULL,
					get_managed_objects_cb,
					req, l_free);
}


bool node_import(const char *app_path, const char *sender, void *json_data,
		const uint8_t *uuid, node_ready_func_t cb, void *user_data)
{
	struct managed_obj_request *req;
	struct node_import_request *node;

	l_debug("");
	node = l_new(struct node_import_request, 1);
	req = l_new(struct managed_obj_request, 1);

	if (!parse_imported_device_key(json_data, node->dev_key)) {
		l_error("Failed to parse imported device key");
		goto fail;
	}

	if (!parse_imported_unicast_addr(json_data, &node->unicast)) {
		l_error("Failed to parse imported unicast address");
		goto fail;
	}

	if (!parse_imported_iv_index(json_data, &node->iv_idx,
							&node->iv_update)) {
		l_error("Failed to parse imported iv idx");
		goto fail;
	}


	if (!parse_imported_net_key(json_data, node->net_key, &node->kr)) {
		l_error("Failed to parse imported network key");
		goto fail;
	}

	node->user_data = user_data;

	memcpy(node->uuid, uuid, 16);
	req->data = (void *) uuid;
	req->user_data = node;
	req->cb = cb;
	req->type = REQUEST_TYPE_IMPORT;

	l_dbus_method_call(dbus_get_bus(), sender, app_path,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"GetManagedObjects", NULL,
					get_managed_objects_cb,
					req, l_free);
	return true;
fail:
	json_object_put(json_data);
	l_free(node);
	return false;
}

void node_create(const char *app_path, const char *sender, const uint8_t *uuid,
					node_ready_func_t cb, void *user_data)
{
	struct managed_obj_request *req;

	l_debug("");

	req = l_new(struct managed_obj_request, 1);
	req->data = (void *) uuid;
	req->cb = cb;
	req->user_data = user_data;
	req->type = REQUEST_TYPE_CREATE;

	l_dbus_method_call(dbus_get_bus(), sender, app_path,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"GetManagedObjects", NULL,
					get_managed_objects_cb,
					req, l_free);
}

static void build_element_config(void *a, void *b)
{
	struct node_element *ele = a;
	struct l_dbus_message_builder *builder = b;

	l_debug("Element %u", ele->idx);

	l_dbus_message_builder_enter_struct(builder, "ya(qa{sv})");

	/* Element index */
	l_dbus_message_builder_append_basic(builder, 'y', &ele->idx);

	l_dbus_message_builder_enter_array(builder, "(qa{sv})");

	/* Iterate over models */
	l_queue_foreach(ele->models, model_build_config, builder);

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_leave_struct(builder);
}

void node_build_attach_reply(struct mesh_node *node,
						struct l_dbus_message *reply)
{
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(reply);

	/* Node object path */
	l_dbus_message_builder_append_basic(builder, 'o', node->path);

	/* Array of element configurations "a*/
	l_dbus_message_builder_enter_array(builder, "(ya(qa{sv}))");
	l_queue_foreach(node->elements, build_element_config, builder);
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static struct l_dbus_message *send_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct mesh_node *node = user_data;
	const char *sender, *ele_path;
	struct l_dbus_message_iter iter_data;
	struct node_element *ele;
	uint16_t dst, app_idx, src;
	uint8_t *data;
	uint32_t len;
	struct l_dbus_message *reply;

	l_debug("Send");

	sender = l_dbus_message_get_sender(msg);

	if (strcmp(sender, node->owner))
		return dbus_error(msg, MESH_ERROR_NOT_AUTHORIZED, NULL);

	if (!l_dbus_message_get_arguments(msg, "oqqay", &ele_path, &dst,
							&app_idx, &iter_data))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	ele = l_queue_find(node->elements, match_element_path, ele_path);
	if (!ele)
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
							"Element not found");

	src = node_get_primary(node) + ele->idx;

	if (!l_dbus_message_iter_get_fixed_array(&iter_data, &data, &len) ||
					!len || len > MESH_MAX_ACCESS_PAYLOAD)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Incorrect data");

	if (!mesh_model_send(node, src, dst, app_idx,
				mesh_net_get_default_ttl(node->net), data, len))
		return dbus_error(msg, MESH_ERROR_FAILED, NULL);

	reply = l_dbus_message_new_method_return(msg);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static struct l_dbus_message *publish_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct mesh_node *node = user_data;
	const char *sender, *ele_path;
	struct l_dbus_message_iter iter_data;
	uint16_t mod_id, src;
	struct node_element *ele;
	uint8_t *data;
	uint32_t len;
	struct l_dbus_message *reply;
	int result;

	l_debug("Publish");

	sender = l_dbus_message_get_sender(msg);

	if (strcmp(sender, node->owner))
		return dbus_error(msg, MESH_ERROR_NOT_AUTHORIZED, NULL);

	if (!l_dbus_message_get_arguments(msg, "oqay", &ele_path, &mod_id,
								&iter_data))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	ele = l_queue_find(node->elements, match_element_path, ele_path);
	if (!ele)
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
							"Element not found");

	src = node_get_primary(node) + ele->idx;

	if (!l_dbus_message_iter_get_fixed_array(&iter_data, &data, &len) ||
					!len || len > MESH_MAX_ACCESS_PAYLOAD)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Incorrect data");

	result = mesh_model_publish(node, VENDOR_ID_MASK | mod_id, src,
				mesh_net_get_default_ttl(node->net), data, len);

	if (result != MESH_ERROR_NONE)
		return dbus_error(msg, result, NULL);

	reply = l_dbus_message_new_method_return(msg);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static struct l_dbus_message *vendor_publish_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct mesh_node *node = user_data;
	const char *sender, *ele_path;
	struct l_dbus_message_iter iter_data;
	uint16_t src;
	uint16_t model_id, vendor;
	uint32_t vendor_mod_id;
	struct node_element *ele;
	uint8_t *data = NULL;
	uint32_t len;
	struct l_dbus_message *reply;
	int result;

	l_debug("Publish");

	sender = l_dbus_message_get_sender(msg);

	if (strcmp(sender, node->owner))
		return dbus_error(msg, MESH_ERROR_NOT_AUTHORIZED, NULL);

	if (!l_dbus_message_get_arguments(msg, "oqqay", &ele_path, &vendor,
							&model_id, &iter_data))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	ele = l_queue_find(node->elements, match_element_path, ele_path);
	if (!ele)
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
							"Element not found");

	src = node_get_primary(node) + ele->idx;

	if (!l_dbus_message_iter_get_fixed_array(&iter_data, &data, &len) ||
					!len || len > MESH_MAX_ACCESS_PAYLOAD)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Incorrect data");

	vendor_mod_id = (vendor << 16) | model_id;
	result = mesh_model_publish(node, vendor_mod_id, src,
				mesh_net_get_default_ttl(node->net), data, len);

	if (result != MESH_ERROR_NONE)
		return dbus_error(msg, result, NULL);

	reply = l_dbus_message_new_method_return(msg);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static void setup_node_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "Send", 0, send_call, "", "oqqay",
						"element_path", "destination",
						"key", "data");
	l_dbus_interface_method(iface, "Publish", 0, publish_call, "", "oqay",
					"element_path", "model_id", "data");
	l_dbus_interface_method(iface, "VendorPublish", 0, vendor_publish_call,
						"", "oqqay", "element_path",
						"vendor", "model_id", "data");

	/* TODO: Properties */
}

bool node_dbus_init(struct l_dbus *bus)
{
	if (!l_dbus_register_interface(bus, MESH_NODE_INTERFACE,
						setup_node_interface,
						NULL, false)) {
		l_info("Unable to register %s interface", MESH_NODE_INTERFACE);
		return false;
	}

	return true;
}

const char *node_get_owner(struct mesh_node *node)
{
	return node->owner;
}

const char *node_get_element_path(struct mesh_node *node, uint8_t ele_idx)
{
	struct node_element *ele;

	ele = l_queue_find(node->elements, match_element_idx,
							L_UINT_TO_PTR(ele_idx));

	if (!ele)
		return NULL;

	return ele->path;
}

bool node_add_pending_local(struct mesh_node *node, void *prov_node_info)
{
	struct mesh_prov_node_info *info = prov_node_info;
	bool kr = !!(info->flags & PROV_FLAG_KR);
	bool ivu = !!(info->flags & PROV_FLAG_IVU);

	return add_local_node(node, info->unicast, kr, ivu, info->iv_index,
			info->device_key, info->net_index, info->net_key);
}

void node_jconfig_set(struct mesh_node *node, void *jconfig)
{
	node->jconfig = jconfig;
}

void *node_jconfig_get(struct mesh_node *node)
{
	return node->jconfig;
}

void node_path_set(struct mesh_node *node, char *path)
{
	l_free(node->node_path);
	node->node_path = l_strdup(path);
}

char *node_path_get(struct mesh_node *node)
{
	return node->node_path;
}

struct mesh_net *node_get_net(struct mesh_node *node)
{
	return node->net;
}
