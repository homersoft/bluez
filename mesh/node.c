/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017-2018  Intel Corporation. All rights reserved.
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
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <inttypes.h>
#include <sys/time.h>
#include <ell/ell.h>

#include "mesh/mesh-defs.h"

#include "mesh/mesh.h"
#include "mesh/mesh-io.h"
#include "mesh/net.h"
#include "mesh/mesh-db.h"
#include "mesh/provision.h"
#include "mesh/storage.h"
#include "mesh/appkey.h"
#include "mesh/model.h"
#include "mesh/cfgmod.h"
#include "mesh/util.h"
#include "mesh/error.h"
#include "mesh/dbus.h"
#include "mesh/agent.h"
#include "mesh/node.h"

#define MIN_COMP_SIZE 14

#define MESH_NODE_PATH_PREFIX "/org/bluez/mesh/node_"
#define MESH_NODE_PATH_PREFIX_LEN 21

/* Default element location: unknown */
#define DEFAULT_LOCATION 0x0000

#define DEFAULT_CRPL 10
#define DEFAULT_SEQUENCE_NUMBER 0

struct node_element {
	struct l_queue *models;
	uint8_t idx;
	uint16_t location;
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
	char *cfg_file;
	uint32_t disc_watch;
	time_t upd_sec;
	uint32_t seq_number;
	uint32_t seq_min_cache;
	uint16_t id;
	bool provisioner;
	uint16_t primary;
	struct node_composition *comp;
	struct {
		uint16_t interval;
		uint8_t cnt;
		uint8_t mode;
	} relay;
	uint8_t dev_uuid[UUID_LEN];
	uint8_t dev_key[DEVKEY_LEN];
	uint8_t num_ele;
	uint8_t ttl;
	uint8_t lpn;
	uint8_t proxy;
	uint8_t friend;
	uint8_t beacon;
	bool is_advertising;
};

static struct l_queue *nodes;

static bool match_node_unicast(const void *a, const void *b)
{
	const struct mesh_node *node = a;
	uint16_t dst = L_PTR_TO_UINT(b);

	return (dst >= node->primary &&
		dst <= (node->primary + node->num_ele - 1));
}

static bool match_node_uuid(const void *a, const void *b)
{
	const struct mesh_node *node = a;
	const uint8_t *uuid = b;

	return (memcmp(node->dev_uuid, uuid, UUID_LEN) == 0);
}

static bool match_token(const void *a, const void *b)
{
	const struct mesh_node *node = a;
	const uint64_t *token = b;
	const uint64_t tmp = l_get_u64(node->dev_key);
	return *token == tmp;
}

static bool match_element_idx(const void *a, const void *b)
{
	const struct node_element *element = a;
	uint32_t index = L_PTR_TO_UINT(b);

	return (element->idx == index);
}

static int compare_element_idx(const void *a, const void *b, void *user_data)
{
	const struct node_element *new_element = a;
	const struct node_element *current_element = b;

	return (new_element->idx - current_element->idx);
}

struct mesh_node *node_find_by_addr(uint16_t addr)
{
	if (!IS_UNICAST(addr))
		return NULL;

	return l_queue_find(nodes, match_node_unicast, L_UINT_TO_PTR(addr));
}

struct mesh_node *node_find_by_uuid(uint8_t uuid[UUID_LEN])
{
	return l_queue_find(nodes, match_node_uuid, uuid);
}

uint8_t *node_uuid_get(struct mesh_node *node)
{
	if (!node)
		return NULL;
	return node->dev_uuid;
}

void replace_dash_with_underscore(char *src, uint32_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (src[i] == '-')
			src[i] = '_';
	}
}

void get_node_path_from_uuid(char *path, uint8_t *uuid)
{
	char uuid_string[(UUID_LEN * 2) + 5] = {'\0'};

	l_uuid_to_string(uuid, uuid_string, ((UUID_LEN * 2) + 5));

	replace_dash_with_underscore(uuid_string, (UUID_LEN * 2) + 5);

	snprintf(path, ((UUID_LEN * 2) + MESH_NODE_PATH_PREFIX_LEN + 5), "%s%s",
		MESH_NODE_PATH_PREFIX, uuid_string);
}

struct mesh_node *node_new(void)
{
	struct mesh_node *node;

	node = l_new(struct mesh_node, 1);
	//todo:JWI
	//node->net = mesh_net_new(node);

	if (!nodes)
		nodes = l_queue_new();

	l_queue_push_tail(nodes, node);

	return node;
}

static void element_free(void *data)
{
	struct node_element *element = data;

	l_queue_destroy(element->models, mesh_model_free);
	l_free(element);
}

static void free_node_resources_simple(void *data)
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
}

static void free_node_resources(void *data)
{
	struct mesh_node *node = data;
	char path[(UUID_LEN * 2) + MESH_NODE_PATH_PREFIX_LEN + 6] = {'\0'};

	get_node_path_from_uuid(path, node->dev_uuid);

	free_node_resources_simple(node);

	l_dbus_object_remove_interface(dbus_get_bus(), path,
					MESH_NODE_INTERFACE);
	l_dbus_object_remove_interface(dbus_get_bus(), path,
					MESH_PROVISIONING_INTERFACE);
	l_dbus_object_remove_interface(dbus_get_bus(), path,
					L_DBUS_INTERFACE_PROPERTIES);

	l_dbus_unregister_object(dbus_get_bus(), path);

	l_free(node->path);

	l_free(node);
}

void node_free(struct mesh_node *node)
{
	if (!node)
		return;

	l_queue_remove(nodes, node);
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

static bool add_model_from_properties(struct node_element *ele,
				uint16_t model_id)
{
	struct mesh_model *mod;

	if (!ele->models)
		ele->models = l_queue_new();

	l_debug("sig model_id %4.4x", model_id);
	mod = mesh_model_new(ele->idx, model_id);
	l_queue_insert(ele->models, mod, compare_model_id, NULL);
}

static bool add_vendor_model_from_properties(struct node_element *ele,
				uint16_t vendor_id, uint16_t model_id)
{
	struct mesh_model *mod;

	if (!ele->models)
		ele->models = l_queue_new();

	l_debug("model_id %4.4x vendor_id: %4.4x", model_id, vendor_id);
	mod = mesh_model_vendor_new(ele->idx, vendor_id, model_id);
	l_queue_insert(ele->models, mod, compare_model_id, NULL);
}

static bool add_element_properties(struct mesh_node *node,
				uint8_t element_idx,
				uint16_t location,
				struct l_dbus_message_iter *iter_sig_models,
				struct l_dbus_message_iter *iter_vendor_models,
				uint16_t cid)
{
	struct node_element *ele;
	uint16_t model = 0;
	uint32_t config_model = 0xFFFF0000;
	uint32_t health_model = 0xFFFF0002;

	ele = l_new(struct node_element, 1);
	ele->idx = element_idx;
	ele->location = location;
	ele->models = l_queue_new();

	while (l_dbus_message_iter_next_entry(iter_sig_models, &model))
		add_model_from_properties(ele, model);

	while (l_dbus_message_iter_next_entry(iter_vendor_models, &model))
		add_vendor_model_from_properties(ele, cid, model);

	if (element_idx == 0) {
		if (!l_queue_find(ele->models, match_model_id,
				L_UINT_TO_PTR(config_model)))
			add_model_from_properties(ele, 0x0000);

		if (!l_queue_find(ele->models, match_model_id,
				L_UINT_TO_PTR(health_model)))
			add_model_from_properties(ele, 0x0002);
	} else {
		if (l_queue_find(ele->models, match_model_id,
				L_UINT_TO_PTR(config_model)) ||
			l_queue_find(ele->models, match_model_id,
				L_UINT_TO_PTR(health_model)))
			goto failed;
	}

	if (!l_queue_insert(node->elements, ele, compare_element_idx, NULL))
		goto failed;

	node->num_ele++;
	return true;

failed:
	element_free(ele);
	return false;
}

static void add_internal_models(struct mesh_node *node)
{
	struct node_element *ele;

	ele = l_queue_find(node->elements, match_element_idx,
				L_UINT_TO_PTR(PRIMARY_ELE_IDX));

	//adding minimal SIG models configuration onto primary element with
	//0x0000 (unknown) location
	if (!ele)
		add_element_properties(node, PRIMARY_ELE_IDX,
			0x0000, NULL, NULL, 0);
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
	node->lpn = db_node->modes.low_power;

	node->proxy = db_node->modes.proxy;
	node->friend = db_node->modes.friend;
	node->beacon = db_node->modes.beacon;

	l_debug("proxy %2.2x, lpn %2.2x, friend %2.2x",
			  node->proxy, node->friend, node->lpn);

	node->ttl = db_node->ttl;
	node->seq_number = db_node->seq_number;

	num_ele = l_queue_length(db_node->elements);
	if (num_ele > 0xff)
		return false;

	node->num_ele = num_ele;
	if (num_ele != 0 && !add_elements(node, db_node))
		return false;

	node->primary = db_node->unicast;

	if(db_node->provisioned) {
		node->net = mesh_net_new(node);
		l_info("provisioned node from storage");
	} else {
		l_info("unprovisioned node from storage");
	}

	/* Initialize configuration server model */
	mesh_config_srv_init(node, PRIMARY_ELE_IDX);

	return true;
}

void node_cleanup(void *data)
{
	struct mesh_node *node = data;
	struct mesh_net *net = node->net;

	/* Save local node configuration */
	if (node->cfg_file) {

		/* Preserve the last sequence number */
		if (net)
			storage_write_sequence_number(net, mesh_net_get_seq_num(net));

		if (storage_save_config(node, true, NULL, NULL))
			l_info("Saved final config to %s", node->cfg_file);
	}

	if (node->disc_watch)
		dbus_disconnect_watch_remove(dbus_get_bus(), node->disc_watch);

	free_node_resources(node);
}

void node_cleanup_all(void)
{
	l_queue_destroy(nodes, node_cleanup);
	l_dbus_unregister_interface(dbus_get_bus(), MESH_NODE_INTERFACE);
	l_dbus_unregister_interface(dbus_get_bus(),
		MESH_PROVISIONING_INTERFACE);
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

void node_set_device_key(struct mesh_node *node, uint8_t key[DEVKEY_LEN])
{
	memcpy(node->dev_key, key, DEVKEY_LEN);
}

void node_set_uuid(struct mesh_node *node, uint8_t uuid[UUID_LEN])
{
	memcpy(node->dev_uuid, uuid, UUID_LEN);
}

const uint8_t *node_get_device_key(struct mesh_node *node)
{
	if (!node)
		return NULL;
	else
		return node->dev_key;
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

	res = storage_set_ttl(node->jconfig, ttl);

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

	res = storage_set_relay(node->jconfig, enable, cnt, interval);

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

void node_id_set(struct mesh_node *node, uint16_t id)
{
	if (node)
		node->id = id;
}

static void attach_io(void *a, void *b)
{
	struct mesh_node *node = a;
	struct mesh_io *io = b;

	if (node->net)
		mesh_net_attach(node->net, io);
}

/* Register callbacks for io */
void node_attach_io(struct mesh_io *io)
{
	l_queue_foreach(nodes, attach_io, io);
}

bool register_node_object(struct mesh_node *node)
{
	l_debug("");

	char path[(UUID_LEN * 2) + MESH_NODE_PATH_PREFIX_LEN + 6] = {'\0'};

	get_node_path_from_uuid(path, node->dev_uuid);

	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
				MESH_NODE_INTERFACE, NULL)) {
		l_info("Unable to add %s object", path);
		return false;
	}

	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
				MESH_PROVISIONING_INTERFACE, NULL)) {
		l_info("Unable to add %s object", path);
		return false;
	}

	if (!l_dbus_object_add_interface(dbus_get_bus(), path,
				L_DBUS_INTERFACE_PROPERTIES, NULL)) {
		l_info("Unable to add %s object", path);
		return false;
	}

	return true;
}

static void app_disc_cb(struct l_dbus *bus, void *user_data)
{
	struct mesh_node *node = user_data;

	l_info("App %s disconnected (%u)", node->owner, node->disc_watch);

	node->disc_watch = 0;

	l_free(node->owner);
	node->owner = NULL;

	l_free(node->app_path);
	node->app_path = NULL;
}

static void convert_node_to_storage(struct mesh_node *node,
												struct mesh_db_node *db_node)
{
	const struct l_queue_entry *entry;

	db_node->cid = node->comp->cid;
	db_node->pid = node->comp->pid;
	db_node->vid = node->comp->vid;

	db_node->iv_index = mesh_net_get_iv_index(node_get_net(node));
	db_node->iv_update = mesh_net_get_iv_update(node_get_net(node));

	memcpy(db_node->uuid, node->dev_uuid, UUID_LEN);
	db_node->modes.beacon = node->beacon;
	db_node->ttl = node->ttl;

	memcpy(db_node->dev_key, node->dev_key, DEVKEY_LEN);
	db_node->modes.friend = node->friend;
	db_node->modes.low_power = node->lpn;

	db_node->provisioned = node->net ? true : false;
	db_node->modes.proxy = node->proxy;
	db_node->seq_number = node->seq_number;
	db_node->unicast = node->primary;
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

	node->comp->crpl = DEFAULT_CRPL;
	node->lpn = MESH_MODE_UNSUPPORTED;
	node->proxy = MESH_MODE_UNSUPPORTED;
	node->friend = MESH_MODE_UNSUPPORTED;
	node->beacon = MESH_MODE_DISABLED;
	node->relay.mode = MESH_MODE_DISABLED;
	node->ttl = DEFAULT_TTL;
	node->seq_number = DEFAULT_SEQUENCE_NUMBER;
}

bool create_node_request(uint8_t *uuid, uint16_t cid, uint16_t pid,
		uint16_t vid, struct l_dbus_message_iter *iter_element_models)
{
	struct mesh_node *new_node;
	struct l_dbus_message_iter iter_sig_models, iter_vendor_models;
	uint8_t element_idx;
	uint16_t location;

	l_debug("");

	new_node = l_new(struct mesh_node, 1);
	new_node->elements = l_queue_new();
	memcpy(new_node->dev_uuid, uuid, UUID_LEN);

	while (l_dbus_message_iter_next_entry(iter_element_models,
				&element_idx, &location,
				&iter_sig_models, &iter_vendor_models)) {
		if (!add_element_properties(new_node, element_idx, location,
				&iter_sig_models, &iter_vendor_models, cid))
			goto failed;
	}

	add_internal_models(new_node);

	if (!new_node->comp)
		new_node->comp = l_new(struct node_composition, 1);

	new_node->comp->cid = cid;
	new_node->comp->pid = pid;
	new_node->comp->vid = vid;

	new_node->is_advertising = false;

	set_defaults(new_node);

	create_node_config(new_node);

	if (!nodes)
		nodes = l_queue_new();

	l_queue_push_tail(nodes, new_node);
	register_node_object(new_node);

	return true;

failed:
	free_node_resources_simple(new_node);
	return false;
}

bool delete_node(uint8_t *uuid)
{
	struct mesh_node *node = NULL;

	node = l_queue_find(nodes, match_node_uuid, uuid);

	if (node) {
		//TODO: check if adveritising in progress and kill prov_acceptor
		l_queue_remove(nodes, node);
		node_free(node);
		return true;
	}

	return false;

}

bool provision_node(struct mesh_node *node, uint8_t *network_key, uint16_t addr)
{
	//TODO
	return true;
}

bool unprovision_node(struct mesh_node *node)
{
	//TODO
	return true;
}

bool start_advertising(struct mesh_node *node)
{
	//TODO
	node->is_advertising = true;
	return true;
}

bool stop_advertising(struct mesh_node *node)
{
	//TODO
	node->is_advertising = false;
	return true;
}

bool send_message(struct mesh_node *node, uint16_t element, uint16_t dest,
		uint8_t *opcode, uint8_t *payload, uint16_t len,
		uint16_t key_index)
{
	//TODO
	return true;
}

bool get_uuid_from_path(const char *path, uint8_t *uuid)
{
	int n;

	path += MESH_NODE_PATH_PREFIX_LEN;

	n = sscanf(path, "%2"SCNx8 "%2"SCNx8 "%2"SCNx8 "%2"SCNx8
				"_%2"SCNx8 "%2"SCNx8 "_%2"SCNx8 "%2"SCNx8
				"_%2"SCNx8 "%2"SCNx8 "_%2"SCNx8 "%2"SCNx8
				"%2"SCNx8 "%2"SCNx8 "%2"SCNx8 "%2"SCNx8 "",
				&uuid[0], &uuid[1], &uuid[2], &uuid[3],
				&uuid[4], &uuid[5], &uuid[6], &uuid[7],
				&uuid[8], &uuid[9], &uuid[10], &uuid[11],
				&uuid[12], &uuid[13], &uuid[14], &uuid[15]);

	if (n != UUID_LEN)
		return false;

	return true;
}

static struct l_dbus_message *provision_call(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *reply;
	struct l_dbus_message_iter iter_network_key;
	struct mesh_node *node;
	const char *path;
	uint8_t uuid[UUID_LEN];
	uint8_t network_key[16];
	uint16_t addr;
	uint32_t n;

	l_debug("Provision");

	if (!l_dbus_message_get_arguments(message, "ayq",
			&iter_network_key, &addr))
		return dbus_error(message, MESH_ERROR_INVALID_ARGS, NULL);

	n = dbus_get_byte_array(&iter_network_key, network_key, 16);
	if (n != 16)
		return dbus_error(message, MESH_ERROR_INVALID_ARGS,
					"Wrong netkey");

	path = l_dbus_message_get_path(message);
	if (!get_uuid_from_path(path, uuid))
		return dbus_error(message, MESH_ERROR_FAILED, "Wrong path");

	node = l_queue_find(nodes, match_node_uuid, uuid);
	if (!node)
		return dbus_error(message, MESH_ERROR_DOES_NOT_EXIST, NULL);

	if (!provision_node(node, network_key, addr))
		return dbus_error(message, MESH_ERROR_FAILED, NULL);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static struct l_dbus_message *unprovision_call(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *reply;
	struct mesh_node *node;
	const char *path;
	uint8_t uuid[UUID_LEN];

	l_debug("Unprovision");

	path = l_dbus_message_get_path(message);
	if (!get_uuid_from_path(path, uuid))
		return dbus_error(message, MESH_ERROR_FAILED, "Wrong path");

	node = l_queue_find(nodes, match_node_uuid, uuid);
	if (!node)
		return dbus_error(message, MESH_ERROR_DOES_NOT_EXIST, NULL);

	if (!unprovision_node(node))
		return dbus_error(message, MESH_ERROR_FAILED, NULL);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static struct l_dbus_message *start_advertising_call(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *reply;
	struct mesh_node *node;
	const char *path;
	uint8_t uuid[UUID_LEN];

	l_debug("Start advertising as unprovisioned node");

	path = l_dbus_message_get_path(message);
	if (!get_uuid_from_path(path, uuid))
		return dbus_error(message, MESH_ERROR_FAILED, "Wrong path");

	node = l_queue_find(nodes, match_node_uuid, uuid);
	if (!node)
		return dbus_error(message, MESH_ERROR_DOES_NOT_EXIST, NULL);

	if (!start_advertising(node))
		return dbus_error(message, MESH_ERROR_FAILED, NULL);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static struct l_dbus_message *stop_advertising_call(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *reply;
	struct mesh_node *node;
	const char *path;
	uint8_t uuid[UUID_LEN];

	l_debug("Stop advertising as unprovisioned node");

	path = l_dbus_message_get_path(message);
	if (!get_uuid_from_path(path, uuid))
		return dbus_error(message, MESH_ERROR_FAILED, "Wrong path");

	node = l_queue_find(nodes, match_node_uuid, uuid);
	if (!node)
		return dbus_error(message, MESH_ERROR_DOES_NOT_EXIST, NULL);

	if (!stop_advertising(node))
		return dbus_error(message, MESH_ERROR_FAILED, NULL);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static bool is_provisioned_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct mesh_node *node;
	const char *path;
	uint8_t uuid[UUID_LEN];
	bool is_provisioned = false;

	path = l_dbus_message_get_path(message);
	if (!get_uuid_from_path(path, uuid)) {
		is_provisioned = false;
		goto done;
	}

	node = l_queue_find(nodes, match_node_uuid, uuid);
	if (node) {
		if (node->net)
			is_provisioned = true;
		goto done;
	}

done:
	l_dbus_message_builder_append_basic(builder, 'b', &is_provisioned);

	return true;
}

static bool is_advertising_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct mesh_node *node;
	const char *path;
	uint8_t uuid[UUID_LEN];
	bool is_advertising = false;

	path = l_dbus_message_get_path(message);
	if (!get_uuid_from_path(path, uuid)) {
		is_advertising = false;
		goto done;
	}

	node = l_queue_find(nodes, match_node_uuid, uuid);
	if (node) {
		is_advertising = node->is_advertising;
		goto done;
	}

done:
	l_dbus_message_builder_append_basic(builder, 'b', &is_advertising);

	return true;
}

static void setup_provisioning_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Provision", 0,
				provision_call, "", "ayq", "net_key", "addr");

	l_dbus_interface_method(interface, "Unprovision", 0,
				unprovision_call, "", "");

	l_dbus_interface_method(interface, "StartAdvertising", 0,
				start_advertising_call, "", "");

	l_dbus_interface_method(interface, "StopAdvertising", 0,
				stop_advertising_call, "", "");

	l_dbus_interface_property(interface, "Provisioned", 0, "b",
				is_provisioned_getter, NULL);

	l_dbus_interface_property(interface, "Advertising", 0, "b",
				is_advertising_getter, NULL);
}

static struct l_dbus_message *send_message_call(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *reply;
	struct l_dbus_message_iter iter_opcode, iter_payload;
	struct mesh_node *node;
	const char *path;
	uint8_t uuid[UUID_LEN];
	uint8_t opcode[OPCODE_MAX_LEN];
	uint8_t *payload;
	uint16_t element, dest, key_index, len;

	l_info("Send message call");

	path = l_dbus_message_get_path(message);
	if (!get_uuid_from_path(path, uuid))
		return dbus_error(message, MESH_ERROR_FAILED, "Wrong path");

	if (!l_dbus_message_get_arguments(message, "qqayayq", &element, &dest,
			&iter_opcode, &iter_payload, &key_index)) {
		return dbus_error(message, MESH_ERROR_INVALID_ARGS, NULL);
	}

	payload = l_new(uint8_t, PAYLOAD_MAX_LEN);

	dbus_get_byte_array(&iter_opcode, opcode, OPCODE_MAX_LEN);
	len = dbus_get_byte_array(&iter_payload, payload, PAYLOAD_MAX_LEN);

	node = l_queue_find(nodes, match_node_uuid, uuid);
	if (!node)
		return dbus_error(message, MESH_ERROR_DOES_NOT_EXIST, NULL);

	if (!send_message(node, element, dest, opcode, payload, len, key_index))
		return dbus_error(message, MESH_ERROR_FAILED, NULL);

	l_free(payload);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static bool node_address_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct mesh_node *node;
	const char *path;
	uint8_t uuid[UUID_LEN];
	uint16_t addr = 0;

	path = l_dbus_message_get_path(message);
	if (!get_uuid_from_path(path, uuid))
		goto done;

	node = l_queue_find(nodes, match_node_uuid, uuid);
	if (node) {
		addr = node_get_primary(node);
		goto done;
	}

done:
	l_dbus_message_builder_append_basic(builder, 'q', &addr);

	return true;
}

static bool node_network_key_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	const uint8_t network_key[16] = {0};

	//TODO - create api to get network key from node
	dbus_append_byte_array(builder, network_key, 16);

	return true;
}

static bool node_device_key_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct mesh_node *node;
	const char *path;
	uint8_t uuid[UUID_LEN];
	const uint8_t *device_key;

	path = l_dbus_message_get_path(message);
	if (!get_uuid_from_path(path, uuid))
		return false;

	node = l_queue_find(nodes, match_node_uuid, uuid);
	if (node)
		device_key = node_get_device_key(node);

	dbus_append_byte_array(builder, device_key, 16);

	return true;
}

static bool node_application_keys_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	const uint8_t app_keys[2][16] = {
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1}
	};
	int i;

	//TODO - create api to get application keys from node

	if (!l_dbus_message_builder_enter_array(builder, "ay"))
		return false;

	for (i = 0; i < 2; i++)
		if (!dbus_append_byte_array(builder, app_keys[i], 16))
			return false;

	if (!l_dbus_message_builder_leave_array(builder))
		return false;

	return true;
}

static bool node_elements_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	const struct l_queue_entry *element_obj;
	const struct l_queue_entry *model_obj;
	struct mesh_node *node;
	struct node_element *element;
	struct mesh_model *model;
	const char *path;
	uint8_t uuid[UUID_LEN];
	uint16_t model_id;

	path = l_dbus_message_get_path(message);
	if (!get_uuid_from_path(path, uuid))
		return false;

	node = l_queue_find(nodes, match_node_uuid, uuid);
	if (!node)
		return false;

	if (!l_dbus_message_builder_enter_array(builder, "{yaq}"))
		return false;

	for (element_obj = l_queue_get_entries(node->elements); element_obj;
			element_obj = element_obj->next) {
		element = element_obj->data;

		if (!l_dbus_message_builder_enter_dict(builder, "yaq"))
			return false;

		if (!l_dbus_message_builder_append_basic(builder, 'y',
				&(element->location)))
			return false;

		if (!l_dbus_message_builder_enter_array(builder, "q"))
			return false;

		for (model_obj = l_queue_get_entries(element->models);
				model_obj; model_obj = model_obj->next) {
			model = model_obj->data;

			model_id = (uint16_t) mesh_model_get_model_id(model);
			if (!l_dbus_message_builder_append_basic(builder, 'q',
					&model_id))
				return false;
		}

		if (!l_dbus_message_builder_leave_array(builder))
			return false;

		if (!l_dbus_message_builder_leave_dict(builder))
			return false;
	}

	if (!l_dbus_message_builder_leave_array(builder))
		return false;

	return true;
}

static void setup_node_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "SendMessage", 0,
				send_message_call, "", "qqayayq", "element",
				"dest", "opcode", "payload", "key_index");

	l_dbus_interface_signal(interface, "MessageReceived", 0,
				"qqayayq", "element", "source", "opcode",
				"payload", "key_index");

	l_dbus_interface_property(interface, "Address", 0, "q",
				node_address_getter, NULL);

	l_dbus_interface_property(interface, "NetworkKey", 0, "ay",
				node_network_key_getter, NULL);

	l_dbus_interface_property(interface, "DeviceKey", 0, "ay",
				node_device_key_getter, NULL);

	l_dbus_interface_property(interface, "ApplicationKeys", 0, "aay",
				node_application_keys_getter, NULL);

	l_dbus_interface_property(interface, "Elements", 0, "a{yaq}",
				node_elements_getter, NULL);
}

bool node_dbus_init(struct l_dbus *bus)
{
	if (!l_dbus_register_interface(bus, MESH_PROVISIONING_INTERFACE,
			setup_provisioning_interface, NULL, false)) {
		l_info("Unable to register %s interface",
			MESH_PROVISIONING_INTERFACE);
		return false;
	}

	if (!l_dbus_register_interface(bus, MESH_NODE_INTERFACE,
			setup_node_interface, NULL, false)) {
		l_info("Unable to register %s interface",
			MESH_NODE_INTERFACE);
		return false;
	}

	return true;
}

const char *node_get_owner(struct mesh_node *node)
{
	return node->owner;
}

bool node_add_pending_local(struct mesh_node *node, void *prov_node_info,
							struct mesh_io *io)
{
	struct mesh_prov_node_info *info = prov_node_info;
	bool kr = !!(info->flags & PROV_FLAG_KR);
	bool ivu = !!(info->flags & PROV_FLAG_IVU);

	node->net = mesh_net_new(node);

	if (!nodes)
		nodes = l_queue_new();

	l_queue_push_tail(nodes, node);

	if (!storage_set_iv_index(node->net, info->iv_index, ivu))
		return false;

	mesh_net_set_iv_index(node->net, info->iv_index, ivu);

	if (!mesh_db_write_uint16_hex(node->jconfig, "unicastAddress",
								info->unicast))
		return false;

	node->primary = info->unicast;
	mesh_net_register_unicast(node->net, info->unicast, node->num_ele);

	memcpy(node->dev_key, info->device_key, 16);
	if (!mesh_db_write_device_key(node->jconfig, info->device_key))
		return false;

	if (mesh_net_add_key(node->net, kr, info->net_index,
			info->net_key) != MESH_STATUS_SUCCESS)
		return false;

	if (!storage_net_key_add(node->net, info->net_index, info->net_key,
			kr ? KEY_REFRESH_PHASE_TWO : KEY_REFRESH_PHASE_NONE))
		return false;

	if (!storage_save_config(node, true, NULL, NULL))
		return false;

	/* Initialize configuration server model */
	mesh_config_srv_init(node, PRIMARY_ELE_IDX);

	mesh_net_attach(node->net, io);

	return true;
}

void node_jconfig_set(struct mesh_node *node, void *jconfig)
{
	node->jconfig = jconfig;
}

void *node_jconfig_get(struct mesh_node *node)
{
	return  node->jconfig;
}

void node_cfg_file_set(struct mesh_node *node, char *cfg)
{
	node->cfg_file = cfg;
}

char *node_cfg_file_get(struct mesh_node *node)
{
	return node->cfg_file;
}

struct mesh_net *node_get_net(struct mesh_node *node)
{
	return node->net;
}
