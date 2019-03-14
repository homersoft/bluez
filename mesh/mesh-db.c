/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <ell/ell.h>

#include "mesh/mesh-defs.h"
#include "mesh/util.h"

#include "mesh/mesh-db.h"
#include "mesh/storage.h"

#define CHECK_KEY_IDX_RANGE(x) (((x) >= 0) && ((x) <= 4095))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static bool get_int(json_object *jobj, const char *keyword, int *value)
{
	json_object *jvalue;

	if (!json_object_object_get_ex(jobj, keyword, &jvalue))
		return false;

	*value = json_object_get_int(jvalue);
	if (errno == EINVAL)
		return false;

	return true;
}

static bool add_key(json_object *jobject, const char *desc,
					const uint8_t key[16])
{
	json_object *jstring;
	char hexstr[33];

	hex2str((uint8_t *) key, 16, hexstr, 33);
	jstring = json_object_new_string(hexstr);
	if (!jstring)
		return false;

	json_object_object_add(jobject, desc, jstring);
	return true;
}

static bool add_uuid(json_object *jobject, const char *desc, uint8_t *uuid)
{
	json_object *jstring;
	char uuid_str[UUID_LEN + 1];

	/* Convert UUID to string */
	l_uuid_to_string(uuid, &uuid_str[0], sizeof(uuid_str));

	jstring = json_object_new_string(uuid_str);
	if (!jstring)
		return false;

	json_object_object_add(jobject, desc, jstring);
	return true;
}

static json_object *get_element_model(json_object *jnode, int ele_idx,
						uint32_t mod_id, bool vendor)
{
	json_object *jelements, *jelement, *jmodels;
	int i, num_mods;
	size_t len;
	char buf[9];

	if (!vendor)
		snprintf(buf, 5, "%4.4x", (uint16_t)mod_id);
	else
		snprintf(buf, 9, "%8.8x", mod_id);

	json_object_object_get_ex(jnode, "elements", &jelements);
	if (!jelements)
		return NULL;

	jelement = json_object_array_get_idx(jelements, ele_idx);
	if (!jelement)
		return NULL;

	json_object_object_get_ex(jelement, "models", &jmodels);
	if (!jmodels)
		return NULL;

	num_mods = json_object_array_length(jmodels);
	if (!num_mods)
		return NULL;

	if (!vendor) {
		snprintf(buf, 5, "%4.4x", mod_id);
		len = 4;
	} else {
		snprintf(buf, 9, "%8.8x", mod_id);
		len = 8;
	}

	for (i = 0; i < num_mods; ++i) {
		json_object *jmodel, *jvalue;
		char *str;

		jmodel = json_object_array_get_idx(jmodels, i);
		json_object_object_get_ex(jmodel, "modelId", &jvalue);
		if (!jvalue)
			return NULL;

		str = (char *)json_object_get_string(jvalue);
		if (!str)
			return NULL;

		if (!strncmp(str, buf, len))
			return jmodel;
	}

	return NULL;
}

static bool jarray_has_string(json_object *jarray, char *str, size_t len)
{
	int i, sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry;
		char *str_entry;

		jentry = json_object_array_get_idx(jarray, i);
		str_entry = (char *)json_object_get_string(jentry);
		if (!str_entry)
			continue;

		if (!strncmp(str, str_entry, len))
			return true;
	}

	return false;
}

static json_object *jarray_string_del(json_object *jarray, char *str,
								size_t len)
{
	int i, sz = json_object_array_length(jarray);
	json_object *jarray_new;

	jarray_new = json_object_new_array();
	if (!jarray_new)
		return NULL;

	for (i = 0; i < sz; ++i) {
		json_object *jentry;
		char *str_entry;

		jentry = json_object_array_get_idx(jarray, i);
		str_entry = (char *)json_object_get_string(jentry);
		if (str_entry && !strncmp(str, str_entry, len))
			continue;

		json_object_get(jentry);
		json_object_array_add(jarray_new, jentry);
	}

	return jarray_new;
}

static json_object *get_key_object(json_object *jarray, uint16_t idx)
{
	int i, sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry, *jvalue;
		uint32_t jidx;

		jentry = json_object_array_get_idx(jarray, i);
		if (!json_object_object_get_ex(jentry, "index", &jvalue))
			return NULL;

		jidx = json_object_get_int(jvalue);

		if (jidx == idx)
			return jentry;
	}

	return NULL;
}

static json_object *jarray_key_del(json_object *jarray, int16_t idx)
{
	json_object *jarray_new;
	int i, sz = json_object_array_length(jarray);

	jarray_new = json_object_new_array();
	if (!jarray_new)
		return NULL;

	for (i = 0; i < sz; ++i) {
		json_object *jentry, *jvalue;

		jentry = json_object_array_get_idx(jarray, i);

		if (json_object_object_get_ex(jentry, "index", &jvalue)) {
			int tmp = json_object_get_int(jvalue);

			if (tmp == idx)
				continue;
		}

		json_object_get(jentry);
		json_object_array_add(jarray_new, jentry);
	}

	return jarray_new;
}

bool mesh_db_read_iv_index(json_object *jobj, uint32_t *idx, bool *update)
{
	int tmp;

	/* IV index */
	if (!get_int(jobj, "IVindex", &tmp))
		return false;

	*idx = (uint32_t) tmp;

	if (!get_int(jobj, "IVupdate", &tmp))
		return false;

	*update = tmp ? true : false;

	return true;
}

bool mesh_db_read_device_key(json_object *jobj, uint8_t key_buf[KEY_LEN])
{
	json_object *jvalue;
	char *str;

	if (!key_buf)
		return false;

	if (!json_object_object_get_ex(jobj, "deviceKey", &jvalue) ||
								!jvalue)
		return false;

	str = (char *)json_object_get_string(jvalue);
	if (!str2hex(str, strlen(str), key_buf, KEY_LEN))
		return false;

	return true;
}

bool mesh_db_read_uuid(json_object *jobj, uint8_t uuid_buf[KEY_LEN])
{
	json_object *jvalue;
	const char *str;

	if (!uuid_buf)
		return false;

	if (!json_object_object_get_ex(jobj, "UUID", &jvalue) ||
		 !jvalue)
		return false;

	str = json_object_get_string(jvalue);

	if (!l_uuid_parse(str, UUID_LEN, &uuid_buf[0]))
		return false;

	return true;
}

bool mesh_db_read_app_keys(json_object *jobj, mesh_db_app_key_cb cb,
							void *user_data)
{
	json_object *jarray;
	int len;
	int i;

	if (!cb)
		return true;

	json_object_object_get_ex(jobj, "appKeys", &jarray);
	if (!jarray || (json_object_get_type(jarray) != json_type_array))
		return false;

	len = json_object_array_length(jarray);

	for (i = 0; i < len; ++i) {
		json_object *jtemp, *jvalue;
		int app_idx, net_idx;

		bool key_refresh = false;
		char *str;
		uint8_t key[KEY_LEN];
		uint8_t new_key[KEY_LEN];

		jtemp = json_object_array_get_idx(jarray, i);

		/* Get app index */
		json_object_object_get_ex(jtemp, "index", &jvalue);
		if (!jvalue)
			return false;

		app_idx = json_object_get_int(jvalue);
		l_info(">>read_app_idx = %d", app_idx);

		if (!CHECK_KEY_IDX_RANGE(app_idx))
			return false;

		/* Get net index */
		json_object_object_get_ex(jtemp, "boundNetKey", &jvalue);
		if (!jvalue)
			return false;

		net_idx = json_object_get_int(jvalue);
		l_info(">>read_net_idx = %d", net_idx);

		if (!CHECK_KEY_IDX_RANGE(net_idx))
			return false;

		/* Get old key if exists */
		json_object_object_get_ex(jtemp, "oldKey", &jvalue);
		if (jvalue) {
			str = (char *)json_object_get_string(jvalue);
			if (!str2hex(str, strlen(str), key, KEY_LEN))
				return false;
			key_refresh = true;
		}

		json_object_object_get_ex(jtemp, "key", &jvalue);
		if (!jvalue)
			return false;

		str = (char *)json_object_get_string(jvalue);
		if (!str2hex(str, strlen(str),
				key_refresh ? new_key : key, KEY_LEN))
			return false;

		if (!cb((uint16_t)net_idx, (uint16_t) app_idx, key,
				key_refresh ? new_key : NULL, user_data))
			return false;
	}

	return true;
}

bool mesh_db_read_net_keys(json_object *jobj, mesh_db_net_key_cb cb,
								void *user_data)
{
	json_object *jarray;
	int len;
	int i;

	if (!cb)
		return true;

	json_object_object_get_ex(jobj, "netKeys", &jarray);
	if (!jarray || (json_object_get_type(jarray) != json_type_array))
		return false;

	len = json_object_array_length(jarray);

	for (i = 0; i < len; ++i) {
		json_object *jtemp, *jvalue;
		int idx;
		char *str;
		bool key_refresh = false;
		int phase;
		uint8_t key[16];
		uint8_t new_key[16];

		jtemp = json_object_array_get_idx(jarray, i);

		if (!get_int(jtemp, "index", &idx))
			return false;

		if (!CHECK_KEY_IDX_RANGE(idx))
			return false;

		json_object_object_get_ex(jtemp, "oldKey", &jvalue);
		if (jvalue) {
			str = (char *)json_object_get_string(jvalue);
			if (!str2hex(str, strlen(str), key, 16))
				return false;
			key_refresh = true;
		}

		json_object_object_get_ex(jtemp, "key", &jvalue);
		if (!jvalue)
			return false;

		str = (char *)json_object_get_string(jvalue);
		if (!str2hex(str, strlen(str), key_refresh ? new_key : key, 16))
			return false;

		json_object_object_get_ex(jtemp, "keyRefresh", &jvalue);
		if (!jvalue)
			phase = KEY_REFRESH_PHASE_NONE;
		else
			phase = json_object_get_int(jvalue);


		if (!cb((uint16_t)idx, key, key_refresh ? new_key : NULL, phase,
								user_data))
			return false;
	}

	return true;
}

bool mesh_db_net_key_add(json_object *jobj, uint16_t idx,
					const uint8_t key[KEY_LEN], int phase)
{
	json_object *jarray, *jentry = NULL, *jstring, *jvalue = NULL;

	json_object_object_get_ex(jobj, "netKeys", &jarray);

	if (jarray)
		jentry = get_key_object(jarray, idx);

	if (jentry) {
		uint8_t buf[KEY_LEN];
		json_object *jvalue;
		char *str;

		json_object_object_get_ex(jentry, "key", &jvalue);
		if (!jvalue)
			return false;

		str = (char *)json_object_get_string(jvalue);
		if (!str2hex(str, strlen(str), buf, sizeof(buf)))
			return false;

		/* If the same key, return success */
		if (memcmp(key, buf, KEY_LEN) == 0)
			return true;

		return false;
	}

	if (!jentry) {
		jentry = json_object_new_object();
		if (!jentry)
			goto fail;

		/* Add index value */
		jvalue = json_object_new_int(idx);

		json_object_object_add(jentry, "index", jvalue);

		if (!jvalue)
			goto fail;

		/* Add key value */
		if (!add_key(jentry, "key", key))
			goto fail;

		/* If Key Refresh underway, add placeholder for "Old Key" */
		if (phase != KEY_REFRESH_PHASE_NONE) {
			uint8_t buf[KEY_LEN];
			uint8_t i;

			/* Flip Bits to differentiate */
			for (i = 0; i < sizeof(buf); i++)
				buf[i] = key[i] ^ 0xff;

			if (!add_key(jentry, "oldKey", buf))
				goto fail;
		}

		if (!jarray) {
			jarray = json_object_new_array();
			if (!jarray)
				goto fail;
			json_object_object_add(jobj, "netKeys", jarray);
		}

		json_object_array_add(jarray, jentry);

	} else {

		if (!json_object_object_get_ex(jentry, "key", &jstring))
			return false;

		json_object_object_add(jentry, "oldKey", jstring);
		json_object_object_del(jentry, "key");

		if (!add_key(jentry, "key", key))
			return false;
	}

	/* Add keyRefresh value */
	jvalue = json_object_new_int(phase);

	json_object_object_add(jentry, "keyRefresh", jvalue);

	if (!jvalue)
		goto fail;

	return true;
fail:

	if (jentry)
		json_object_put(jentry);

	return false;
}

bool mesh_db_net_key_del(json_object *jobj, uint16_t idx)
{
	json_object *jarray, *jarray_new;

	json_object_object_get_ex(jobj, "netKeys", &jarray);
	if (!jarray)
		return true;

	/* Check if matching entry exists */
	if (!get_key_object(jarray, idx))
		return true;

	if (json_object_array_length(jarray) == 1) {
		json_object_object_del(jobj, "netKeys");
		return true;
	}

	/*
	 * There is no easy way to delete a value from json array.
	 * Create a new copy without specified element and
	 * then remove old array.
	 */
	jarray_new = jarray_key_del(jarray, idx);
	if (!jarray_new)
		return false;

	json_object_object_del(jobj, "netKeys");
	json_object_object_add(jobj, "netKeys", jarray_new);

	return true;
}

bool mesh_db_write_device_key(json_object *jnode, uint8_t *key)
{
	return add_key(jnode, "deviceKey", key);
}

bool mesh_db_app_key_add(json_object *jobj, uint16_t net_idx, uint16_t app_idx,
			 const uint8_t key[KEY_LEN], bool update)
{
	json_object *jarray, *jentry = NULL, *jstring = NULL, *jvalue = NULL;

	json_object_object_get_ex(jobj, "appKeys", &jarray);
	if (!jarray && update)
		return false;

	if (jarray)
		jentry = get_key_object(jarray, app_idx);

	/* The key entry should exist if the key is updated */
	if (!jentry  && update)
		return false;

	if (jentry) {
		uint8_t buf[KEY_LEN];
		json_object *jvalue;
		char *str;

		json_object_object_get_ex(jentry, "key", &jvalue);
		if (!jvalue)
			return false;

		str = (char *)json_object_get_string(jvalue);
		if (!str2hex(str, strlen(str), buf, sizeof(buf)))
			return false;

		/* If the same key, return success */
		if (memcmp(key, buf, KEY_LEN) == 0)
			return true;

		return false;
	}

	if (!update) {
		jentry = json_object_new_object();
		if (!jentry)
			goto fail;

		/* Add app index value */
		jvalue = json_object_new_int(app_idx);

		json_object_object_add(jentry, "index", jvalue);

		if (!jvalue)
			goto fail;

		/* Add net index value */
		jvalue = json_object_new_int(net_idx);
		json_object_object_add(jentry, "boundNetKey", jvalue);

		if (!jvalue)
			goto fail;

		if (!add_key(jentry, "key", key))
			goto fail;

		if (!jarray) {
			jarray = json_object_new_array();
			if (!jarray)
				goto fail;
			json_object_object_add(jobj, "appKeys", jarray);
		}

		json_object_array_add(jarray, jentry);

	} else {

		if (!json_object_object_get_ex(jentry, "key", &jstring))
			return false;

		json_object_object_add(jentry, "oldKey", jstring);
		json_object_object_del(jentry, "key");

		if (!add_key(jentry, "key", key))
			return false;
	}

	return true;
fail:

	if (jentry)
		json_object_put(jentry);

	return false;
}

bool mesh_db_app_key_del(json_object *jobj, uint16_t net_idx, uint16_t idx)
{
	json_object *jarray, *jarray_new;

	json_object_object_get_ex(jobj, "appKeys", &jarray);
	if (!jarray)
		return true;

	/* Check if matching entry exists */
	if (!get_key_object(jarray, idx))
		return true;

	if (json_object_array_length(jarray) == 1) {
		json_object_object_del(jobj, "appKeys");
		return true;
	}

	/*
	 * There is no easy way to delete a value from json array.
	 * Create a new copy without specified element and
	 * then remove old array.
	 */
	jarray_new = jarray_key_del(jarray, idx);
	if (!jarray_new)
		return false;

	json_object_object_del(jobj, "appKeys");
	json_object_object_add(jobj, "appKeys", jarray_new);

	return true;
}

bool mesh_db_model_binding_add(json_object *jnode, uint8_t ele_idx, bool vendor,
				uint32_t mod_id, uint16_t app_idx)
{
	json_object *jmodel, *jstring, *jarray;
	char buf[5];

	jmodel = get_element_model(jnode, ele_idx, mod_id, vendor);
	if (!jmodel)
		return false;

	json_object_object_get_ex(jmodel, "bind", &jarray);

	snprintf(buf, 5, "%4.4x", app_idx);

	if (jarray && jarray_has_string(jarray, buf, 4))
		return true;

	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	if (!jarray) {
		jarray = json_object_new_array();
		if (!jarray) {
			json_object_put(jstring);
			return false;
		}
		json_object_object_add(jmodel, "bind", jarray);
	}

	json_object_array_add(jarray, jstring);

	return true;
}

bool mesh_db_model_binding_del(json_object *jnode, uint8_t ele_idx, bool vendor,
				uint32_t mod_id, uint16_t app_idx)
{
	json_object *jmodel, *jarray, *jarray_new;
	char buf[5];

	jmodel = get_element_model(jnode, ele_idx, mod_id, vendor);
	if (!jmodel)
		return false;

	json_object_object_get_ex(jmodel, "bind", &jarray);

	snprintf(buf, 5, "%4.4x", app_idx);

	if (!jarray || !jarray_has_string(jarray, buf, 4))
		return true;

	if (json_object_array_length(jarray) == 1) {
		json_object_object_del(jmodel, "bind");
		return true;
	}

	/*
	 * There is no easy way to delete a value from json array.
	 * Create a new copy without specified element and
	 * then remove old array.
	 */
	jarray_new = jarray_string_del(jarray, buf, 4);
	if (!jarray_new)
		return false;

	json_object_object_del(jmodel, "bind");
	json_object_object_add(jmodel, "bind", jarray_new);

	return true;
}

static void free_model(void *data)
{
	struct mesh_db_model *mod = data;

	l_free(mod->bindings);
	l_free(mod->subs);
	l_free(mod->pub);
	l_free(mod);
}

static void free_element(void *data)
{
	struct mesh_db_element *ele = data;

	l_queue_destroy(ele->models, free_model);
	l_free(ele);
}

static bool parse_bindings(json_object *jbindings, struct mesh_db_model *mod)
{
	int cnt;
	int i;

	cnt = json_object_array_length(jbindings);
	if (cnt > 0xffff)
		return false;

	mod->num_bindings = cnt;

	/* Allow empty bindings list */
	if (!cnt)
		return true;

	mod->bindings = l_new(uint16_t, cnt);
	if (!mod->bindings)
		return false;

	for (i = 0; i < cnt; ++i) {
		int idx;
		json_object *jvalue;

		jvalue = json_object_array_get_idx(jbindings, i);
		if (!jvalue)
			return false;

		idx = json_object_get_int(jvalue);
		if (!CHECK_KEY_IDX_RANGE(idx))
			return false;

		mod->bindings[i] = (uint16_t) idx;
	}

	return true;
}

static bool get_key_index(json_object *jobj, const char *keyword,
								uint16_t *index)
{
	int idx;

	if (!get_int(jobj, keyword, &idx))
		return false;

	if (!CHECK_KEY_IDX_RANGE(idx))
		return false;

	*index = (uint16_t) idx;
	return true;
}

static struct mesh_db_pub *parse_model_publication(json_object *jpub)
{
	json_object *jvalue;
	struct mesh_db_pub *pub;
	int len, value;
	char *str;

	pub = l_new(struct mesh_db_pub, 1);
	if (!pub)
		return NULL;

	json_object_object_get_ex(jpub, "address", &jvalue);
	str = (char *)json_object_get_string(jvalue);
	len = strlen(str);

	switch (len) {
	case 4:
		if (sscanf(str, "%04hx", &pub->addr) != 1)
			goto fail;
		break;
	case 32:
		if (!str2hex(str, len, pub->virt_addr, 16))
			goto fail;
		pub->virt = true;
		break;
	default:
		goto fail;
	}

	if (!get_key_index(jpub, "index", &pub->idx))
		goto fail;

	if (!get_int(jpub, "ttl", &value))
		goto fail;
	pub->ttl = (uint8_t) value;

	if (!get_int(jpub, "period", &value))
		goto fail;
	pub->period = (uint8_t) value;

	if (!get_int(jpub, "credentials", &value))
		goto fail;
	pub->credential = (uint8_t) value;

	if (!get_int(jpub, "retransmit", &value))
		goto fail;

	pub->retransmit = (uint8_t) value;
	return pub;

fail:
	l_free(pub);
	return NULL;
}

static bool parse_model_subscriptions(json_object *jsubs,
						struct mesh_db_model *mod)
{
	struct mesh_db_sub *subs;
	int i, cnt;

	if (json_object_get_type(jsubs) != json_type_array)
		return NULL;

	cnt = json_object_array_length(jsubs);
	/* Allow empty array */
	if (!cnt)
		return true;

	subs = l_new(struct mesh_db_sub, cnt);
	if (!subs)
		return false;

	for (i = 0; i < cnt; ++i) {
		char *str;
		int len;
		json_object *jvalue;

		jvalue = json_object_array_get_idx(jsubs, i);
		if (!jvalue)
			return false;

		str = (char *)json_object_get_string(jvalue);
		len = strlen(str);

		switch (len) {
		case 4:
			if (sscanf(str, "%04hx", &subs[i].src.addr) != 1)
				goto fail;
		break;
		case 32:
			if (!str2hex(str, len, subs[i].src.virt_addr, 16))
				goto fail;
			subs[i].virt = true;
			break;
		default:
			goto fail;
		}
	}

	mod->num_subs = cnt;
	mod->subs = subs;

	return true;
fail:
	l_free(subs);
	return false;
}

static bool parse_models(json_object *jmodels, struct mesh_db_element *ele)
{
	int num_models = json_object_array_length(jmodels);

	if (!num_models)
		return true;

	for (int i = 0; i < num_models; ++i) {
		json_object *jarray, *jvalue;
		struct mesh_db_model *mod;
		uint32_t id;
		int len;
		const char *str;

		json_object *jmodel = json_object_array_get_idx(jmodels, i);

		if (!jmodel)
			goto fail;

		mod = l_new(struct mesh_db_model, 1);
		if (!ele)
			goto fail;

		str = (char *)json_object_get_string(jmodel);

		len = strlen(str);

		if (len != 4 && len != 8)
			goto fail;

		if (len == 4) {
			if (sscanf(str, "%04x", &id) != 1)
				goto fail;

			id |= VENDOR_ID_MASK;
		} else if (len == 8) {
			if (sscanf(str, "%08x", &id) != 1)
				goto fail;
		} else
			goto fail;

		mod->id = id;

		if (len == 8)
			mod->vendor = true;

		json_object_object_get_ex(jmodel, "bind", &jarray);

		if (jarray && (json_object_get_type(jarray) != json_type_array
					|| !parse_bindings(jarray, mod)))
			goto fail;

		json_object_object_get_ex(jmodel, "publish", &jvalue);
		if (jvalue) {
			mod->pub = parse_model_publication(jvalue);
			if (!mod->pub)
				goto fail;
		}

		json_object_object_get_ex(jmodel, "subscribe", &jarray);

		if (jarray && !parse_model_subscriptions(jarray, mod))
			goto fail;

		l_queue_push_tail(ele->models, mod);
	}

	return true;

fail:
	l_queue_destroy(ele->models, free_model);
	return false;
}

static bool parse_elements(json_object *jelements, struct mesh_db_node *node)
{
	node->elements = l_queue_new();
	if (!node->elements)
		return false;

	for (uint16_t ele_nr = 0;; ele_nr++) {
		json_object *jelement;
		json_object *jlocation;
		json_object *jmodels;
		struct mesh_db_element *ele;
		int elementIndex;
		const char *str;
		/* Convert integer to string */
		char int_as_str[6];

		sprintf(int_as_str, "%u", ele_nr);

		if (!json_object_object_get_ex(jelements, int_as_str,
			 &jelement)) {
			/* End of elements */
			return true;
		}

		if (!get_int(jelement, "elementIndex", &elementIndex))
			goto fail;

		ele = l_new(struct mesh_db_element, 1);

		if (!ele)
			goto fail;

		/* Store elIdx in the structure */
		ele->index = elementIndex;

		ele->models = l_queue_new();
		if (!ele->models)
			goto fail;

		if (!json_object_object_get_ex(jelement, "location",
			 &jlocation))
			goto fail;

		str = json_object_get_string(jlocation);

		/* Store location in the structure */
		if (sscanf(str, "%04hx", &(ele->location)) != 1)
			goto fail;

		if (!json_object_object_get_ex(jelement, "models", &jmodels))
			goto fail;

		if (jmodels &&
			 (json_object_get_type(jmodels) != json_type_array))
			goto fail;

		if (!parse_models(jmodels, ele))
			goto fail;

		l_queue_push_tail(node->elements, ele);
	}

fail:
	l_queue_destroy(node->elements, free_element);
	node->elements = NULL;

	return false;
}

static int get_mode(json_object *jvalue)
{
	const char *str;

	str = json_object_get_string(jvalue);
	if (!str)
		return 0xffffffff;

	if (!strncasecmp(str, "false", strlen("false")))
		return MESH_MODE_DISABLED;

	if (!strncasecmp(str, "true", strlen("true")))
		return MESH_MODE_ENABLED;

	if (!strncasecmp(str, "unsupported", strlen("unsupported")))
		return MESH_MODE_UNSUPPORTED;

	return 0xffffffff;
}

static void parse_features(json_object *jconfig, struct mesh_db_node *node)
{
	json_object *jvalue, *jrelay;
	int mode;

	json_object_object_get_ex(jconfig, "proxy", &jvalue);
	if (jvalue) {
		mode = get_mode(jvalue);
		if (mode <= MESH_MODE_UNSUPPORTED)
			node->modes.proxy = mode;
	}

	json_object_object_get_ex(jconfig, "friend", &jvalue);
	if (jvalue) {
		mode = get_mode(jvalue);
		if (mode <= MESH_MODE_UNSUPPORTED)
			node->modes.friend = mode;
	}

	json_object_object_get_ex(jconfig, "lowPower", &jvalue);
	if (jvalue) {
		mode = get_mode(jvalue);
		if (mode <= MESH_MODE_UNSUPPORTED)
			node->modes.low_power = mode;
	}

	json_object_object_get_ex(jconfig, "beacon", &jvalue);
	if (jvalue) {
		mode = get_mode(jvalue);
		if (mode <= MESH_MODE_ENABLED)
			node->modes.beacon = mode;
	}

	json_object_object_get_ex(jconfig, "provisioned", &jvalue);
	if (jvalue) {
		mode = get_mode(jvalue);
		if (mode <= MESH_MODE_UNSUPPORTED)
			node->provisioned = mode;
	}

	json_object_object_get_ex(jconfig, "relay", &jrelay);
	if (!jrelay)
		return;

	json_object_object_get_ex(jrelay, "mode", &jvalue);
	if (jvalue) {
		uint8_t mode = get_mode(jvalue);

		if (mode <= MESH_MODE_UNSUPPORTED)
			node->modes.relay.mode = mode;
		else
			return;
	} else
		return;

	json_object_object_get_ex(jrelay, "count", &jvalue);
	if (!jvalue)
		return;

	node->modes.relay.cnt = MIN(json_object_get_int(jvalue),
			RELAY_RETRAN_COUNT_MAX);

	json_object_object_get_ex(jrelay, "interval", &jvalue);
	if (!jvalue)
		return;

	node->modes.relay.interval = MIN(json_object_get_int(jvalue),
			RELAY_RETR_INTERVAL_STEPS_MAX);
}

static bool parse_iv_idx(json_object *jcomp, struct mesh_db_node *node)
{
	uint32_t iv_index;
	bool iv_update;

	if (mesh_db_read_iv_index(jcomp, &iv_index, &iv_update)) {
		node->iv_index = iv_index;
		node->iv_update = iv_update;
	} else {
		return false;
	}

	return true;
}

static bool parse_uuid(json_object *jcomp, struct mesh_db_node *node)
{
	uint8_t uuid_buf[KEY_LEN];

	if (mesh_db_read_uuid(jcomp, uuid_buf))
		memcpy(node->uuid, uuid_buf, KEY_LEN);
	else
		return false;

	return true;
}

static bool parse_keys(json_object *jcomp, struct mesh_db_node *node)
{
	uint8_t key_buf[KEY_LEN];

	/* Get Device Key */
	if (mesh_db_read_device_key(jcomp, key_buf))
		memcpy(node->dev_key, key_buf, KEY_LEN);
	else
		return false;

	return true;
}

static bool parse_composition(json_object *jcomp, struct mesh_db_node *node)
{
	json_object *jvalue;
	char *str;

	/* All the fields in node composition are mandatory */
	json_object_object_get_ex(jcomp, "cid", &jvalue);
	if (!jvalue)
		return false;

	str = (char *)json_object_get_string(jvalue);
	if (sscanf(str, "%04hx", &node->cid) != 1)
		return false;

	json_object_object_get_ex(jcomp, "pid", &jvalue);
	if (!jvalue)
		return false;

	str = (char *)json_object_get_string(jvalue);
	if (sscanf(str, "%04hx", &node->pid) != 1)
		return false;

	json_object_object_get_ex(jcomp, "vid", &jvalue);
	if (!jvalue)
		return false;

	str = (char *)json_object_get_string(jvalue);
	if (sscanf(str, "%04hx", &node->vid) != 1)
		return false;

	return true;
}

bool mesh_db_read_node(json_object *jnode, mesh_db_node_cb cb, void *user_data)
{
	struct mesh_db_node node;
	json_object *jvalue;

	if (!cb) {
		l_info("Node read callback is required");
		return false;
	}

	memset(&node, 0, sizeof(node));

	/* Parse IV idx and IV update flag */
	if (!parse_iv_idx(jnode, &node))
		l_info("Failed to parse IV index and IV update");

	/* Parse UUID */
	if (!parse_uuid(jnode, &node)) {
		l_info("Failed to parse uuid");
		return false;
	}

	/* Parse keys */
	if (!parse_keys(jnode, &node)) {
		l_info("Failed to parse device key");
		return false;
	}

	/* Parse Composition Data */
	if (!parse_composition(jnode, &node)) {
		l_info("Failed to parse local node composition");
		return false;
	}

	/* Parse features */
	parse_features(jnode, &node);

	/* Parse unicast */
	json_object_object_get_ex(jnode, "unicastAddress", &jvalue);

	if (jvalue) {
		char *str = (char *)json_object_get_string(jvalue);

		if (sscanf(str, "%04hx", &node.unicast) != 1)
			l_error("Failed to parse unicast address");
	} else
		l_info("Unicast address not available - node is not provisioned");

	/* Parse TTL */
	json_object_object_get_ex(jnode, "defaultTTL", &jvalue);

	if (jvalue) {
		int ttl = json_object_get_int(jvalue);

		if (ttl < 0 || ttl == 1 || ttl > DEFAULT_TTL) {
			l_info("Wrong TTL parameter during parsing data");
			return false;
		}
		node.ttl = (uint8_t) ttl;
	} else {
		l_info("Failed to parse TTL");
	}

	/* Parse sequence number */
	json_object_object_get_ex(jnode, "sequenceNumber", &jvalue);

	if (jvalue)
		node.seq_number = json_object_get_int(jvalue);
	else
		l_info("Failed to parse sequence number");

	/* Parse advertising */
	json_object_object_get_ex(jnode, "advertising", &jvalue);

	if (jvalue)
		node.is_advertising = json_object_get_boolean(jvalue);
	else
		l_info("Failed to parse advertising state");

	/* Parse elements */
	json_object_object_get_ex(jnode, "elements", &jvalue);

	if (jvalue && json_object_get_type(jvalue) == json_type_object) {

		if (!parse_elements(jvalue, &node)) {
			l_info("Failed to parse elements");
			return false;
		}
	} else {
		l_info("Failed to parse elements: wrong JSON object type");
	}

	return cb(&node, user_data);
}

bool mesh_db_write_model_id(json_object *jobj, struct mesh_db_model *mod)
{
	char buf[9];
	json_object *jstring;

	if (!mod->vendor)
		snprintf(buf, 5, "%4.4x", (uint16_t)mod->id);
	else
		snprintf(buf, 9, "%8.8x", mod->id);

	jstring = json_object_new_string(buf);

	if (!jstring)
		return false;

	json_object_array_add(jobj, jstring);
	return true;
}

bool mesh_db_write_uint16_hex(json_object *jobj, const char *desc,
								uint16_t value)
{
	json_object *jstring;
	char buf[5];

	snprintf(buf, 5, "%4.4x", value);
	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	json_object_object_add(jobj, desc, jstring);
	return true;
}

bool mesh_db_write_uint32_hex(json_object *jobj, const char *desc,
								uint32_t value)
{
	json_object *jstring;
	char buf[9];

	snprintf(buf, 9, "%8.8x", value);
	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	json_object_object_add(jobj, desc, jstring);
	return true;
}

bool mesh_db_write_int(json_object *jobj, const char *keyword, int value)
{
	json_object *jvalue;

	json_object_object_del(jobj, keyword);

	jvalue = json_object_new_int(value);
	if (!jvalue)
		return false;

	json_object_object_add(jobj, keyword, jvalue);
	return true;
}

bool mesh_db_write_bool(json_object *jobj, const char *keyword, bool value)
{
	json_object *jvalue;

	json_object_object_del(jobj, keyword);

	jvalue = json_object_new_boolean(value);
	if (!jvalue)
		return false;

	json_object_object_add(jobj, keyword, jvalue);
	return true;
}

bool mesh_db_write_mode(json_object *jobj, const char *keyword, int value)
{
	json_object *jstring;

	if (value != MESH_MODE_ENABLED)
		jstring = json_object_new_boolean(false);
	else
		jstring = json_object_new_boolean(true);

	if (!jstring)
		return false;

	json_object_object_add(jobj, keyword, jstring);

	return true;
}

bool mesh_db_write_relay_mode(json_object *jnode, uint8_t mode, uint8_t count,
							uint16_t interval)
{
	json_object *jrelay;

	json_object_object_del(jnode, "relay");

	jrelay = json_object_new_object();
	if (!jrelay)
		return false;

	if (!mesh_db_write_mode(jrelay, "mode", mode))
		goto fail;

	if (!mesh_db_write_int(jrelay, "count", count))
		goto fail;

	if (!mesh_db_write_int(jrelay, "interval", interval))
		goto fail;

	json_object_object_add(jnode, "relay", jrelay);

	return true;
fail:
	json_object_put(jrelay);
	return false;
}

bool mesh_db_read_net_transmit(json_object *jobj, uint8_t *cnt,
							uint16_t *interval)
{
	json_object *jretransmit, *jvalue;

	json_object_object_get_ex(jobj, "retransmit", &jretransmit);
	if (!jretransmit)
		return false;

	json_object_object_get_ex(jretransmit, "count", &jvalue);
	if (!jvalue)
		return false;

	*cnt = (uint8_t) json_object_get_int(jvalue);

	json_object_object_get_ex(jretransmit, "interval", &jvalue);
	if (!jvalue)
		return false;

	*interval = (uint16_t) json_object_get_int(jvalue);

	return true;
}

bool mesh_db_write_net_transmit(json_object *jobj, uint8_t cnt,
							uint16_t interval)
{
	json_object *jretransmit;

	json_object_object_del(jobj, "retransmit");

	jretransmit = json_object_new_object();
	if (jretransmit)
		return false;

	if (!mesh_db_write_int(jretransmit, "count", cnt))
		goto fail;

	if (!mesh_db_write_int(jretransmit, "interval", interval))
		goto fail;

	json_object_object_add(jobj, "retransmit", jretransmit);

	return true;
fail:
	json_object_put(jretransmit);
	return false;

}

bool mesh_db_write_iv_index(json_object *jobj, uint32_t idx, bool update)
{
	int tmp = update ? 1 : 0;

	if (!mesh_db_write_int(jobj, "IVindex", idx))
		return false;

	if (!mesh_db_write_int(jobj, "IVupdate", tmp))
		return false;

	return true;
}

void mesh_db_remove_property(json_object *jobj, const char *desc)
{
	json_object_object_del(jobj, desc);
}

static void add_model(void *a, void *b)
{
	struct mesh_db_model *mod = a;
	json_object *jmodels = b;

	(void)mesh_db_write_model_id(jmodels, mod);
}

/* Add unprovisioned node (local) */
bool mesh_db_add_node(json_object *jnode,
	struct mesh_db_node *db_node,
	struct mesh_node *node)
{
	struct mesh_db_modes *modes = &db_node->modes;
	const struct l_queue_entry *entry;
	json_object *jelements;

	/* CID, PID, VID */
	if (!mesh_db_write_uint16_hex(jnode, "cid", db_node->cid))
		return false;

	if (!mesh_db_write_uint16_hex(jnode, "pid", db_node->pid))
		return false;

	if (!mesh_db_write_uint16_hex(jnode, "vid", db_node->vid))
		return false;

	/* IV index and IV update flag */
	if (node_is_provisioned(node)) {
		if (!mesh_db_write_iv_index(jnode, db_node->iv_index,
				db_node->iv_update))
			return false;
	} else {
		json_object_object_add(jnode, "IVindex", NULL);
		json_object_object_add(jnode, "IVupdate", NULL);
	}

	/* Device UUID */
	if (!add_uuid(jnode, "UUID", db_node->uuid))
		return false;

	/* Device Key */
	if (!mesh_db_write_device_key(jnode, db_node->dev_key))
		return false;

	/* Default TTL */
	if (node_is_provisioned(node))
		json_object_object_add(jnode, "defaultTTL",
				json_object_new_int(db_node->ttl));
	else
		json_object_object_add(jnode, "defaultTTL", NULL);

	/* Sequence number */
	json_object_object_add(jnode, "sequenceNumber",
		json_object_new_int(db_node->seq_number));

	/* Beaconing state */
	if (!mesh_db_write_mode(jnode, "beacon", modes->beacon))
		return false;

	/* Low power mode */
	if (!mesh_db_write_mode(jnode, "lowPower", modes->low_power))
		return false;

	/* Friend mode */
	if (!mesh_db_write_mode(jnode, "friend", modes->friend))
		return false;

	/* Provisioned and proxy flags */
	if (!mesh_db_write_bool(jnode, "provisioned",
		 node_is_provisioned(node)))
		return false;

	/* Proxy mode */
	if (!mesh_db_write_mode(jnode, "proxy", modes->proxy))
		return false;

	/* Relay related parameters */
	if (!mesh_db_write_relay_mode(jnode, db_node->modes.relay.mode,
		 db_node->modes.relay.cnt, db_node->modes.relay.interval))
		return false;

	/* Advertising state */
	if (!mesh_db_write_bool(jnode, "advertising", db_node->is_advertising))
		return false;

	/* Elements */
	jelements = json_object_new_object();

	if (!jelements)
		return false;

	entry = l_queue_get_entries(db_node->elements);

	for (int idx = 0; entry; entry = entry->next, idx++) {
		char int_as_str[11];
		struct mesh_db_element *ele = entry->data;
		json_object *jmodels;
		json_object *jsub_elements;

		/* Convert idx to string value */
		sprintf(int_as_str, "%d", idx);

		jsub_elements = json_object_new_object();

		mesh_db_write_int(jsub_elements, "elementIndex", ele->index);
		mesh_db_write_uint16_hex(jsub_elements, "location",
			ele->location);

		json_object_object_add(jelements, &int_as_str[0],
			jsub_elements);

		/* Models */
		if (l_queue_isempty(ele->models))
			continue;

		jmodels = json_object_new_array();

		if (!jmodels) {
			json_object_put(jelements);
			return false;
		}

		json_object_object_add(jsub_elements, "models", jmodels);
		l_queue_foreach(ele->models, add_model, jmodels);
	}

	json_object_object_add(jnode, "elements", jelements);

	return true;
}
