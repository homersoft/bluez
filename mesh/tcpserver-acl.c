/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Silvair Inc. All rights reserved.
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
#include "tcpserver-acl.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <ell/ell.h>
#include <json-c/json.h>

#include "mesh/dbus.h"
#include "mesh/error.h"
#include "mesh/crypto.h"
#include "mesh/util.h"

#include "config.h"

#define UUID_LEN (16)
#define DEV_KEY_LEN (16)
#define NET_KEY_LEN (16)
#define IDENTITY_LEN (16)
#define PSK_LEN (16)


static const char *TCPSERVER_ACL_IFACE = "org.bluez.mesh.AccessControlList1";


struct tcpserver_acl {
	char			*config_path;
	const char		*dbus_path;
	struct l_queue		*entries;
	void			*user_data;
	on_acl_entry_changed	on_acl_entry_changed_callback;
};

struct acl_entry {
	uint64_t	token;
	uint8_t		identity[IDENTITY_LEN];
	uint8_t		psk[PSK_LEN];
};


static bool calc_identity(const uint8_t *uuid, const uint8_t *net_key,
			  uint8_t *identity)
{
	uint8_t net_id[8];
	char s1_info[24];

	// net_id = k3(net_key)
	if (!mesh_crypto_k3(net_key, net_id))
		return false;

	// s1_info = (uuid|net_id)
	memcpy(s1_info, uuid, UUID_LEN);
	memcpy(s1_info + UUID_LEN, net_id, sizeof(net_id));

	// id = s1(s1_info)
	if (!mesh_crypto_s1(s1_info, sizeof(s1_info), identity))
		return false;

	return true;
}

static bool calc_psk(const uint8_t *identity, const uint8_t *dev_key,
		     uint8_t *psk)
{
	const char k1_info[] = { 'i', 'd', 'p', 's', 'k' };

	// psk = k1(dev_key, identity, "idpsk")
	if (!mesh_crypto_k1(dev_key, identity, k1_info, sizeof(k1_info), psk))
		return false;

	return true;
}

static bool acl_entry_fill(struct acl_entry *entry, const uint8_t *uuid,
			   const uint8_t *dev_key, const uint8_t *net_key)
{
	if (!calc_identity(uuid, net_key, entry->identity))
		return false;

	if (!calc_psk(entry->identity, dev_key, entry->psk))
		return false;

	return true;
}

static bool match_identity(const void *a, const void *b)
{
	const struct acl_entry *entry = a;
	const unsigned char *identity = b;

	return !memcmp(entry->identity, identity, sizeof(entry->identity));
}

static struct acl_entry *acl_entry_find_by_identity(
	struct l_queue *entries, const uint8_t *identity_buf)
{
	return l_queue_find(entries, match_identity, identity_buf);
}

static bool match_token(const void *a, const void *b)
{
	const struct acl_entry *entry = a;
	const uint64_t *token = b;

	return entry->token == *token;
}

static struct acl_entry *acl_entry_find_by_token(
	struct l_queue *acl, uint64_t token)
{
	return l_queue_find(acl, match_token, &token);
}

static uint64_t acl_get_unique_token(struct l_queue *entries)
{
	uint64_t token;

	do {
		l_getrandom(&token, sizeof(token));
	} while (acl_entry_find_by_token(entries, token));

	return token;
}

static uint32_t acl_add_entry(
	struct l_queue *entries, struct acl_entry *entry)
{
	if (acl_entry_find_by_identity(entries, entry->identity))
		return MESH_ERROR_ALREADY_EXISTS;

	if (!l_queue_push_tail(entries, entry))
		return MESH_ERROR_FAILED;

	return MESH_ERROR_NONE;
}

static bool write_hexstr(json_object *jobj, const char *key,
			 void *buf, size_t buf_len)
{
	char str[33];
	json_object *jstr;

	if (!hex2str(buf, buf_len, str, 33))
		return false;

	jstr = json_object_new_string(str);
	if (!jstr)
		return false;

	json_object_object_add(jobj, key, jstr);
	return true;
}

static void adapter_cfg_write_acl_entry(void *data, void *user_data)
{
	struct acl_entry *entry = data;

	json_object *jarray = user_data;
	json_object *jobj;

	jobj = json_object_new_object();
	if (!jobj)
		return;

	if (!write_hexstr(jobj, "token", &entry->token, sizeof(entry->token)))
		goto fail;

	if (!write_hexstr(jobj, "identity", entry->identity, IDENTITY_LEN))
		goto fail;

	if (!write_hexstr(jobj, "psk", entry->psk, PSK_LEN))
		goto fail;

	json_object_array_add(jarray, jobj);
	return;

fail:
	l_error("Failed to write ACL entry");

	// Release memory allocated by JSON-c
	json_object_put(jobj);
	return;

}

static json_object *acl_to_json_cfg(struct tcpserver_acl *acl)
{
	json_object *jcfg;
	json_object *jarray;

	jcfg = json_object_new_object();
	if (!jcfg)
		return NULL;

	jarray = json_object_new_array();
	if (!jarray) {
		// Release memory allocated by JSON-c
		json_object_put(jcfg);

		return NULL;
	}

	l_queue_foreach(acl->entries, adapter_cfg_write_acl_entry, jarray);

	json_object_object_add(jcfg, "ACL", jarray);

	return jcfg;
}

static bool save_config(struct tcpserver_acl *acl)
{
	FILE *outfile;
	json_object *jcfg;
	const char *str;
	bool result = false;

	outfile = fopen(acl->config_path, "w");
	if (!outfile) {
		l_error("Failed to save configuration to %s", acl->config_path);
		return false;
	}

	jcfg = acl_to_json_cfg(acl);

	str = json_object_to_json_string_ext(jcfg, JSON_C_TO_STRING_PRETTY);

	if (fwrite(str, sizeof(char), strlen(str), outfile) < strlen(str))
		l_warn("Incomplete write of adapter configuration");
	else
		result = true;

	json_object_put(jcfg);
	fclose(outfile);

	return result;
}

static bool read_hexstr_data(json_object *jobj, const char *key,
			     void *buf, size_t buf_len)
{
	json_object *jval;
	const char *str;

	if (!json_object_object_get_ex(jobj, key, &jval))
		return false;

	str = json_object_get_string(jval);
	if (!str)
		return false;

	return str2hex(str, strlen(str), buf, buf_len);
}

static struct acl_entry *adapter_cfg_parse_acl_entry(json_object *jobj)
{
	struct acl_entry *entry = l_new(struct acl_entry, 1);

	if (!read_hexstr_data(jobj, "token", &entry->token, sizeof(uint64_t)))
		goto fail;

	if (!read_hexstr_data(jobj, "identity", entry->identity, IDENTITY_LEN))
		goto fail;

	if (!read_hexstr_data(jobj, "psk", entry->psk, PSK_LEN))
		goto fail;

	return entry;

fail:
	l_error("Failed to parse ACL entry");

	l_free(entry);
	return NULL;
}

static bool set_json_config(struct tcpserver_acl *acl, json_object *jcfg)
{
	struct acl_entry	*entry;
	json_object		*jentry;
	json_object		*jarray;
	size_t			array_len;
	uint32_t		err;

	json_object_object_get_ex(jcfg, "ACL", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	array_len = json_object_array_length(jarray);

	for (size_t i = 0; i < array_len; i++) {
		jentry = json_object_array_get_idx(jarray, i);
		if (!jentry)
			goto fail;

		entry = adapter_cfg_parse_acl_entry(jentry);
		if (!entry)
			goto fail;

		err = acl_add_entry(acl->entries, entry);
		if (err != MESH_ERROR_NONE) {
			l_free(entry);
			goto fail;
		}

		if (acl->on_acl_entry_changed_callback)
			acl->on_acl_entry_changed_callback(acl,
							   entry->identity,
							   acl->user_data,
							   false);

		l_debug("Added ACL entry with token: '%ju'", entry->token);
	}

	return true;
fail:

	l_queue_clear(acl->entries, l_free);
	return false;
}

static bool load_config(struct tcpserver_acl *acl)
{
	int fd;
	char *str;
	struct stat st;
	ssize_t sz;
	json_object *jcfg;

	fd = open(acl->config_path, O_RDONLY);
	if (fd < 0)
		return false;

	if (fstat(fd, &st) == -1) {
		close(fd);
		return false;
	}

	str = l_new(char, st.st_size + 1);

	sz = read(fd, str, st.st_size);
	if (sz != st.st_size) {
		l_error("Failed to read configuration file %s",
			acl->config_path);
		close(fd);
		return false;
	}

	jcfg = json_tokener_parse(str);

	close(fd);
	l_free(str);

	return set_json_config(acl, jcfg);
}

static struct l_dbus_message *grant_access_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct tcpserver_acl *acl = user_data;

	struct acl_entry *entry;
	struct l_dbus_message *ret_msg;
	struct l_dbus_message_iter iter_uuid;
	struct l_dbus_message_iter iter_dev_key;
	struct l_dbus_message_iter iter_net_key;

	uint8_t *uuid;
	uint8_t *dev_key;
	uint8_t *net_key;
	uint32_t n;
	uint32_t err;

	if (!l_dbus_message_get_arguments(msg, "ayayay", &iter_uuid,
					  &iter_dev_key, &iter_net_key))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (!l_dbus_message_iter_get_fixed_array(&iter_uuid, &uuid, &n) ||
	    (n != UUID_LEN))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (!l_dbus_message_iter_get_fixed_array(&iter_dev_key, &dev_key, &n)
	    || (n != DEV_KEY_LEN))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (!l_dbus_message_iter_get_fixed_array(&iter_net_key, &net_key, &n)
	    || (n != NET_KEY_LEN))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	entry = l_new(struct acl_entry, 1);

	entry->token = acl_get_unique_token(acl->entries);

	if (!acl_entry_fill(entry, uuid, dev_key, net_key)) {
		l_free(entry);
		return dbus_error(msg, MESH_ERROR_FAILED, NULL);
	}

	err = acl_add_entry(acl->entries, entry);
	if (err != MESH_ERROR_NONE) {
		l_free(entry);
		return dbus_error(msg, err, NULL);
	}

	if (acl->on_acl_entry_changed_callback &&
	    acl->on_acl_entry_changed_callback(acl,
					       entry->identity,
					       acl->user_data,
					       false))
		save_config(acl);

	ret_msg = l_dbus_message_new_method_return(msg);

	l_dbus_message_set_arguments(ret_msg, "t", entry->token);

	return ret_msg;
}

static struct l_dbus_message *revoke_access_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct tcpserver_acl *acl = user_data;
	struct acl_entry *entry;

	uint64_t token;

	if (!l_dbus_message_get_arguments(msg, "t", &token))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	entry = acl_entry_find_by_token(acl->entries, token);

	if (!entry)
		return dbus_error(msg, MESH_ERROR_NOT_FOUND, NULL);

	if (!l_queue_remove(acl->entries, entry))
		return dbus_error(msg, MESH_ERROR_NOT_FOUND, NULL);

	if (acl->on_acl_entry_changed_callback &&
	    acl->on_acl_entry_changed_callback(acl, entry->identity,
					       acl->user_data, true))
		save_config(acl);

	l_free(entry);

	return l_dbus_message_new_method_return(msg);
}

static void setup_acl_iface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "GrantAccess", 0, grant_access_call, "t",
				"ayayay", "token", "uuid", "dev_key",
				"net_key");

	l_dbus_interface_method(iface, "RevokeAccess", 0, revoke_access_call,
				"", "t", "token");
}

struct tcpserver_acl *tcpserver_acl_new(const char *config_dir,
			const char *dbus_path,
			on_acl_entry_changed on_acl_entry_changed_callback,
			void *user_data)
{
	struct tcpserver_acl *acl;

	acl			= l_new(struct tcpserver_acl, 1);
	acl->config_path	= l_strdup_printf("%s/tcpserver_acl.conf",
						config_dir ?: MESH_STORAGEDIR);
	acl->dbus_path		= dbus_path;
	acl->entries		= l_queue_new();
	acl->user_data		= user_data;

	acl->on_acl_entry_changed_callback = on_acl_entry_changed_callback;

	load_config(acl);

	return acl;
}

void tcpserver_acl_destroy(struct tcpserver_acl *acl)
{
	if (acl->entries)
		l_queue_destroy(acl->entries, l_free);

	if (acl->config_path)
		l_free(acl->config_path);

	l_free(acl);
}

bool tcpserver_acl_dbus_init(struct tcpserver_acl *acl, struct l_dbus *bus)
{
	if (!l_dbus_register_interface(bus, TCPSERVER_ACL_IFACE,
				       setup_acl_iface, NULL, false)) {
		l_info("Unable to register %s interface",
		       TCPSERVER_ACL_IFACE);

		return false;
	}

	if (!l_dbus_object_add_interface(bus, acl->dbus_path,
					 TCPSERVER_ACL_IFACE, acl)) {
		l_info("Unable to register the mesh object on '%s'",
		       TCPSERVER_ACL_IFACE);

		l_dbus_unregister_interface(bus, TCPSERVER_ACL_IFACE);
		return false;
	}

	return true;
}

size_t tcpserver_acl_psk_get(struct tcpserver_acl *acl, const char *identity,
			     uint8_t *psk, unsigned int max_psk_len)
{
	uint8_t			identity_buf[IDENTITY_LEN];
	struct acl_entry	*entry;

	if (!str2hex(identity, strlen(identity), identity_buf, IDENTITY_LEN))
		return 0;

	entry = acl_entry_find_by_identity(acl->entries, identity_buf);

	if (!entry || max_psk_len < PSK_LEN)
		return 0;

	memcpy(psk, entry->psk, PSK_LEN);

	return PSK_LEN;
}
