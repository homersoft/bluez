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
#include <time.h>
#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "src/shared/mgmt.h"

#include "mesh/mesh-defs.h"
#include "mesh/mesh-io.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/storage.h"
#include "mesh/prov.h"
#include "mesh/provision.h"
#include "mesh/model.h"
#include "mesh/dbus.h"
#include "mesh/error.h"
#include "mesh/mesh.h"
#include "mesh/agent.h"

#define MESH_COMP_MAX_LEN 378

/*
 * The default values for mesh configuration. Can be
 * overwritten by values from mesh.conf
 */
#define DEFAULT_PROV_TIMEOUT 60
#define DEFAULT_ALGORITHMS 0x0001

/* TODO: add more default values */

struct scan_filter {
	uint8_t id;
	const char *pattern;
};

struct bt_mesh {
	struct mesh_io *io;
	struct l_queue *filters;
	prov_rx_cb_t prov_rx;
	void *prov_data;
	uint32_t prov_timeout;
	uint16_t algorithms;
	uint16_t req_index;
	uint8_t max_filters;
};

struct attach_data {
	uint64_t token;
	struct l_dbus_message *msg;
	const char *app;
};

static struct bt_mesh mesh;
static struct l_queue *controllers;
static struct mgmt *mgmt_mesh;
static bool initialized;

static bool simple_match(const void *a, const void *b)
{
	return a == b;
}

static void start_io(uint16_t index)
{
	struct mesh_io *io;
	struct mesh_io_caps caps;

	l_debug("Starting mesh on hci %u", index);

	io = mesh_io_new(index, MESH_IO_TYPE_GENERIC);
	if (!io) {
		l_error("Failed to start mesh io (hci %u)", index);
		return;
	}

	mesh_io_get_caps(io, &caps);
	mesh.max_filters = caps.max_num_filters;

	mesh.io = io;

	l_debug("Started mesh (io %p) on hci %u", mesh.io, index);

	node_attach_io(io);
}

struct mesh_io *mesh_get_io(void)
{
	return mesh.io;
}

/* Used for any outbound traffic that doesn't have Friendship Constraints */
/* This includes Beacons, Provisioning and unrestricted Network Traffic */
bool mesh_send_pkt(uint8_t count, uint16_t interval,
					uint8_t *data, uint16_t len)
{
	struct mesh_io_send_info info = {
		.type = MESH_IO_TIMING_TYPE_GENERAL,
		.u.gen.cnt = count,
		.u.gen.interval = interval,
		.u.gen.max_delay = 0,
		.u.gen.min_delay = 0,
	};

	return mesh_io_send(mesh.io, &info, data, len);
}

bool mesh_send_cancel(const uint8_t *filter, uint8_t len)
{
	return mesh_io_send_cancel(mesh.io, filter, len);
}

static void prov_rx(void *user_data, struct mesh_io_recv_info *info,
					const uint8_t *data, uint16_t len)
{
	if (user_data != &mesh)
		return;

	if (mesh.prov_rx)
		mesh.prov_rx(mesh.prov_data, data, len);
}

bool mesh_reg_prov_rx(prov_rx_cb_t cb, void *user_data)
{
	if (mesh.prov_rx && mesh.prov_rx != cb)
		return false;

	mesh.prov_rx = cb;
	mesh.prov_data = user_data;

	return mesh_io_register_recv_cb(mesh.io, MESH_IO_FILTER_PROV,
							prov_rx, &mesh);
}

void mesh_unreg_prov_rx(prov_rx_cb_t cb)
{
	if (mesh.prov_rx != cb)
		return;

	mesh.prov_rx = NULL;
	mesh.prov_data = NULL;
	mesh_io_deregister_recv_cb(mesh.io, MESH_IO_FILTER_PROV);
}

static void read_info_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	uint16_t index = L_PTR_TO_UINT(user_data);
	const struct mgmt_rp_read_info *rp = param;
	uint32_t current_settings, supported_settings;

	if (mesh.io)
		/* Already initialized */
		return;

	l_debug("hci %u status 0x%02x", index, status);

	if (status != MGMT_STATUS_SUCCESS) {
		l_error("Failed to read info for hci index %u: %s (0x%02x)",
					index, mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		l_error("Read info response too short");
		return;
	}

	current_settings = btohl(rp->current_settings);
	supported_settings = btohl(rp->supported_settings);

	l_debug("settings: supp %8.8x curr %8.8x",
					supported_settings, current_settings);

	if (current_settings & MGMT_SETTING_POWERED) {
		l_info("Controller hci %u is in use", index);
		return;
	}

	if (!(supported_settings & MGMT_SETTING_LE)) {
		l_info("Controller hci %u does not support LE", index);
		return;
	}

	start_io(index);
}

static void index_added(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	l_debug("hci device %u", index);

	if (mesh.req_index != MGMT_INDEX_NONE &&
					index != mesh.req_index) {
		l_debug("Ignore index %d", index);
		return;
	}

	if (l_queue_find(controllers, simple_match, L_UINT_TO_PTR(index)))
		return;

	l_queue_push_tail(controllers, L_UINT_TO_PTR(index));

	if (mgmt_send(mgmt_mesh, MGMT_OP_READ_INFO, index, 0, NULL,
			read_info_cb, L_UINT_TO_PTR(index), NULL) > 0)
		return;

	l_queue_remove(controllers, L_UINT_TO_PTR(index));
}

static void index_removed(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	l_warn("Hci dev %4.4x removed", index);
	l_queue_remove(controllers, L_UINT_TO_PTR(index));
}

static void read_index_list_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	uint16_t num;
	int i;

	if (status != MGMT_STATUS_SUCCESS) {
		l_error("Failed to read index list: %s (0x%02x)",
						mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		l_error("Read index list response sixe too short");
		return;
	}

	num = btohs(rp->num_controllers);

	l_debug("Number of controllers: %u", num);

	if (num * sizeof(uint16_t) + sizeof(*rp) != length) {
		l_error("Incorrect packet size for index list response");
		return;
	}

	for (i = 0; i < num; i++) {
		uint16_t index;

		index = btohs(rp->index[i]);
		index_added(index, 0, NULL, user_data);
	}
}

static bool init_mgmt(void)
{
	mgmt_mesh = mgmt_new_default();
	if (!mgmt_mesh)
		return false;

	controllers = l_queue_new();
	if (!controllers)
		return false;

	mgmt_register(mgmt_mesh, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
						index_added, NULL, NULL);
	mgmt_register(mgmt_mesh, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
						index_removed, NULL, NULL);
	return true;
}

bool mesh_init(uint16_t index, const char *config_dir)
{
	if (initialized)
		return true;

	if (!init_mgmt()) {
		l_error("Failed to initialize mesh management");
		return false;
	}

	mesh.req_index = index;

	mesh_model_init();
	mesh_agent_init();

	/* TODO: read mesh.conf */
	mesh.prov_timeout = DEFAULT_PROV_TIMEOUT;
	mesh.algorithms = DEFAULT_ALGORITHMS;

	if (!config_dir)
		config_dir = MESH_STORAGEDIR;

	l_info("Loading node configuration from %s", config_dir);

	if (!storage_load_nodes(config_dir))
		return false;

	l_debug("send read index_list");
	if (mgmt_send(mgmt_mesh, MGMT_OP_READ_INDEX_LIST,
				MGMT_INDEX_NONE, 0, NULL,
				read_index_list_cb, NULL, NULL) <= 0)
		return false;

	return true;
}

void mesh_cleanup(void)
{
	mesh_io_destroy(mesh.io);
	mgmt_unref(mgmt_mesh);

	node_cleanup_all();
	mesh_model_cleanup();

	l_queue_destroy(controllers, NULL);
	l_dbus_object_remove_interface(dbus_get_bus(), BLUEZ_MESH_PATH,
							MESH_NETWORK_INTERFACE);
	l_dbus_unregister_interface(dbus_get_bus(), MESH_NETWORK_INTERFACE);
}

const char *mesh_status_str(uint8_t err)
{
	switch (err) {
	case MESH_STATUS_SUCCESS: return "Success";
	case MESH_STATUS_INVALID_ADDRESS: return "Invalid Address";
	case MESH_STATUS_INVALID_MODEL: return "Invalid Model";
	case MESH_STATUS_INVALID_APPKEY: return "Invalid AppKey";
	case MESH_STATUS_INVALID_NETKEY: return "Invalid NetKey";
	case MESH_STATUS_INSUFF_RESOURCES: return "Insufficient Resources";
	case MESH_STATUS_IDX_ALREADY_STORED: return "Key Idx Already Stored";
	case MESH_STATUS_INVALID_PUB_PARAM: return "Invalid Publish Parameters";
	case MESH_STATUS_NOT_SUB_MOD: return "Not a Subscribe Model";
	case MESH_STATUS_STORAGE_FAIL: return "Storage Failure";
	case MESH_STATUS_FEATURE_NO_SUPPORT: return "Feature Not Supported";
	case MESH_STATUS_CANNOT_UPDATE: return "Cannot Update";
	case MESH_STATUS_CANNOT_REMOVE: return "Cannot Remove";
	case MESH_STATUS_CANNOT_BIND: return "Cannot bind";
	case MESH_STATUS_UNABLE_CHANGE_STATE: return "Unable to change state";
	case MESH_STATUS_CANNOT_SET: return "Cannot set";
	case MESH_STATUS_UNSPECIFIED_ERROR: return "Unspecified error";
	case MESH_STATUS_INVALID_BINDING: return "Invalid Binding";

	default: return "Unknown";
	}
}

static struct l_dbus_message *create_node_call(struct l_dbus *dbus,
			struct l_dbus_message *msg, void *user_data)
{
	uint16_t n = 0;
	uint64_t element_bits = 0;
	uint16_t cid, pid, vid;

	struct l_dbus_message_iter iter_element_models;
	struct l_dbus_message_iter iter_temp_element_models;
	struct l_dbus_message_iter iter_uuid;
	struct l_dbus_message_iter iter_sig_models;
	struct l_dbus_message_iter iter_vendor_models;

	uint8_t element_idx;
	uint16_t location;
	uint8_t temp_uuid[KEY_LEN] = {0};

	struct l_dbus_message *reply;

	l_debug("Create node request");

	if (!l_dbus_message_get_arguments(msg, "qqqaya{y(qaqaq)}",
			&cid, &pid, &vid,
			&iter_uuid, &iter_element_models))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	iter_temp_element_models = iter_element_models;

	if (dbus_get_byte_array(&iter_uuid, temp_uuid, KEY_LEN) != KEY_LEN)
		return dbus_error(msg,
			MESH_ERROR_INVALID_ARGS,
			"Incorrect device UUID format");

	if (!l_uuid_is_valid(temp_uuid))
		return dbus_error(msg,
			MESH_ERROR_INVALID_ARGS,
			"Incorrect device UUID format");

	if (node_find_by_uuid(temp_uuid))
		return dbus_error(msg, MESH_ERROR_ALREADY_EXISTS, NULL);

	while (l_dbus_message_iter_next_entry(&iter_temp_element_models,
		&element_idx,
		&location,
		&iter_sig_models,
		&iter_vendor_models)) {

		if (element_idx > 63)
			return dbus_error(msg,
				MESH_ERROR_INVALID_ARGS,
				"Max element id 63");

				element_bits |= (1 << element_idx);
		n++;
	}

	if (element_bits != ((1u << n) - 1))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
			"Wrong element indexation");

	if (!create_node_request(temp_uuid, pid, cid, vid,
				&iter_element_models))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
			"Only element 0 can implement models {0x0000, 0x0002}");

	reply = l_dbus_message_new_method_return(msg);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static struct l_dbus_message *delete_node_call(struct l_dbus *dbus,
		struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message *reply;
	struct l_dbus_message_iter iter_uuid;
	uint8_t uuid[KEY_LEN];

	l_debug("Delete Node");

	if (!l_dbus_message_get_arguments(msg, "ay", &iter_uuid))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (dbus_get_byte_array(&iter_uuid, uuid, KEY_LEN) != KEY_LEN)
		return dbus_error(msg,
			MESH_ERROR_INVALID_ARGS,
			"Incorrect device UUID format");

	if (!delete_node(uuid))
		return dbus_error(msg, MESH_ERROR_DOES_NOT_EXIST, NULL);

	reply = l_dbus_message_new_method_return(msg);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static void setup_network_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "CreateNode", 0, create_node_call, "",
				"qqqaya{y(qaqaq)}", "cid", "pid",
				"vid", "uuid", "element_models");

	l_dbus_interface_method(iface, "DeleteNode", 0, delete_node_call, "",
				"ay", "uuid");
}

bool mesh_dbus_init(struct l_dbus *dbus)
{
	if (!l_dbus_register_interface(dbus, MESH_NETWORK_INTERFACE,
			setup_network_interface, NULL, false)) {

		l_info("Unable to register %s interface",
					MESH_NETWORK_INTERFACE);
		return false;
	}

	if (!l_dbus_object_add_interface(dbus, BLUEZ_MESH_PATH,
						MESH_NETWORK_INTERFACE, NULL)) {
		l_info("Unable to register the mesh object on '%s'",
							MESH_NETWORK_INTERFACE);
		l_dbus_unregister_interface(dbus, MESH_NETWORK_INTERFACE);
		return false;
	}

	l_info("Added Network Interface on %s", BLUEZ_MESH_PATH);

	return true;
}
