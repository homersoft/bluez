// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "lib/bluetooth.h"

#include "mesh/mesh-defs.h"
#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"

/* List of Mesh-IO Type headers */
#include "mesh/mesh-io-generic.h"
#include "mesh/mesh-io-unit.h"
#include "mesh/mesh-io-uart.h"
#include "mesh/mesh-io-tcpserver.h"

static const uint8_t prov_filter[] = {MESH_AD_TYPE_PROVISION};
static const uint8_t net_filter[] = {MESH_AD_TYPE_NETWORK}; // TODO: also filter by NID
static const uint8_t prvb_filter[] = {MESH_AD_TYPE_BEACON, 0x00};
static const uint8_t snb_filter[] = {MESH_AD_TYPE_BEACON, 0x01}; // TODO: filter by network id

/* List of Supported Mesh-IO Types */
static const struct mesh_io_table table[] = {
	{MESH_IO_TYPE_GENERIC, &mesh_io_generic},
	{MESH_IO_TYPE_UNIT_TEST, &mesh_io_unit},
	{MESH_IO_TYPE_UART,		&mesh_io_uart},
	{MESH_IO_TYPE_TCPSERVER,	&mesh_io_tcpserver}
};


static struct l_queue *io_list;

static bool match_by_io(const void *a, const void *b)
{
	return a == b;
}

static bool match_by_type(const void *a, const void *b)
{
	const struct mesh_io *io = a;
	const enum mesh_io_type type = L_PTR_TO_UINT(b);

	return io->type == type;
}

struct mesh_io *mesh_io_new(enum mesh_io_type type, void *opts,
				struct l_dbus *dbus, mesh_io_ready_func_t cb,
				void *user_data)
{
	const struct mesh_io_api *api = NULL;
	struct mesh_io *io;
	uint16_t i;

	for (i = 0; i < L_ARRAY_SIZE(table); i++) {
		if (table[i].type == type) {
			api = table[i].api;
			break;
		}
	}

	io = l_queue_find(io_list, match_by_type, L_UINT_TO_PTR(type));

	if (!api || !api->init || io)
		return NULL;

	io = l_new(struct mesh_io, 1);

	io->type = type;
	io->api = api;

	if (!api->init(io, opts, dbus, cb, user_data))
		goto fail;

	if (!io_list)
		io_list = l_queue_new();

	if (l_queue_push_head(io_list, io))
		return io;

fail:
	if (api->destroy)
		api->destroy(io);

	l_free(io);
	return NULL;
}

void mesh_io_destroy(struct mesh_io *io)
{
	io = l_queue_remove_if(io_list, match_by_io, io);

	if (io && io->api && io->api->destroy)
		io->api->destroy(io);

	l_free(io);

	if (l_queue_isempty(io_list)) {
		l_queue_destroy(io_list, NULL);
		io_list = NULL;
	}
}

bool mesh_io_register_prov_beacon_cb(struct mesh_io *io, mesh_io_recv_func_t cb,
				void *user_data)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (io && io->api && io->api->filter_reg)
		return io->api->filter_reg(io, prvb_filter, sizeof(prvb_filter), cb, user_data);

	return false;
}

bool mesh_io_deregister_prov_beacon_cb(struct mesh_io *io)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (io && io->api && io->api->filter_dereg)
		return io->api->filter_dereg(io, prvb_filter, sizeof(prvb_filter));

	return false;
}

bool mesh_io_register_prov_cb(struct mesh_io *io, mesh_io_recv_func_t cb,
				void *user_data)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (io && io->api && io->api->filter_reg)
		return io->api->filter_reg(io, prov_filter, sizeof(prov_filter), cb, user_data);

	return false;
}

bool mesh_io_deregister_prov_cb(struct mesh_io *io)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (io && io->api && io->api->filter_dereg)
		return io->api->filter_dereg(io, prov_filter, sizeof(prov_filter));

	return false;
}

bool mesh_io_register_subnet_cb(struct mesh_io *io, uint32_t net_key_id,
						mesh_io_recv_func_t net_cb,
						mesh_io_recv_func_t snb_cb,
						void *user_data)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (!io || !io->api)
		return false;

	if (io->api->subnet_reg)
		return io->api->subnet_reg(io, net_key_id, net_cb, snb_cb,
								user_data);

	if (!io->subnets++) {
		if (!io->api->filter_reg)
			return false;

		if (!io->api->filter_reg(io, net_filter, sizeof(net_filter),
								net_cb, NULL))
			return false;

		if (!io->api->filter_reg(io, snb_filter, sizeof(snb_filter),
								snb_cb, NULL))
			return false;
	}

	return true;
}

bool mesh_io_deregister_subnet_cb(struct mesh_io *io, uint32_t net_key_id)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (!io || !io->api)
		return false;

	if (io->api->subnet_dereg)
		return io->api->subnet_dereg(io, net_key_id);

	if (!--io->subnets) {
		if (!io->api->filter_dereg)
			return false;

		if (!io->api->filter_dereg(io, net_filter, sizeof(net_filter)))
			return false;

		if (!io->api->filter_dereg(io, snb_filter, sizeof(snb_filter)))
			return false;
	}

	return true;
}

bool mesh_io_send(struct mesh_io *io, struct mesh_io_send_info *info,
					const uint8_t *data, uint16_t len)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (!io)
		io = l_queue_peek_head(io_list);

	if (io && io->api && io->api->send)
		return io->api->send(io, info, data, len);

	return false;
}

bool mesh_io_send_cancel(struct mesh_io *io, const uint8_t *pattern,
								uint8_t len)
{
	io = l_queue_find(io_list, match_by_io, io);

	if (io && io->api && io->api->cancel)
		return io->api->cancel(io, pattern, len);

	return false;
}
