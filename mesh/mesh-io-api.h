/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
 *
 *
 */

struct mesh_io_private;

typedef bool (*mesh_io_init_t)(struct mesh_io *io, void *opts,
				struct l_dbus *dbus, mesh_io_ready_func_t cb,
				void *user_data);
typedef bool (*mesh_io_destroy_t)(struct mesh_io *io);
typedef bool (*mesh_io_send_t)(struct mesh_io *io,
					struct mesh_io_send_info *info,
					const uint8_t *data, uint16_t len);
typedef bool (*mesh_io_filter_reg_t)(struct mesh_io *io, const uint8_t *filter,
					uint8_t len, mesh_io_recv_func_t cb,
					void *user_data);
typedef bool (*mesh_io_filter_dereg_t)(struct mesh_io *io,
					const uint8_t *filter, uint8_t len);
typedef bool (*mesh_io_subnet_reg_t)(struct mesh_io *io, uint32_t net_key_id,
						mesh_io_recv_func_t net_cb,
						mesh_io_recv_func_t snb_cb,
						void *user_data);
typedef bool (*mesh_io_subnet_dereg_t)(struct mesh_io *io, uint32_t net_key_id);
typedef bool (*mesh_io_tx_cancel_t)(struct mesh_io *io, const uint8_t *pattern,
								uint8_t len);

struct mesh_io_api {
	mesh_io_init_t		init;
	mesh_io_destroy_t	destroy;
	mesh_io_send_t		send;
	mesh_io_filter_reg_t	filter_reg;
	mesh_io_filter_dereg_t	filter_dereg;
	mesh_io_subnet_reg_t	subnet_reg;
	mesh_io_subnet_dereg_t	subnet_dereg;
	mesh_io_tx_cancel_t	cancel;
};

struct mesh_io {
	enum mesh_io_type		type;
	const struct mesh_io_api	*api;
	size_t subnets;
	struct mesh_io_private		*pvt;
};

struct mesh_io_table {
	enum mesh_io_type		type;
	const struct mesh_io_api	*api;
};
