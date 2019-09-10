/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Silvair Inc. All rights reserved.
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
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

struct mesh_io;
struct mesh_io_private;

struct slip {
	uint8_t buf[512];
	size_t offset;
	bool esc;
};

enum packet_type {
	PACKET_TYPE_MESSAGE,
	PACKET_TYPE_KEEP_ALIVE,
};

typedef void (*process_packet_cb)(struct mesh_io_private *pvt, int8_t rssi,
					uint32_t instant,
					const uint8_t *data, uint8_t len);

typedef bool (*send_data_cb)(struct mesh_io_private *pvt, uint32_t instant,
					const uint8_t *data, size_t len);

void silvair_process_packet(struct mesh_io *io, uint8_t *buf, size_t size,
					uint32_t instant, process_packet_cb cb);

void silvair_process_slip(struct mesh_io *io, struct slip *slip,
					uint8_t *buf, size_t size,
					uint32_t instant, process_packet_cb cb);

bool silvair_send_packet(struct mesh_io *io, uint8_t *buf, size_t size,
					uint32_t instant, send_data_cb cb,
					enum packet_type type);

bool silvair_send_slip(struct mesh_io *io, uint8_t *buf, size_t size,
					uint32_t instant, send_data_cb cb,
					enum packet_type type);
