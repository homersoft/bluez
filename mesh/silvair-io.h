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

struct slip {
	uint8_t	buf[512];
	size_t	offset;
	bool	esc;
	bool	kernel_support;
};

struct silvair_io {
	struct l_io		*l_io;
	struct l_timeout	*keep_alive_watchdog;
	struct slip		slip;
	void *context;
};

enum packet_type {
	PACKET_TYPE_MESSAGE,
	PACKET_TYPE_KEEP_ALIVE,
};

struct rx_process_cb {

	void (*process_packet_cb)(struct silvair_io *io,
				int8_t rssi,
				uint32_t instant,
				const uint8_t *data,
				uint8_t len,
				void *user_data);

	void (*process_keep_alive_cb)(struct silvair_io *io);
};

typedef bool (*send_data_cb)(struct silvair_io *io,
				uint32_t instant,
				const uint8_t *data,
				size_t len);

typedef void (*keep_alive_tmout_cb)(struct l_timeout *timeout, void *user_data);

struct silvair_io *silvair_io_new(int fd,
				keep_alive_tmout_cb tmout_cb,
				bool kernel_support,
				void *context);

void silvair_io_kepp_alive_wdt_refresh(struct silvair_io *io);

void silvair_process_rx(struct silvair_io *io,
			uint8_t *buf,
			size_t size,
			uint32_t instant,
			const struct rx_process_cb *cb,
			void *user_data);

void silvair_process_tx(struct silvair_io *io,
			uint8_t *buf,
			size_t size,
			uint32_t instant,
			send_data_cb cb,
			enum packet_type type);
