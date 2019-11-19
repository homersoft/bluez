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
#include <ell/ell.h>

struct silvair_io;

typedef void (*process_packet_cb)(struct silvair_io *io,
				  int8_t rssi,
				  const uint8_t *data,
				  uint8_t len,
				  void *user_data);

typedef void (*keep_alive_tmout_cb)(struct l_timeout *timeout, void *user_data);
typedef void (*io_disconnect_cb)(struct silvair_io *io);
typedef void (*io_read_failed_cb)(struct silvair_io *io);

struct slip {
	uint8_t	buf[512];
	size_t	offset;
	bool	esc;
	bool	kernel_support;
};

struct silvair_io {
	struct l_io		*l_io;

	struct l_timeout	*keep_alive_watchdog;
	keep_alive_tmout_cb	keep_alived_disconnect_cb;
	struct l_timeout	*disconnect_tmr;

	io_disconnect_cb	_disconnect_cb;
	io_read_failed_cb	_read_destroy_cb;

	struct slip		slip;
	process_packet_cb	process_rx_cb;
	void *context;
};

enum packet_type {
	PACKET_TYPE_MESSAGE,
	PACKET_TYPE_KEEP_ALIVE,
};

struct silvair_io *silvair_io_new(int fd,
				keep_alive_tmout_cb tmout_cb,
				bool kernel_support,
				process_packet_cb rx_cb,
				void *context,
				io_read_failed_cb read_fail_cb,
				io_disconnect_cb disc_cb);

int silvair_io_get_fd(struct silvair_io *io);

void silvair_io_destroy(struct silvair_io *io);

void silvair_io_keep_alive_wdt_refresh(struct silvair_io *io);

void silvair_io_process_tx(struct silvair_io *io,
			uint8_t *buf,
			size_t size,
			enum packet_type type);
