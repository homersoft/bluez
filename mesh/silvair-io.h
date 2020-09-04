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

#include <openssl/ssl.h>

struct silvair_io;
struct l_io;
struct l_timeout;

typedef void (*process_packet_cb)(struct silvair_io *io,
				  int8_t rssi,
				  const uint8_t *data,
				  uint8_t len,
				  void *user_data);

typedef void (*keep_alive_tmout_cb)(struct l_timeout *timeout, void *user_data);
typedef void (*io_disconnect_cb)(struct silvair_io *io);
typedef void (*io_error_cb)(struct silvair_io *io);

struct slip {
	uint8_t	buf[512];
	size_t	offset;
	bool	esc;
	bool	kernel_support;
};

struct silvair_io {
	uint8_t                 nid_filter[16];

	struct l_io		*l_io;
	struct l_ringbuf	*out_ringbuf;

	struct l_timeout	*keep_alive_watchdog;
	struct l_timeout	*disconnect_watchdog;

	io_disconnect_cb	disconnect_cb;
	io_error_cb		error_cb;

	struct slip		slip;
	process_packet_cb	process_rx_cb;
	void *context;

	SSL                     *tls_conn;
	bool                    tls_read_wants_write;
	bool                    tls_write_wants_read;
};

struct silvair_io *silvair_io_new(int fd,
				bool kernel_support,
				process_packet_cb rx_cb,
				io_error_cb read_failed_cb,
				io_disconnect_cb disc_cb,
				void *context,
				SSL *tls_conn);

int silvair_io_get_fd(struct silvair_io *io);

void silvair_io_destroy(struct silvair_io *io);

void silvair_io_keep_alive_wdt_refresh(struct silvair_io *io);

void silvair_io_send_message(struct silvair_io *io, uint8_t *buf, size_t size);

void silvair_io_close(struct silvair_io *io);

void silvair_io_nid_filter_nid_set(struct silvair_io *io, uint8_t nid);

void silvair_io_nid_filter_send(struct silvair_io *io);
