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
#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <arpa/inet.h>
#include <linux/tty.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/limits.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <ell/ell.h>

#include <stdio.h>

#include "src/shared/io.h"

#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"
#include "mesh/mesh-io-tcpserver.h"
#include "mesh/silvair-io.h"

struct mesh_io_private {
	struct sockaddr_in server_addr;
	struct io *server_io;

	struct sockaddr_in client_addr;
	struct io *client_io;

	struct l_timeout *tx_timeout;
	struct l_timeout *keep_alive_timeout;
	struct l_queue *rx_regs;
	struct l_queue *tx_pkts;
	uint8_t filters[3]; /* Simple filtering on AD type only */
	struct tx_pkt *tx;

	struct slip slip;
};

struct pvt_rx_reg {
	uint8_t filter_id;
	mesh_io_recv_func_t cb;
	void *user_data;
};

struct process_data {
	struct mesh_io_private		*pvt;
	const uint8_t			*data;
	uint8_t				len;
	struct mesh_io_recv_info	info;
};

struct tx_pkt {
	uint32_t	instant;
	uint8_t		len;
	uint8_t		data[30];
};

struct tx_pattern {
	const uint8_t			*data;
	uint8_t				len;
};

static void process_rx(struct mesh_io *io, int8_t rssi,
					uint32_t instant,
					const uint8_t *data, uint8_t len);

static const struct rx_process_cb rx_cbk = {
	.process_packet_cb = process_rx,
	.process_keep_alive_cb = NULL,
};

static uint32_t get_instant(void)
{
	struct timeval tm;
	uint32_t instant;

	gettimeofday(&tm, NULL);
	instant = tm.tv_sec * 1000;
	instant += tm.tv_usec / 1000;

	return instant;
}

static void process_rx_callbacks(void *v_rx, void *v_reg)
{
	struct pvt_rx_reg *rx_reg = v_rx;
	struct process_data *rx = v_reg;
	uint8_t ad_type;

	ad_type = rx->pvt->filters[rx_reg->filter_id - 1];

	if (rx->data[0] == ad_type && rx_reg->cb)
		rx_reg->cb(rx_reg->user_data, &rx->info, rx->data, rx->len);
}

static void process_rx(struct mesh_io *io, int8_t rssi,
					uint32_t instant,
					const uint8_t *data, uint8_t len)
{
	struct process_data rx = {
		.pvt = io->pvt,
		.data = data,
		.len = len,
		.info.instant = instant,
		.info.chan = 7,
		.info.rssi = rssi,
	};

	l_queue_foreach(io->pvt->rx_regs, process_rx_callbacks, &rx);
}

static bool io_read_callback(struct io *io, void *user_data)
{
	struct mesh_io *mesh_io = user_data;
	uint8_t buf[512];
	uint32_t instant;
	int r;
	int fd;

	fd = io_get_fd(mesh_io->pvt->client_io);
	if (fd < 0)
		return false;

	r = read(fd, buf, sizeof(buf));

	if (r <= 0) {
		l_info("Disconnected %s:%hu",
				inet_ntoa(mesh_io->pvt->client_addr.sin_addr),
				ntohs(mesh_io->pvt->client_addr.sin_port));
		mesh_io->pvt->client_io = NULL;
		return false;
	}

	instant = get_instant();

	silvair_process_slip(mesh_io, &mesh_io->pvt->slip, buf, r, instant,
						&rx_cbk);

	return true;
}

static bool io_accept_callback(struct io *io, void *user_data)
{
	struct mesh_io *mesh_io = user_data;
	int server_fd;
	int client_fd;
	struct sockaddr_in client_addr;
	socklen_t client_addrlen = sizeof(client_addr);

	server_fd = io_get_fd(mesh_io->pvt->server_io);
	if (server_fd < 0)
		return false;

	client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
							&client_addrlen);

	if (mesh_io->pvt->client_io) {
		l_info("Dropped %s:%hu",
				inet_ntoa(client_addr.sin_addr),
				ntohs(client_addr.sin_port));

		close(client_fd);
		return true;
	}

	if (client_fd < 0)
		return false;

	fcntl(client_fd, F_SETFL, fcntl(client_fd, F_GETFL, 0) | O_NONBLOCK);

	memcpy(&mesh_io->pvt->client_addr, &client_addr, sizeof(client_addr));

	mesh_io->pvt->client_io = io_new(client_fd);
	io_set_close_on_destroy(mesh_io->pvt->client_io, true);
	io_set_read_handler(mesh_io->pvt->client_io, io_read_callback, mesh_io,
									NULL);

	l_info("Connected %s:%hu",
				inet_ntoa(mesh_io->pvt->client_addr.sin_addr),
				ntohs(mesh_io->pvt->client_addr.sin_port));

	return true;
}

static void send_timeout(struct l_timeout *timeout, void *user_data);
static void send_keep_alive(struct l_timeout *timeout, void *user_data);

static bool tcpserver_io_init(struct mesh_io *mesh_io, void *opts)
{
	int server_fd;
	uint16_t port = 0;

	char *opt = opts;
	char *delim;

	do {
		delim = strchr(opt, ':');

		if (delim)
			*delim = '\0';

		if (sscanf(opt, "%hu", &port) != 1)
			return false;

		opt = delim + 1;

	} while (delim);

	if (!mesh_io || mesh_io->pvt)
		return false;

	if (!port)
		return false;

	mesh_io->pvt = l_new(struct mesh_io_private, 1);

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_NONBLOCK);
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 },
								sizeof(int));
	mesh_io->pvt->server_addr.sin_addr.s_addr = INADDR_ANY;
	mesh_io->pvt->server_addr.sin_port = htons(port);
	if (bind(server_fd, (struct sockaddr *)&mesh_io->pvt->server_addr,
				sizeof(mesh_io->pvt->server_addr)) < 0) {
		l_error("Failed to start mesh io (bind): %s",
							strerror(errno));
		return false;
	}

	if (listen(server_fd, 1) < 0) {
		l_error("Failed to start mesh io (listen): %s",
							strerror(errno));
		return false;
	}

	mesh_io->pvt->server_io = io_new(server_fd);

	mesh_io->pvt->rx_regs = l_queue_new();
	mesh_io->pvt->tx_pkts = l_queue_new();

	if (!io_set_read_handler(mesh_io->pvt->server_io, io_accept_callback,
								mesh_io, NULL))
		return false;

	mesh_io->pvt->tx_timeout = l_timeout_create_ms(0, send_timeout,
							mesh_io, NULL);

	mesh_io->pvt->keep_alive_timeout = l_timeout_create(10, send_keep_alive,
							mesh_io, NULL);

	l_info("Started mesh on tcp port %d", port);

	return true;
}

static bool tcpserver_io_destroy(struct mesh_io *mesh_io)
{
	struct mesh_io_private *pvt = mesh_io->pvt;

	if (!pvt)
		return true;

	io_destroy(pvt->server_io);
	io_destroy(pvt->client_io);

	l_timeout_remove(pvt->tx_timeout);
	l_timeout_remove(pvt->keep_alive_timeout);
	l_queue_destroy(pvt->rx_regs, l_free);
	l_queue_destroy(pvt->tx_pkts, l_free);
	l_free(pvt);
	mesh_io->pvt = NULL;

	return true;
}

static bool tcpserver_io_caps(struct mesh_io *mesh_io,
						struct mesh_io_caps *caps)
{
	struct mesh_io_private *pvt = mesh_io->pvt;

	if (!pvt || !caps)
		return false;

	caps->max_num_filters = sizeof(pvt->filters);
	caps->window_accuracy = 50;

	return true;
}

static bool client_write(struct mesh_io_private *pvt, uint32_t instant,
					const uint8_t *buf, size_t size)
{
	int fd = io_get_fd(pvt->client_io);
	int w = write(fd, buf, size);

	return (w > 0 && (size_t)w == size);
}

static void send_flush(struct mesh_io *mesh_io)
{
	struct tx_pkt *tx;
	uint32_t instant = get_instant();

	do {
		tx = l_queue_peek_head(mesh_io->pvt->tx_pkts);

		if (!tx || tx->instant > instant)
			break;

		if (!silvair_send_slip(mesh_io, tx->data, tx->len, tx->instant,
					client_write, PACKET_TYPE_MESSAGE)) {
			l_error("write failed: %s", strerror(errno));
			close(io_get_fd(mesh_io->pvt->client_io));
			mesh_io->pvt->client_io = NULL;
			return;
		}

		tx = l_queue_pop_head(mesh_io->pvt->tx_pkts);
		l_free(tx);
	} while (tx);

	if (tx)
		l_timeout_modify_ms(mesh_io->pvt->tx_timeout,
							tx->instant - instant);
}

static void send_timeout(struct l_timeout *timeout, void *user_data)
{
	struct mesh_io *mesh_io = user_data;

	if (!mesh_io)
		return;

	send_flush(mesh_io);
}

static void send_keep_alive(struct l_timeout *timeout, void *user_data)
{
	int fd;
	struct mesh_io *io = user_data;

	if (!io)
		return;

	fd = io_get_fd(io->pvt->client_io);

	if (fd < 0)
		return;

	silvair_send_slip(io, NULL, 0, get_instant(),
		client_write, PACKET_TYPE_KEEP_ALIVE);
	l_timeout_modify(timeout, 10);
}

static int compare_tx_pkt_instant(const void *a, const void *b,
							void *user_data)
{
	const struct tx_pkt *lhs = a;
	const struct tx_pkt *rhs = b;

	if (lhs->instant == rhs->instant)
		return 0;

	return lhs->instant < rhs->instant ? -1 : 1;
}

static void send_pkt(struct mesh_io *mesh_io,
			const uint8_t *data, uint16_t len, uint32_t instant)
{
	struct tx_pkt *tx = l_new(struct tx_pkt, 1);

	tx->instant = instant;
	tx->len = len;
	memcpy(tx->data, data, len);

	l_queue_insert(mesh_io->pvt->tx_pkts, tx, compare_tx_pkt_instant, NULL);

	send_flush(mesh_io);
}

static bool tcpserver_io_send(struct mesh_io *mesh_io,
					struct mesh_io_send_info *info,
					const uint8_t *data, uint16_t len)
{
	uint32_t instant;
	uint16_t interval;
	uint8_t delay;
	int i;

	if (!info || !data || !len)
		return false;

	switch (info->type) {
	case MESH_IO_TIMING_TYPE_GENERAL:
		instant = get_instant();
		interval = info->u.gen.interval;

		if (info->u.gen.min_delay == info->u.gen.max_delay)
			delay = info->u.gen.min_delay;
		else {
			l_getrandom(&delay, sizeof(delay));
			delay %= info->u.gen.max_delay - info->u.gen.min_delay;
			delay += info->u.gen.min_delay;
		}

		for (i = 0; i < info->u.gen.cnt; ++i)
			send_pkt(mesh_io, data, len,
					instant + delay + interval * i);
		break;
	case MESH_IO_TIMING_TYPE_POLL:
		instant = get_instant();

		if (info->u.gen.min_delay == info->u.gen.max_delay)
			delay = info->u.gen.min_delay;
		else {
			l_getrandom(&delay, sizeof(delay));
			delay %= info->u.gen.max_delay - info->u.gen.min_delay;
			delay += info->u.gen.min_delay;
		}

		send_pkt(mesh_io, data, len, instant + delay);
		break;

	case MESH_IO_TIMING_TYPE_POLL_RSP:
		instant = info->u.poll_rsp.instant;
		delay = info->u.poll_rsp.delay;

		send_pkt(mesh_io, data, len, instant + delay);
		break;
	}

	return true;
}

static bool find_by_filter_id(const void *a, const void *b)
{
	const struct pvt_rx_reg *rx_reg = a;
	uint8_t filter_id = L_PTR_TO_UINT(b);

	return rx_reg->filter_id == filter_id;
}

static bool tcpserver_io_reg(struct mesh_io *mesh_io, uint8_t filter_id,
				mesh_io_recv_func_t cb, void *user_data)
{
	struct mesh_io_private *pvt = mesh_io->pvt;
	struct pvt_rx_reg *rx_reg;

	l_info("%s %d", __func__, filter_id);
	if (!cb || !filter_id || filter_id > sizeof(pvt->filters))
		return false;

	rx_reg = l_queue_remove_if(pvt->rx_regs, find_by_filter_id,
						L_UINT_TO_PTR(filter_id));

	if (!rx_reg) {
		rx_reg = l_new(struct pvt_rx_reg, 1);
		if (!rx_reg)
			return false;
	}

	rx_reg->filter_id = filter_id;
	rx_reg->cb = cb;
	rx_reg->user_data = user_data;

	l_queue_push_head(pvt->rx_regs, rx_reg);

	return true;
}

static bool tcpserver_io_dereg(struct mesh_io *mesh_io, uint8_t filter_id)
{
	struct mesh_io_private *pvt = mesh_io->pvt;

	struct pvt_rx_reg *rx_reg;

	rx_reg = l_queue_remove_if(pvt->rx_regs, find_by_filter_id,
						L_UINT_TO_PTR(filter_id));

	if (rx_reg)
		l_free(rx_reg);

	return true;
}

static bool tcpserver_io_set(struct mesh_io *mesh_io,
		uint8_t filter_id, const uint8_t *data, uint8_t len,
		mesh_io_status_func_t callback, void *user_data)
{
	struct mesh_io_private *pvt = mesh_io->pvt;

	l_info("%s id: %d, --> %2.2x", __func__, filter_id, data[0]);
	if (!data || !len || !filter_id || filter_id > sizeof(pvt->filters))
		return false;

	pvt->filters[filter_id - 1] = data[0];

	/* TODO: Delayed Call to successful status */

	return true;
}

static bool find_by_pattern(const void *a, const void *b)
{
	const struct tx_pkt *tx = a;
	const struct tx_pattern *pattern = b;

	if (tx->len < pattern->len)
		return false;

	return (!memcmp(tx->data, pattern->data, pattern->len));
}

static bool tcpserver_io_cancel(struct mesh_io *mesh_io, const uint8_t *data,
								uint8_t len)
{
	struct mesh_io_private *pvt = mesh_io->pvt;
	struct tx_pkt *tx;
	const struct tx_pattern pattern = {
		.data = data,
		.len = len
	};

	if (!data)
		return false;

	do {
		tx = l_queue_remove_if(pvt->tx_pkts, find_by_pattern,
							&pattern);
		l_free(tx);
	} while (tx);

	tx = l_queue_peek_head(pvt->tx_pkts);

	if (tx)
		l_timeout_modify_ms(pvt->tx_timeout,
						tx->instant - get_instant());

	return true;
}

const struct mesh_io_api mesh_io_tcpserver = {
	.init = tcpserver_io_init,
	.destroy = tcpserver_io_destroy,
	.caps = tcpserver_io_caps,
	.send = tcpserver_io_send,
	.reg = tcpserver_io_reg,
	.dereg = tcpserver_io_dereg,
	.set = tcpserver_io_set,
	.cancel = tcpserver_io_cancel,
};
