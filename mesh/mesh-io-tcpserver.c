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
#include <stdlib.h>
#include <stdio.h>

#include "src/shared/io.h"

#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"
#include "mesh/mesh-io-tcpserver.h"
#include "mesh/silvair-io.h"


struct mesh_io_private {
	struct l_io		*server_io;
	struct l_queue		*client_io;

	struct l_timeout	*tx_timeout;
	struct l_queue		*rx_regs;
	struct l_queue		*tx_pkts;

	/* Simple filtering on AD type only */
	uint8_t			filters[3];
	struct tx_pkt		*tx;
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

enum io_type {
	IO_TYPE_SERVER,
	IO_TYPE_CLIENT
};

static void send_timeout(struct l_timeout *timeout, void *user_data);
static void keep_alive_error(struct l_timeout *timeout, void *user_data);


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

static void process_rx(struct silvair_io *silvair_io, int8_t rssi,
			const uint8_t *data, uint8_t len, void *user_data)
{
	struct mesh_io *mesh_io = user_data;
	struct process_data rx;

	if (!mesh_io) {
		l_error("mesh_io does not exist");
		return;
	}

	rx.pvt = mesh_io->pvt,
	rx.data = data,
	rx.len = len,
	rx.info.instant = get_instant(),
	rx.info.chan = 7,
	rx.info.rssi = rssi,

	silvair_io_keep_alive_wdt_refresh(silvair_io);
	l_queue_foreach(mesh_io->pvt->rx_regs, process_rx_callbacks, &rx);
}

static bool get_fd_info(int fd, char *log, enum io_type type)
{
	/* Address */
	struct sockaddr_in addr;
	unsigned int addrlen;

	addrlen = sizeof(addr);

	switch (type) {
	case IO_TYPE_CLIENT:
		if (getpeername(fd, (struct sockaddr *)&addr, &addrlen) < 0) {
			l_error("getpeername() error");
			return false;
		}
		break;

	case IO_TYPE_SERVER:
		if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) < 0) {
			l_error("getsockname() error");
			return false;
		}
		break;

	default:
		l_error("get_df_info() Invalid type");
		return false;
	}

	l_info("%s -> addr:%s port:%d fd:%d", log,
			inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), fd);
	return true;
}

static void io_read_callback_destroy(struct silvair_io *silvair_io)
{
	int fd = silvair_io_get_fd(silvair_io);

	get_fd_info(fd, "Disconnecting the TCP client", IO_TYPE_CLIENT);

	/* shutdown will trigger the io_disconnect_callback() */
	shutdown(fd, SHUT_RDWR);
}

static void io_disconnect_callback(struct silvair_io *silvair_io)
{
	struct mesh_io *mesh_io = silvair_io->context;

	if (!mesh_io->pvt->client_io)
		return;

	if (!l_queue_remove(mesh_io->pvt->client_io, silvair_io)) {
		perror("l_queue_remove() error");
		abort();
	}

	l_info("Client disconneted from TCP Server");
	silvair_io_destroy(silvair_io);
}

static bool io_accept_callback(struct l_io *l_io, void *user_data)
{
	struct mesh_io *mesh_io = user_data;
	struct silvair_io *silvair_io = NULL;

	/* Client address */
	struct sockaddr_in clientaddr;
	unsigned int client_addrlen;

	/* Newly accepted socket descriptor */
	int newfd;

	/* Listening socket descriptor */
	int server_fd;

	server_fd = l_io_get_fd(l_io);

	if (server_fd < 0) {
		l_error("l_io_get_fd error");
		return false;
	}

	/* Handle new connections */
	client_addrlen = sizeof(clientaddr);

	newfd = accept(server_fd, (struct sockaddr *)&clientaddr,
							&client_addrlen);

	if (newfd < 0) {
		l_error("server accept error");
		return false;
	}

	if (fcntl(newfd, F_SETFL,
			fcntl(newfd, F_GETFL, 0) | O_NONBLOCK) != 0) {
		l_error("client fcntl error");
		return false;
	}

	get_fd_info(newfd, "New client accepted", IO_TYPE_CLIENT);

	silvair_io = silvair_io_new(newfd, keep_alive_error, false, process_rx,
					mesh_io, io_read_callback_destroy,
					io_disconnect_callback);

	if (!silvair_io) {
		l_error("silvair_io_new error");
		return false;
	}

	l_io_set_close_on_destroy(silvair_io->l_io, true);

	l_queue_push_tail(mesh_io->pvt->client_io, silvair_io);

	l_info("Connected %s:%hu",
			inet_ntoa(clientaddr.sin_addr),
			ntohs(clientaddr.sin_port));

	return true;
}

static bool tcpserver_io_init(struct mesh_io *mesh_io, void *opts)
{
	/* Listening socket descriptor */
	int server_fd;
	uint16_t port = 0;

	/* Server address */
	struct sockaddr_in serveraddr;

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

	/* Get the listener */
	server_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (server_fd < 0) {
		l_error("socket() error");
		return false;
	}

	if (fcntl(server_fd, F_SETFL,
		fcntl(server_fd, F_GETFL, 0) | O_NONBLOCK) != 0) {

		l_error("fcntl() error");
		return false;
	}

	if (setsockopt(server_fd, SOL_SOCKET,
				SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {

		l_error("setsockopt() error");
		return false;
	}

	/* Bind */
	serveraddr.sin_addr.s_addr = INADDR_ANY;
	serveraddr.sin_port = htons(port);
	serveraddr.sin_family = AF_INET;

	if (bind(server_fd, (struct sockaddr *)&serveraddr,
						sizeof(serveraddr)) < 0) {

		l_error("Failed to start mesh io (bind): %s", strerror(errno));
		return false;
	}

	get_fd_info(server_fd, "Server bind", IO_TYPE_SERVER);

	if (listen(server_fd, 1) < 0) {
		l_error("Failed to start mesh io (listen): %s",
							strerror(errno));
		return false;
	}

	mesh_io->pvt->server_io = l_io_new(server_fd);
	mesh_io->pvt->client_io = l_queue_new();
	mesh_io->pvt->rx_regs = l_queue_new();
	mesh_io->pvt->tx_pkts = l_queue_new();

	if (!l_io_set_read_handler(mesh_io->pvt->server_io,
					io_accept_callback, mesh_io, NULL)) {
		l_error("l_io_set_read_handler error");
		return false;
	}

	mesh_io->pvt->tx_timeout = l_timeout_create_ms(0, send_timeout,
								mesh_io, NULL);

	l_info("Started mesh on tcp port %d", port);
	return true;
}

static bool tcpserver_io_destroy(struct mesh_io *mesh_io)
{
	struct mesh_io_private *pvt = mesh_io->pvt;

	if (!pvt)
		return true;

	l_io_destroy(pvt->server_io);

	if (pvt->client_io != NULL) {
		struct l_queue *queue = pvt->client_io;

		pvt->client_io = NULL;
		l_queue_destroy(queue,
				(l_queue_destroy_func_t) silvair_io_destroy);
	}

	l_queue_destroy(pvt->rx_regs, l_free);
	l_queue_destroy(pvt->tx_pkts, l_free);
	l_timeout_remove(pvt->tx_timeout);

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

static void send_flush_all_clients(void *data, void *user_data)
{
	struct silvair_io *silvair_io = data;
	struct tx_pkt *tx = user_data;

	silvair_io_process_tx(silvair_io, tx->data, tx->len,
							PACKET_TYPE_MESSAGE);
}

static void send_flush(struct mesh_io *mesh_io)
{	struct tx_pkt *tx;
	struct l_queue *client_queue = mesh_io->pvt->client_io;
	uint32_t instant = get_instant();

	do {
		tx = l_queue_peek_head(mesh_io->pvt->tx_pkts);

		if (!tx || tx->instant > instant)
			break;

		l_queue_foreach(client_queue, send_flush_all_clients, tx);
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

static void keep_alive_error(struct l_timeout *timeout, void *user_data)
{
	struct silvair_io *silvair_io = user_data;

	if (!silvair_io)
		return;

	l_error("Keep alive error");

	/* shutdown will trigger the io_disconnect_callback() */
	shutdown(silvair_io_get_fd(silvair_io), SHUT_RDWR);
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

static bool tcpserver_io_cancel(struct mesh_io *mesh_io,
			const uint8_t *data, uint8_t len)
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
