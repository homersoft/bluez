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
#include <termios.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/limits.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <ell/ell.h>

#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"
#include "mesh/mesh-io-uart.h"
#include "mesh/silvair-io.h"


struct mesh_io_private {
	char			tty_name[PATH_MAX];
	int			tty_fd;

	char			iface_name[IFNAMSIZ];
	int			iface_fd;

	struct silvair_io	*silvair_io;
	struct l_timeout	*tx_timeout;
	struct l_queue		*rx_regs;
	struct l_queue		*tx_pkts;

	/* Simple filtering on AD type only */
	uint8_t			filters[3];
	struct tx_pkt		*tx;
};

struct pvt_rx_reg {
	uint8_t			filter_id;
	mesh_io_recv_func_t	cb;
	void			*user_data;
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
	const uint8_t	*data;
	uint8_t		len;
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

	struct process_data rx = {
		.pvt = mesh_io->pvt,
		.data = data,
		.len = len,
		.info.instant = get_instant(),
		.info.chan = 7,
		.info.rssi = rssi,
	};

	if (!mesh_io) {
		l_error("mesh_io does not exist");
		return;
	}

	silvair_io_kepp_alive_wdt_refresh(silvair_io);
	l_queue_foreach(mesh_io->pvt->rx_regs, process_rx_callbacks, &rx);
}

static void io_read_callback_destroy(void *user_data)
{
	struct silvair_io *silvair_io = user_data;

	l_info("Disconnecting the UART client");
	close(l_io_get_fd(silvair_io->l_io));
}

static void io_disconnect_callback(void *user_data)
{
	struct silvair_io *silvair_io = user_data;

	(void)silvair_io;
	l_info("USB cable disconnected !");
}

static bool uart_kernel_init(struct mesh_io *mesh_io)
{
	struct ifreq req;
	struct sockaddr_ll addr;
	int disc = N_SLIP;
	int encap = 0;

	if (ioctl(mesh_io->pvt->tty_fd, TIOCSETD, &disc) != 0) {
		l_error("cannot set line discipline: %s", strerror(errno));
		return false;
	}

	if (ioctl(mesh_io->pvt->tty_fd, SIOCSIFENCAP, &encap) != 0) {
		l_error("cannot set encapsulation: %s", strerror(errno));
		return false;
	}

	if (ioctl(mesh_io->pvt->tty_fd, SIOCGIFNAME,
				mesh_io->pvt->iface_name) != 0)
		return false;

	l_strlcpy(req.ifr_name, mesh_io->pvt->iface_name, sizeof(req.ifr_name));

	mesh_io->pvt->iface_fd = socket(PF_PACKET, SOCK_RAW, 0);

	if (mesh_io->pvt->iface_fd < 0) {
		l_error("%s: cannot open socket: %s",
			mesh_io->pvt->iface_name, strerror(errno));
		return false;
	}

	if (ioctl(mesh_io->pvt->iface_fd, SIOCGIFINDEX, &req) != 0) {
		l_error("%s: cannot get interface index: %s",
			mesh_io->pvt->iface_name, strerror(errno));
		return false;
	}

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = req.ifr_ifindex;
	addr.sll_pkttype = PACKET_HOST;

	req.ifr_flags |= IFF_UP;

	if (ioctl(mesh_io->pvt->iface_fd, SIOCSIFFLAGS, &req) != 0) {
		l_error("%s: cannot bring interface up: %s",
			mesh_io->pvt->iface_name, strerror(errno));
		return false;
	}

	if (bind(mesh_io->pvt->iface_fd, (struct sockaddr *)&addr,
							sizeof(addr)) != 0) {
		l_error("%s: cannot bind interface: %s",
			mesh_io->pvt->iface_name, strerror(errno));
		return false;
	}

	l_info("Started mesh on tty %s, interface %s", mesh_io->pvt->tty_name,
		mesh_io->pvt->iface_name);

	mesh_io->pvt->silvair_io = silvair_io_new(mesh_io->pvt->iface_fd,
						keep_alive_error,
						true,
						process_rx,
						mesh_io,
						io_read_callback_destroy,
						io_disconnect_callback);
	return true;
}

static bool uart_user_init(struct mesh_io *mesh_io)
{
	mesh_io->pvt->silvair_io = silvair_io_new(mesh_io->pvt->tty_fd,
						keep_alive_error,
						false,
						process_rx,
						mesh_io,
						io_read_callback_destroy,
						io_disconnect_callback);
	mesh_io->pvt->iface_fd = -1;

	l_info("Started mesh on tty %s", mesh_io->pvt->tty_name);
	return true;
}

static bool uart_tty_init(struct mesh_io *mesh_io, bool flow)
{
	struct termios ttys;

	mesh_io->pvt->tty_fd = open(mesh_io->pvt->tty_name, O_RDWR);

	if (mesh_io->pvt->tty_fd < 0) {
		l_error("%s: cannot open: %s", mesh_io->pvt->tty_name,
							strerror(errno));
		return false;
	}

	cfmakeraw(&ttys);
	cfsetspeed(&ttys, B1000000);

	if (flow)
		ttys.c_cflag |= CRTSCTS;
	else
		ttys.c_cflag &= ~CRTSCTS;

	if (tcsetattr(mesh_io->pvt->tty_fd, TCSANOW, &ttys) != 0) {
		l_error("%s: cannot configure tty: %s",
			mesh_io->pvt->tty_name, strerror(errno));
		return false;
	}

	return true;
}

static bool uart_io_init(struct mesh_io *mesh_io, void *opts)
{
	bool tty_kernel = false;
	bool tty_flow = false;

	char *opts_delim = strchr(opts, ':');
	char *opt;
	char *delim;

	if (opts_delim) {
		*opts_delim = '\0';
		opt = opts_delim + 1;

		if (!*opt) {
			l_error("missing options");
			return false;
		}

		do {
			delim = strchr(opt, ',');

			if (delim)
				*delim = '\0';

			if (!strcmp(opt, "kernel"))
				tty_kernel = true;

			if (!strcmp(opt, "nokernel"))
				tty_kernel = false;

			if (!strcmp(opt, "flow"))
				tty_flow = true;

			if (!strcmp(opt, "noflow"))
				tty_flow = false;

			opt = delim + 1;

		} while (delim);
	}

	if (!mesh_io || mesh_io->pvt)
		return false;

	mesh_io->pvt = l_new(struct mesh_io_private, 1);

	strncpy(mesh_io->pvt->tty_name, opts,
		sizeof(mesh_io->pvt->tty_name) - 1);

	l_debug("%s: flow control %s, slip in %s",
		mesh_io->pvt->tty_name, tty_flow ? "on" : "off",
		tty_kernel ? "kernel" : "userspace");

	if (!uart_tty_init(mesh_io, tty_flow)) {
		l_error("tty initialization failed");
		return false;
	}

	if (!(tty_kernel ? uart_kernel_init : uart_user_init)(mesh_io)) {
		l_error("initialization failed");
		return false;
	}

	mesh_io->pvt->rx_regs = l_queue_new();
	mesh_io->pvt->tx_pkts = l_queue_new();

	mesh_io->pvt->tx_timeout = l_timeout_create_ms(0, send_timeout,
					mesh_io, NULL);

	/* Send keep alive request */
	silvair_process_tx(mesh_io->pvt->silvair_io, NULL, 0,
						PACKET_TYPE_KEEP_ALIVE);

	return true;
}

static bool uart_io_destroy(struct mesh_io *mesh_io)
{
	struct mesh_io_private *pvt = mesh_io->pvt;
	struct silvair_io *silvair_io = mesh_io->pvt->silvair_io;

	if (!pvt)
		return true;

	if (silvair_io) {
		l_io_destroy(silvair_io->l_io);
		l_timeout_remove(silvair_io->keep_alive_watchdog);
		l_free(silvair_io);
	}

	close(pvt->iface_fd);
	close(pvt->tty_fd);
	l_timeout_remove(pvt->tx_timeout);
	l_queue_destroy(pvt->rx_regs, l_free);
	l_queue_destroy(pvt->tx_pkts, l_free);
	l_free(pvt);

	return true;
}

static bool uart_io_caps(struct mesh_io *mesh_io, struct mesh_io_caps *caps)
{
	struct mesh_io_private *pvt = mesh_io->pvt;

	if (!pvt || !caps)
		return false;

	caps->max_num_filters = sizeof(pvt->filters);
	caps->window_accuracy = 50;

	return true;
}

static void send_flush(struct mesh_io *mesh_io)
{
	struct tx_pkt *tx;
	uint32_t instant = get_instant();
	struct silvair_io *silvair_io = mesh_io->pvt->silvair_io;

	do {
		tx = l_queue_peek_head(mesh_io->pvt->tx_pkts);

		if (!tx || tx->instant > instant)
			break;

		silvair_process_tx(silvair_io, tx->data, tx->len,
							PACKET_TYPE_MESSAGE);

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
	(void)timeout;
	(void)user_data;
	l_error("USB cable disconnected !");
}

static int compare_tx_pkt_instant(const void *a, const void *b, void *user_data)
{
	const struct tx_pkt *lhs = a;
	const struct tx_pkt *rhs = b;
	(void)user_data;

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

static bool uart_io_send(struct mesh_io *mesh_io,
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

static bool uart_io_reg(struct mesh_io *mesh_io, uint8_t filter_id,
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

static bool uart_io_dereg(struct mesh_io *mesh_io, uint8_t filter_id)
{
	struct mesh_io_private *pvt = mesh_io->pvt;
	struct pvt_rx_reg *rx_reg;

	rx_reg = l_queue_remove_if(pvt->rx_regs, find_by_filter_id,
						L_UINT_TO_PTR(filter_id));

	if (rx_reg)
		l_free(rx_reg);

	return true;
}

static bool uart_io_set(struct mesh_io *mesh_io,
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

static bool uart_io_cancel(struct mesh_io *mesh_io,
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
		tx = l_queue_remove_if(pvt->tx_pkts, find_by_pattern, &pattern);
		l_free(tx);
	} while (tx);

	tx = l_queue_peek_head(pvt->tx_pkts);

	if (tx)
		l_timeout_modify_ms(pvt->tx_timeout,
						tx->instant - get_instant());
	return true;
}

const struct mesh_io_api mesh_io_uart = {
	.init = uart_io_init,
	.destroy = uart_io_destroy,
	.caps = uart_io_caps,
	.send = uart_io_send,
	.reg = uart_io_reg,
	.dereg = uart_io_dereg,
	.set = uart_io_set,
	.cancel = uart_io_cancel,
};
