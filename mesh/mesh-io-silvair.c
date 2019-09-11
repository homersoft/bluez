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

#include <stdio.h>

#include "src/shared/io.h"

#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"
#include "mesh/mesh-io-silvair.h"
#include "mesh/silvair-io.h"

const uint8_t KEEP_ALIVE_TMOUT_PERIOD = 10;
const uint8_t KEEP_ALIVE_WATCHDOG_PERIOD = 2 * KEEP_ALIVE_TMOUT_PERIOD;

struct mesh_io_private {
	char tty_name[PATH_MAX];
	int tty_fd;

	char iface_name[IFNAMSIZ];
	int iface_fd;

	struct io *io;

	struct l_timeout *tx_timeout;
	struct l_timeout *keep_alive_timeout;
	struct l_timeout *keep_alive_watchdog;
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

static uint32_t get_instant(void)
{
	struct timeval tm;
	uint32_t instant;

	gettimeofday(&tm, NULL);
	instant = tm.tv_sec * 1000;
	instant += tm.tv_usec / 1000;

	return instant;
}

static void send_timeout(struct l_timeout *timeout, void *user_data);
static void send_keep_alive(struct l_timeout *timeout, void *user_data);
static void keep_alive_error(struct l_timeout *timeout, void *user_data);

static void process_rx(struct mesh_io_private *pvt, int8_t rssi,
					uint32_t instant,
					const uint8_t *data, uint8_t len);

static void process_keep_alive_refresh(struct mesh_io *io);

static const struct rx_process_cb rx_cbk = {
	.process_packet_cb = process_rx,
	.process_keep_alive_cb = process_keep_alive_refresh,
};

static void process_rx_callbacks(void *v_rx, void *v_reg)
{
	struct pvt_rx_reg *rx_reg = v_rx;
	struct process_data *rx = v_reg;
	uint8_t ad_type;

	ad_type = rx->pvt->filters[rx_reg->filter_id - 1];

	if (rx->data[0] == ad_type && rx_reg->cb)
		rx_reg->cb(rx_reg->user_data, &rx->info, rx->data, rx->len);
}

static void process_rx(struct mesh_io_private *pvt, int8_t rssi,
					uint32_t instant,
					const uint8_t *data, uint8_t len)
{
	struct process_data rx = {
		.pvt = pvt,
		.data = data,
		.len = len,
		.info.instant = instant,
		.info.chan = 7,
		.info.rssi = rssi,
	};

	l_queue_foreach(pvt->rx_regs, process_rx_callbacks, &rx);
}

static void process_keep_alive_refresh(struct mesh_io *io)
{
	if (!io)
		return;

	l_timeout_modify(io->pvt->keep_alive_watchdog,
					KEEP_ALIVE_WATCHDOG_PERIOD);
}

static bool io_read_callback(struct io *io, void *user_data)
{
	struct mesh_io *mesh_io = user_data;
	uint8_t buf[512];
	uint32_t instant;
	int r;
	int fd;

	fd = io_get_fd(mesh_io->pvt->io);
	if (fd < 0)
		return false;

	r = read(fd, buf, sizeof(buf));

	if (r <= 0)
		return false;


	instant = get_instant();

	if (mesh_io->pvt->iface_fd >= 0)
		silvair_process_packet(mesh_io, buf, r, instant, &rx_cbk);
	else
		silvair_process_slip(mesh_io, &mesh_io->pvt->slip,
						buf, r, instant, &rx_cbk);

	return true;
}

static bool silvair_kernel_init(struct mesh_io *io)
{
	struct ifreq req;
	struct sockaddr_ll addr;
	int disc = N_SLIP;
	int encap = 0;

	if (ioctl(io->pvt->tty_fd, TIOCSETD, &disc) != 0) {
		l_error("cannot set line discipline: %s", strerror(errno));
		return false;
	}

	if (ioctl(io->pvt->tty_fd, SIOCSIFENCAP, &encap) != 0) {
		l_error("cannot set encapsulation: %s", strerror(errno));
		return false;
	}

	if (ioctl(io->pvt->tty_fd, SIOCGIFNAME, io->pvt->iface_name) != 0)
		return false;

	l_strlcpy(req.ifr_name, io->pvt->iface_name, sizeof(req.ifr_name));

	io->pvt->iface_fd = socket(PF_PACKET, SOCK_RAW, 0);

	if (io->pvt->iface_fd < 0) {
		l_error("%s: cannot open socket: %s",
					io->pvt->iface_name, strerror(errno));
		return false;
	}

	if (ioctl(io->pvt->iface_fd, SIOCGIFINDEX, &req) != 0) {
		l_error("%s: cannot get interface index: %s",
					io->pvt->iface_name, strerror(errno));
		return false;
	}

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = req.ifr_ifindex;
	addr.sll_pkttype = PACKET_HOST;

	req.ifr_flags |= IFF_UP;
	if (ioctl(io->pvt->iface_fd, SIOCSIFFLAGS, &req) != 0) {
		l_error("%s: cannot bring interface up: %s",
					io->pvt->iface_name, strerror(errno));
		return false;
	}

	if (bind(io->pvt->iface_fd, (struct sockaddr *)&addr,
							sizeof(addr)) != 0) {
		l_error("%s: cannot bind interface: %s",
					io->pvt->iface_name, strerror(errno));
		return false;
	}

	l_info("Started mesh on tty %s, interface %s", io->pvt->tty_name,
							io->pvt->iface_name);

	io->pvt->io = io_new(io->pvt->iface_fd);

	return true;
}

static bool silvair_user_init(struct mesh_io *io)
{
	io->pvt->io = io_new(io->pvt->tty_fd);
	io->pvt->iface_fd = -1;
	io->pvt->slip.offset = 0;
	io->pvt->slip.esc = false;

	l_info("Started mesh on tty %s", io->pvt->tty_name);

	return true;
}

static bool silvair_tty_init(struct mesh_io *io, bool flow)
{
	struct termios ttys;

	io->pvt->tty_fd = open(io->pvt->tty_name, O_RDWR);

	if (io->pvt->tty_fd < 0) {
		l_error("%s: cannot open: %s", io->pvt->tty_name,
							strerror(errno));
		return false;
	}

	cfmakeraw(&ttys);
	cfsetspeed(&ttys, B1000000);

	if (flow)
		ttys.c_cflag |= CRTSCTS;
	else
		ttys.c_cflag &= ~CRTSCTS;

	if (tcsetattr(io->pvt->tty_fd, TCSANOW, &ttys) != 0) {
		l_error("%s: cannot configure tty: %s", io->pvt->tty_name,
							strerror(errno));
		return false;
	}

	return true;
}

static bool silvair_io_init(struct mesh_io *io, void *opts)
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



	if (!io || io->pvt)
		return false;

	io->pvt = l_new(struct mesh_io_private, 1);
	strncpy(io->pvt->tty_name, opts, sizeof(io->pvt->tty_name) - 1);

	l_debug("%s: flow control %s, slip in %s", io->pvt->tty_name,
					tty_flow ? "on" : "off",
					tty_kernel ? "kernel" : "userspace");

	if (!silvair_tty_init(io, tty_flow)) {
		l_error("tty initialization failed");
		return false;
	}

	if (!(tty_kernel ? silvair_kernel_init : silvair_user_init)(io)) {
		l_error("initialization failed");
		return false;
	}

	io->pvt->rx_regs = l_queue_new();
	io->pvt->tx_pkts = l_queue_new();

	if (!io_set_read_handler(io->pvt->io, io_read_callback, io, NULL))
		return false;

	io->pvt->tx_timeout = l_timeout_create_ms(0, send_timeout, io->pvt,
									NULL);

	io->pvt->keep_alive_timeout = l_timeout_create(KEEP_ALIVE_TMOUT_PERIOD,
		send_keep_alive, io, NULL);

	io->pvt->keep_alive_watchdog =
		l_timeout_create(KEEP_ALIVE_WATCHDOG_PERIOD, keep_alive_error,
			io, NULL);

	return true;
}

static bool silvair_io_destroy(struct mesh_io *io)
{
	struct mesh_io_private *pvt = io->pvt;

	if (!pvt)
		return true;

	close(io->pvt->iface_fd);
	close(io->pvt->tty_fd);
	io_destroy(io->pvt->io);
	l_timeout_remove(pvt->tx_timeout);
	l_timeout_remove(pvt->keep_alive_timeout);
	l_timeout_remove(pvt->keep_alive_watchdog);
	l_queue_destroy(pvt->rx_regs, l_free);
	l_queue_destroy(pvt->tx_pkts, l_free);
	l_free(pvt);
	io->pvt = NULL;

	return true;
}

static bool silvair_io_caps(struct mesh_io *io, struct mesh_io_caps *caps)
{
	struct mesh_io_private *pvt = io->pvt;

	if (!pvt || !caps)
		return false;

	caps->max_num_filters = sizeof(pvt->filters);
	caps->window_accuracy = 50;

	return true;
}

static bool io_write(struct mesh_io_private *pvt, uint32_t instant,
					const uint8_t *buf, size_t size)
{
	int fd = io_get_fd(pvt->io);
	int w = write(fd, buf, size);

	return (w > 0 && (size_t)w == size);
}

static void send_flush(struct mesh_io_private *pvt)
{
	struct tx_pkt *tx;
	uint32_t instant = get_instant();
	struct mesh_io *io = l_container_of(&pvt, struct mesh_io, pvt);

	do {
		tx = l_queue_peek_head(pvt->tx_pkts);

		if (!tx || tx->instant > instant)
			break;

		if (pvt->iface_fd >= 0) {
			if (!silvair_send_packet(io, tx->data, tx->len,
							tx->instant,
							io_write,
							PACKET_TYPE_MESSAGE)) {
				l_error("write failed: %s", strerror(errno));
				return;
			}
		} else {
			if (!silvair_send_slip(io, tx->data, tx->len,
							tx->instant,
							io_write,
							PACKET_TYPE_MESSAGE)) {
				l_error("write failed: %s", strerror(errno));
				return;
			}
		}

		tx = l_queue_pop_head(pvt->tx_pkts);
		l_free(tx);

	} while (tx);

	if (tx)
		l_timeout_modify_ms(pvt->tx_timeout, tx->instant - instant);
}

static void send_timeout(struct l_timeout *timeout, void *user_data)
{
	struct mesh_io_private *pvt = user_data;

	if (!pvt)
		return;

	send_flush(pvt);
}

static void send_keep_alive(struct l_timeout *timeout, void *user_data)
{
	struct mesh_io *io = user_data;

	if (!io)
		return;

	if (io->pvt->iface_fd >= 0)
		silvair_send_packet(io, NULL, 0, get_instant(),
			io_write, PACKET_TYPE_KEEP_ALIVE);
	else
		silvair_send_slip(io, NULL, 0, get_instant(),
			io_write, PACKET_TYPE_KEEP_ALIVE);

	l_timeout_modify(timeout, 10);
}

static void keep_alive_error(struct l_timeout *timeout, void *user_data)
{
	l_error("USB cable disconnected !");

	/* TODO: JWI - perform some action */
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

static void send_pkt(struct mesh_io_private *pvt,
			const uint8_t *data, uint16_t len, uint32_t instant)
{
	struct tx_pkt *tx = l_new(struct tx_pkt, 1);

	tx->instant = instant;
	tx->len = len;
	memcpy(tx->data, data, len);

	l_queue_insert(pvt->tx_pkts, tx, compare_tx_pkt_instant, NULL);

	send_flush(pvt);
}

static bool silvair_io_send(struct mesh_io *io, struct mesh_io_send_info *info,
					const uint8_t *data, uint16_t len)
{
	struct mesh_io_private *pvt = io->pvt;
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
			send_pkt(pvt, data, len,
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

		send_pkt(pvt, data, len, instant + delay);
		break;

	case MESH_IO_TIMING_TYPE_POLL_RSP:
		instant = info->u.poll_rsp.instant;
		delay = info->u.poll_rsp.delay;

		send_pkt(pvt, data, len, instant + delay);
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

static bool silvair_io_reg(struct mesh_io *io, uint8_t filter_id,
				mesh_io_recv_func_t cb, void *user_data)
{
	struct mesh_io_private *pvt = io->pvt;
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

static bool silvair_io_dereg(struct mesh_io *io, uint8_t filter_id)
{
	struct mesh_io_private *pvt = io->pvt;

	struct pvt_rx_reg *rx_reg;

	rx_reg = l_queue_remove_if(pvt->rx_regs, find_by_filter_id,
						L_UINT_TO_PTR(filter_id));

	if (rx_reg)
		l_free(rx_reg);

	return true;
}

static bool silvair_io_set(struct mesh_io *io,
		uint8_t filter_id, const uint8_t *data, uint8_t len,
		mesh_io_status_func_t callback, void *user_data)
{
	struct mesh_io_private *pvt = io->pvt;

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

static bool silvair_io_cancel(struct mesh_io *io, const uint8_t *data,
								uint8_t len)
{
	struct mesh_io_private *pvt = io->pvt;
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

const struct mesh_io_api mesh_io_silvair = {
	.init = silvair_io_init,
	.destroy = silvair_io_destroy,
	.caps = silvair_io_caps,
	.send = silvair_io_send,
	.reg = silvair_io_reg,
	.dereg = silvair_io_dereg,
	.set = silvair_io_set,
	.cancel = silvair_io_cancel,
};

