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

#include "mesh/mesh.h"
#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"
#include "mesh/mesh-io-mqtt.h"
#include "mesh/net-keys.h"
#include "mesh/util.h"
#include "mosquitto.h"

struct mesh_io_private {
	uint8_t		*uuid;
	uint8_t		*key;
	char		*hostname;
	uint16_t	port;

	struct l_timeout	*tx_timeout;
	struct l_queue		*tx_pkts;
	struct l_queue		*conns;

	struct l_dbus	*dbus;

	mesh_io_ready_func_t	ready_cb;
	void					*user_data;
};

struct mqtt_conn {
	uint32_t net_key_id;
	size_t   cnt;

	struct l_timeout    *conn_timeout;
	struct mosquitto	*mosq;
    char				identity[16];
	char				*topic;

	mesh_io_recv_func_t	net_cb;
	mesh_io_recv_func_t	snb_cb;
    void				*user_data;

    struct mesh_io *io;
};

struct tx_pkt {
	uint32_t	net_key_id;
	uint32_t	instant;
	uint8_t		len;
	uint8_t		data[30];
};

struct tx_pattern {
	const uint8_t			*data;
	uint8_t				len;
};

static void send_timeout(struct l_timeout *timeout, void *user_data);
static void conn_destroy(struct mqtt_conn *conn);
static void conn_timeout(struct l_timeout *timeout, void *user_data);

static uint32_t get_instant(void)
{
	struct timeval tm;
	uint32_t instant;

	gettimeofday(&tm, NULL);
	instant = tm.tv_sec * 1000;
	instant += tm.tv_usec / 1000;

	return instant;
}

static void machine_id_cb(struct l_dbus_message *msg, void *user_data)
{
	struct mesh_io *io = user_data;
	char *uuid, *key;
	size_t len;
	const char *err;

	if (!msg || l_dbus_message_is_error(msg)) {
		l_dbus_message_get_error(msg, NULL, &err);
		l_error("Failed to get machine id: %s", err);
		goto err;
	}

	if (!l_dbus_message_get_arguments(msg, "s", &uuid)) {
		l_error("Failed to get machine id");
		goto err;
	}

	io->pvt->uuid = l_util_from_hexstring(uuid, &len);

	if (!io->pvt->uuid || len != 16) {
		l_error("Failed to parse machine id %s", uuid);
		l_free(io->pvt->uuid);
		io->pvt->uuid = NULL;
		goto err;
	}

	key = l_util_hexstring(io->pvt->key, 16);
	l_error("uuid=%s key=%s", uuid, key);
	l_free(key);

	return io->pvt->ready_cb(io->pvt->user_data, true);
err:
	io->pvt->ready_cb(io->pvt->user_data, false);
}

static void mqtt_io_init_done(void *user_data)
{
	struct mesh_io *io = user_data;
	static const char *destination = "org.freedesktop.DBus";
	static const char *path = "/org/freedesktop/DBus";
	static const char *iface = "org.freedesktop.DBus.Peer";
	struct l_dbus_message *msg;

	msg = l_dbus_message_new_method_call(io->pvt->dbus, destination,
						path, iface, "GetMachineId");
	l_dbus_message_set_arguments(msg, "");

	l_dbus_send_with_reply(io->pvt->dbus, msg, machine_id_cb, io,
									NULL);
}

static bool mqtt_io_init(struct mesh_io *io, void *opts,
				struct l_dbus *dbus, mesh_io_ready_func_t cb,
				void *user_data)
{
	char *opt = opts;
	char *delim;

	char *argv[4] = { 0 };
	size_t argc = 0;

	size_t len;

	if (!io)
		return false;

	io->pvt = l_new(struct mesh_io_private, 1);

	do {
		delim = strchr(opt, ':');

		if (delim)
			*delim = '\0';

		argv[argc++] = opt;

		if (delim)
			opt = delim + 1;

	} while (delim && (argc < L_ARRAY_SIZE(argv)));

	if (argc <= 0) {
		l_error("Invalid number of arguments.");
		return false;
	}

	if (!argv[0] || !strlen(argv[0])) {
		l_error("Need key");
		return false;
	}

	if (!argv[1] || !strlen(argv[1])) {
		l_error("Need hostname");
		return false;
	}

	if (argv[2] && strlen(argv[2])) {
		if (sscanf(argv[2], "%hi", &io->pvt->port) != 1) {
			l_error("Need port");
			return false;
		}
	} else {
		io->pvt->port = 1883;
	}

	io->pvt->key = l_util_from_hexstring(argv[0], &len);
	if (len != 16) {
		l_error("Invalid key length");
		return false;
	}
	io->pvt->hostname = l_strdup(argv[1]);

	io->pvt->tx_pkts = l_queue_new();
	io->pvt->conns = l_queue_new();

	io->pvt->ready_cb = cb;
	io->pvt->user_data = user_data;
	io->pvt->dbus = dbus;

	io->pvt->tx_timeout = l_timeout_create_ms(0, send_timeout,
						       io, NULL);

	mosquitto_lib_init();
	l_idle_oneshot(mqtt_io_init_done, io, NULL);
	return true;
}

static void conn_free(void *user_data)
{
	struct mqtt_conn *conn = user_data;
	conn_destroy(conn);
}

static bool mqtt_io_destroy(struct mesh_io *io)
{
	if (!io || !io->pvt)
		return true;

	l_free(io->pvt->uuid);
	l_free(io->pvt->key);
	l_free(io->pvt->hostname);
	l_queue_destroy(io->pvt->tx_pkts, l_free);
	l_queue_destroy(io->pvt->conns, conn_free);
	l_timeout_remove(io->pvt->tx_timeout);
	l_free(io->pvt);

	mosquitto_lib_cleanup();
	return true;
}

static bool find_by_net_key_id(const void *a, const void *b)
{
	const struct mqtt_conn *conn = a;
	uint32_t net_key_id = L_PTR_TO_UINT(b);

	return conn->net_key_id == net_key_id;
}

static void send_flush(struct mesh_io *io)
{
	struct tx_pkt *tx;
	struct mqtt_conn *conn;
	char *hex;
	uint32_t instant = get_instant();

	do {
		tx = l_queue_peek_head(io->pvt->tx_pkts);

		if (!tx || tx->instant > instant)
			break;

		tx = l_queue_pop_head(io->pvt->tx_pkts);

		conn = l_queue_find(io->pvt->conns, find_by_net_key_id,
						L_UINT_TO_PTR(tx->net_key_id));
		if (conn) {
            hex = l_util_hexstring(tx->data, tx->len);
            l_debug("%i: [%s] send %s", conn->net_key_id, conn->topic, hex);
            l_free(hex);

			mosquitto_publish(conn->mosq, NULL, "testing_silvair_stack", tx->len, tx->data, 1, false);
		}
		l_free(tx);
	} while (tx);

	if (tx)
		l_timeout_modify_ms(io->pvt->tx_timeout,
				    tx->instant - instant);
}

static void send_timeout(struct l_timeout *timeout, void *user_data)
{
	struct mesh_io *io = user_data;

	if (!io)
		return;

	send_flush(io);
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

static void send_pkt(struct mesh_io *io, uint32_t net_key_id,
		     const uint8_t *data, uint16_t len, uint32_t instant)
{
	struct tx_pkt *tx = l_new(struct tx_pkt, 1);

	tx->net_key_id = net_key_id;
	tx->instant = instant;
	tx->len = len;
	memcpy(tx->data, data, len);

	l_queue_insert(io->pvt->tx_pkts, tx, compare_tx_pkt_instant, NULL);
	send_flush(io);
}

static bool mqtt_io_send(struct mesh_io *io,
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

		// FIXME: such packets need to be rescheduled on flush
		if (info->u.gen.cnt == MESH_IO_TX_COUNT_UNLIMITED)
			info->u.gen.cnt = 1;

		for (i = 0; i < info->u.gen.cnt; ++i)
			send_pkt(io, info->net_key_id, data, len,
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

		send_pkt(io, info->net_key_id, data, len, instant + delay);
		break;

	case MESH_IO_TIMING_TYPE_POLL_RSP:
		instant = info->u.poll_rsp.instant;
		delay = info->u.poll_rsp.delay;

		send_pkt(io, info->net_key_id, data, len, instant + delay);
		break;
	}

	return true;
}


static bool mqtt_io_filter_reg(struct mesh_io *io, const uint8_t *filter,
			uint8_t len, mesh_io_recv_func_t cb, void *user_data)
{
	l_error("This io doesn't support filter registration");
	return false;
}

static bool mqtt_io_filter_dereg(struct mesh_io *io, const uint8_t *filter,
								uint8_t len)
{
	l_error("This io doesn't support filter registration");
	return false;
}

static void on_connect(struct mosquitto *mosq, void *user_data, int rc)
{
	struct mqtt_conn *conn = user_data;
	l_info("%i: connected(%i)", conn->net_key_id, rc);

	mosquitto_subscribe(conn->mosq, NULL, conn->topic, 1);
	l_info("%i: topic: %s", conn->net_key_id, conn->topic);

	l_timeout_remove(conn->conn_timeout);
	conn->conn_timeout = NULL;
}

static void on_disconnect(struct mosquitto *mosq, void *user_data, int rc)
{
	struct mqtt_conn *conn = user_data;
	l_info("%i: disconnected(%i)", conn->net_key_id, rc);

	if (!conn->cnt)
	    conn_destroy(conn);
	else {
		conn->conn_timeout = l_timeout_create(5, conn_timeout, conn, NULL);
	}
}

static void on_message(struct mosquitto *mosq, void *user_data,
					const struct mosquitto_message *msg)
{
	struct mqtt_conn *conn = user_data;
	struct mesh_io_recv_info info = {0};
	char *hex;

    hex = l_util_hexstring(msg->payload, msg->payloadlen);
    l_debug("%i: [%s] receive %s", conn->net_key_id, msg->topic, hex);
    l_free(hex);

	conn->net_cb(conn->user_data, &info, msg->payload, msg->payloadlen);
}

static struct mqtt_conn *conn_new(struct mesh_io *io, uint32_t net_key_id,
										mesh_io_recv_func_t net_cb, mesh_io_recv_func_t snb_cb,
										void *user_data)
{
	struct mqtt_conn *conn = l_new(struct mqtt_conn, 1);
	char network_id[8];
	char *identity, *network;

	if (!net_key_psk(net_key_id, io->pvt->uuid, io->pvt->key, conn->identity, NULL, network_id))
		return NULL;

	network = l_util_hexstring(network_id, 8);

	conn->net_key_id = net_key_id;
	conn->mosq = mosquitto_new(NULL, true, conn);
	conn->topic = l_strdup_printf("%s", network);
	conn->net_cb = net_cb;
	conn->snb_cb = snb_cb;
	conn->user_data = user_data;
	conn->io = io;

	identity = l_util_hexstring(conn->identity, sizeof(conn->identity));

	l_info("%i: identity=%s network=%s", net_key_id, identity, network);

	l_free(identity);
	l_free(network);

	return conn;
}

static void conn_destroy(struct mqtt_conn *conn)
{
    mosquitto_destroy(conn->mosq);
    l_timeout_remove(conn->conn_timeout);
    l_free(conn->topic);
    l_free(conn);
}

static void conn_timeout(struct l_timeout *timeout, void *user_data)
{
	struct mqtt_conn *conn = user_data;
	struct mesh_io *io = conn->io;
	char *identity = l_util_hexstring(conn->identity, sizeof(conn->identity));

	mosquitto_disconnect(conn->mosq);
	mosquitto_loop_stop(conn->mosq, false);

	mosquitto_reinitialise(conn->mosq, NULL, true, conn);

	mosquitto_connect_callback_set(conn->mosq, on_connect);
	mosquitto_disconnect_callback_set(conn->mosq, on_disconnect);
	mosquitto_message_callback_set(conn->mosq, on_message);

	l_info("%i: connect_async to hostname %s on port %d", conn->net_key_id, io->pvt->hostname, io->pvt->port);
	int err = mosquitto_connect_async(conn->mosq, io->pvt->hostname, io->pvt->port, 5);
	if (err != MOSQ_ERR_SUCCESS)
	{
	    l_debug("%i: err: %s, errno: %d", conn->net_key_id, mosquitto_strerror(err), errno);
	}

    mosquitto_loop_start(conn->mosq);

	l_timeout_modify(conn->conn_timeout, 1);
	l_free(identity);

}

static bool mqtt_io_subnet_reg(struct mesh_io *io, uint32_t net_key_id,
						mesh_io_recv_func_t net_cb,
						mesh_io_recv_func_t snb_cb,
						void *user_data)
{
	struct mqtt_conn *conn;

	if (!io || !io->pvt)
		return false;

	conn = l_queue_find(io->pvt->conns, find_by_net_key_id,
						L_UINT_TO_PTR(net_key_id));

	if (conn) {
		if (conn->net_cb != net_cb || conn->snb_cb != snb_cb || conn->user_data != user_data)
			return false;
	} else {
		conn = conn_new(io, net_key_id, net_cb, snb_cb, user_data);

		if (!conn)
		{
			return false;
		}

		conn->conn_timeout = l_timeout_create(0, conn_timeout, conn, NULL);
		conn_timeout(conn->conn_timeout, conn);

		l_queue_push_tail(io->pvt->conns, conn);
	}

	conn->cnt++;

	return false;
}

static bool mqtt_io_subnet_dereg(struct mesh_io *io, uint32_t net_key_id)
{
	struct mqtt_conn *conn;

	if (!io || !io->pvt)
		return false;

	conn = l_queue_find(io->pvt->conns, find_by_net_key_id, L_UINT_TO_PTR(net_key_id));

	if (!conn)
		return true;

	if (!--conn->cnt) {
		l_info("Close connection for net key %i", net_key_id);
		l_queue_remove(io->pvt->conns, conn);
        mosquitto_disconnect(conn->mosq);
	}

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

static bool mqtt_io_cancel(struct mesh_io *io,
				const uint8_t *data, uint8_t len)
{
	struct tx_pkt *tx;
	const struct tx_pattern pattern = {
		.data = data,
		.len = len
	};

	if (!data)
		return false;

	do {
		tx = l_queue_remove_if(io->pvt->tx_pkts, find_by_pattern,
				       &pattern);
		l_free(tx);
	} while (tx);

	tx = l_queue_peek_head(io->pvt->tx_pkts);

	if (tx)
		l_timeout_modify_ms(io->pvt->tx_timeout,
				    tx->instant - get_instant());

	return true;
}

const struct mesh_io_api mesh_io_mqtt = {
	.init = mqtt_io_init,
	.destroy = mqtt_io_destroy,
	.send = mqtt_io_send,
	.filter_reg = mqtt_io_filter_reg,
	.filter_dereg = mqtt_io_filter_dereg,
	.subnet_reg = mqtt_io_subnet_reg,
	.subnet_dereg = mqtt_io_subnet_dereg,
	.cancel = mqtt_io_cancel,
};
