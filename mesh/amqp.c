/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020 Silvair Inc. All rights reserved.
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
#include "mesh/amqp.h"
#include "amqp_tcp_socket.h"

#include <ell/ell.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>

enum message_type {
	CONNECT,
	EXCHANGE,
	PUBLISH,
};

struct message {
	enum message_type type;
	union {
		struct message_connect {
			char host[128];
			int port;

			char vhost[64];
			char user[64];
			char pass[64];
		} connect;

		struct message_exchange {
			char name[33];
		} exchange;

		struct message_publish {
			char exchange[33];
			char routing_key[33];
			size_t size;
			uint8_t data[30];
		} publish;
	};
};

struct mesh_amqp {
	char *url;
	pthread_t thread;
	struct l_queue *queue;
	struct l_io *io;
};

static bool amqp_read_handler(struct l_io *io, void *user_data)
{
	struct message msg;

	if (recv(l_io_get_fd(io), &msg, sizeof(msg), 0) <= 0)
		return false;

	return true;
}

static bool amqp_write_message(void *data, void *user_data)
{
	struct message *msg = data;
	struct l_io *io = user_data;

	if (send(l_io_get_fd(io), msg, sizeof(*msg), 0) == sizeof(*msg)) {
		l_free(data);
		return true;
	}

	return false;
}

static bool amqp_write_handler(struct l_io *io, void *user_data)
{
	struct mesh_amqp *amqp = user_data;

	l_queue_foreach_remove(amqp->queue, amqp_write_message, io);

	l_io_set_write_handler(io,
		l_queue_isempty(amqp->queue) ? NULL : amqp_write_handler,
		amqp, NULL);

	return true;
}

static void amqp_connect_handler(amqp_connection_state_t conn,
						struct message_connect *connect)
{
	int status;
	amqp_rpc_reply_t reply;

	amqp_connection_close(conn, AMQP_REPLY_SUCCESS);

	status = amqp_socket_open(amqp_get_socket(conn),
						connect->host, connect->port);

	if (status != AMQP_STATUS_OK) {
		l_error("amqp_socket_open() failed: %i", status);
		return;
	}

	reply = amqp_login(conn, connect->vhost, 0, AMQP_DEFAULT_FRAME_SIZE, 0,
		AMQP_SASL_METHOD_PLAIN, connect->user, connect->pass);

	switch (reply.reply_type)
	{
		case AMQP_RESPONSE_LIBRARY_EXCEPTION:
			l_error("amqp_login() failed: %s", amqp_error_string2(reply.library_error));
			return;
			break;

		case AMQP_RESPONSE_SERVER_EXCEPTION:
			switch (reply.reply.id)
			{
				case AMQP_CONNECTION_CLOSE_METHOD:
				{
					amqp_connection_close_t *m = (amqp_connection_close_t *)reply.reply.decoded;
					l_error("amqp_login() failed: %.*s", (int)m->reply_text.len, (char*)m->reply_text.bytes);
					return;
				}
			}
			break;

		case AMQP_RESPONSE_NORMAL:
			l_info("Connected to amqp://%s:***@%s:%i/%s",
			       connect->user, connect->host, connect->port,
			       connect->vhost);
			break;

		case AMQP_RESPONSE_NONE:
			return;
	}

	amqp_channel_open(conn, 1);

	reply = amqp_get_rpc_reply(conn);

	if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
		l_error("Channel failed");
		return;
	}

	l_error("Channel open");
}

static void amqp_exchange_handler(amqp_connection_state_t conn,
					struct message_exchange *exchange)
{
	amqp_rpc_reply_t reply;

	amqp_exchange_declare(conn, 1,
			amqp_cstring_bytes(exchange->name), /* name */
			amqp_cstring_bytes("topic"), /* type */
			0, /* passive */
			1, /* durable */
			0, /* auto_delete */
			0, /* internal */
			amqp_empty_table /* arguments */);

	reply = amqp_get_rpc_reply(conn);

	if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
		l_error("Exchange failed");
		return;
	}

	l_info("Exchange declared %s", exchange->name);
}

static void amqp_publish_handler(amqp_connection_state_t conn,
					struct message_publish *publish)
{
	amqp_rpc_reply_t reply;
	amqp_basic_properties_t props;
	amqp_bytes_t body;

	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
	props.content_type = amqp_cstring_bytes("application/octet-stream");
	props.delivery_mode = 2; /* persistent delivery mode */

	body.len = publish->size;
	body.bytes = publish->data;

	amqp_basic_publish(conn, 1,
			amqp_cstring_bytes(publish->exchange), /* name */
			amqp_cstring_bytes(publish->routing_key), /* key */
			0, 0,
			&props,
			body);

	reply = amqp_get_rpc_reply(conn);

	if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
		l_error("Publish failed");
		return;
	}
}

static void amqp_message_handler(amqp_connection_state_t conn, int fd)
{
	struct message msg;

	while (recv(fd, &msg, sizeof(msg), 0) == sizeof(msg))
	{
		switch (msg.type)
		{
		case CONNECT:
			amqp_connect_handler(conn, &msg.connect);
			break;

		case EXCHANGE:
			amqp_exchange_handler(conn, &msg.exchange);
			break;

		case PUBLISH:
			amqp_publish_handler(conn, &msg.publish);
			break;
		}
	}
}

static void *amqp_thread(void *user_data)
{
	int fd = L_PTR_TO_INT(user_data);
	bool connected = false;

	amqp_connection_state_t conn = amqp_new_connection();
	amqp_socket_t *sock = amqp_tcp_socket_new(conn);

	fd_set read_fds;
	int max_fd = -1;

	while (true)
	{
		FD_ZERO(&read_fds);

		FD_SET(fd, &read_fds);
		if (fd > max_fd)
			max_fd = fd;

		if (connected) {
			FD_SET(amqp_socket_get_sockfd(sock), &read_fds);
			if (amqp_socket_get_sockfd(sock) > max_fd)
				max_fd = amqp_socket_get_sockfd(sock);
		}

		select(max_fd + 1, &read_fds, NULL, NULL, NULL);

		if (FD_ISSET(fd, &read_fds))
			amqp_message_handler(conn, fd);

		if (connected && FD_ISSET(amqp_socket_get_sockfd(sock), &read_fds)) {
			amqp_rpc_reply_t ret;
			amqp_envelope_t envelope;

			amqp_maybe_release_buffers(conn);
			ret = amqp_consume_message(conn, &envelope, NULL, 0);

			if (ret.reply_type != AMQP_RESPONSE_NORMAL)
				break;

			amqp_destroy_envelope(&envelope);
		}
	}

	close(fd);
	return NULL;
}


struct mesh_amqp *mesh_amqp_new(void)
{
	struct mesh_amqp *amqp = l_new(struct mesh_amqp, 1);
	pthread_attr_t attr;
	int fds[2];

	socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_create(&amqp->thread, &attr, amqp_thread, L_INT_TO_PTR(fds[1]));

	amqp->queue = l_queue_new();
	amqp->io = l_io_new(fds[0]);
	l_io_set_close_on_destroy(amqp->io, true);
	l_io_set_read_handler(amqp->io, amqp_read_handler, amqp, NULL);

	return amqp;
}

void mesh_amqp_free(struct mesh_amqp *amqp)
{
	l_io_destroy(amqp->io);
	l_queue_destroy(amqp->queue, l_free);
	l_free(amqp->url);
	l_free(amqp);

	// pthread_cancel(amqp->thread);
}

const char *mesh_amqp_get_url(struct mesh_amqp *amqp)
{
	return amqp->url;
}

bool mesh_amqp_set_url(struct mesh_amqp *amqp, const char *url)
{
	struct amqp_connection_info info;
	char *tmp = l_strdup(url);
	struct message *msg = l_new(struct message, 1);

	if (amqp->url && !strcmp(amqp->url, url))
		return true;

	if (amqp_parse_url(tmp, &info) != AMQP_STATUS_OK) {
		l_warn("Cannot parse '%s'", url);
		l_free(tmp);
		return false;
	}

	amqp->url = l_strdup(url);

	msg = l_new(struct message, 1);
	msg->type = CONNECT;
	strncpy(msg->connect.host, info.host, sizeof(msg->connect.host) - 1);
	msg->connect.port = info.port;

	strncpy(msg->connect.vhost, strlen(info.vhost) ? info.vhost : "/", sizeof(msg->connect.vhost) - 1);
	strncpy(msg->connect.user, info.user, sizeof(msg->connect.user) - 1);
	strncpy(msg->connect.pass, info.password, sizeof(msg->connect.pass) - 1);

	l_queue_push_tail(amqp->queue, msg);
	l_io_set_write_handler(amqp->io, amqp_write_handler, amqp, NULL);

	l_free(tmp);
	return true;
}

void mesh_amqp_set_exchange(struct mesh_amqp *amqp, const char *exchange)
{
	struct message *msg;

	msg = l_new(struct message, 1);
	msg->type = EXCHANGE;
	strncpy(msg->exchange.name, exchange, sizeof(msg->exchange.name) - 1);

	l_queue_push_tail(amqp->queue, msg);
	l_io_set_write_handler(amqp->io, amqp_write_handler, amqp, NULL);
}

void mesh_amqp_publish(struct mesh_amqp *amqp, size_t size, const void *data)
{
	struct message *msg;

	msg = l_new(struct message, 1);
	msg->type = PUBLISH;
	strncpy(msg->publish.exchange, "83bf3b46810345a28bcce70d8d0b46d3", sizeof(msg->publish.exchange));
	strncpy(msg->publish.routing_key, "foo", sizeof(msg->publish.routing_key));

	msg->publish.size = size;
	memcpy(msg->publish.data, data, sizeof(msg->publish.data));

	l_queue_push_tail(amqp->queue, msg);
	l_io_set_write_handler(amqp->io, amqp_write_handler, amqp, NULL);
}
