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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <string.h>

static const int DEFAULT_RECONNECT_DELAY = 5;

enum message_type {
	SET_URL,
	GET_URL,
	SET_EXCHANGE,
	GET_EXCHANGE,
	SET_ROUTING_KEY,
	GET_ROUTING_KEY,
	GET_READY_STATUS,
	PUBLISH,
	STOP,
};

enum amqp_state {
	AMQP_STATE_DISCONNECTED = 0,
	AMQP_STATE_CONNECTING,
	AMQP_STATE_CONNECTED,
};

struct message {
	enum message_type type;
	union {
		struct message_url {
			char url[255];
		} url;
		struct message_exchange {
			char exchange[64];
		} exchange;
		struct message_routing_key
		{
			char routing_key[64];
		} routing_key;
		struct message_publish {
			size_t size;
			uint8_t data[32];
		} publish;
		struct message_is_ready {
			bool is_ready;
		} is_ready;
	};
};

struct amqp_thread_context {
	amqp_connection_state_t conn_state;
	amqp_socket_t *sock;

	struct mesh_amqp_config config;
	enum amqp_state amqp_state;

	int fd;
	int tim_fd;
	bool stop;
};

struct mesh_amqp {
	bool thread_started;
	pthread_t thread;
	struct l_queue *queue;
	struct l_queue *ret_queue;
	struct l_io *io;
};

static bool amqp_read_handler(struct l_io *io, void *user_data)
{
	struct mesh_amqp *amqp = user_data;
	struct message *msg = l_new(struct message, 1);

	if (recv(l_io_get_fd(io), msg, sizeof(*msg), 0) == sizeof(*msg))
	{
		if (!l_queue_push_tail(amqp->ret_queue, msg))
		{
			l_free(msg);
			return false;
		}

		return true;
	}

	l_free(msg);
	return false;
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

static bool is_reply_ok(amqp_rpc_reply_t *reply)
{
	switch (reply->reply_type)
	{
		case AMQP_RESPONSE_NORMAL:
			return true;

		case AMQP_RESPONSE_NONE:
			l_error("response none");
			break;

		case AMQP_RESPONSE_LIBRARY_EXCEPTION:
			l_error("library exception: %s", amqp_error_string2(reply->library_error));
			break;

		case AMQP_RESPONSE_SERVER_EXCEPTION:
			switch (reply->reply.id)
			{
				case AMQP_CONNECTION_CLOSE_METHOD:
				{
					amqp_connection_close_t *m = (amqp_connection_close_t *)reply->reply.decoded;
					l_error("server exception: %.*s", (int)m->reply_text.len, (char*)m->reply_text.bytes);
					break;
				}

				case AMQP_CHANNEL_CLOSE_METHOD:
				{
					amqp_channel_close_t *m = (amqp_channel_close_t *)reply->reply.decoded;
					l_error("server exception: %.*s", (int)m->reply_text.len, (char*)m->reply_text.bytes);
					break;
				}

				default:
					l_error("server exception: 0x%08x", reply->reply.id);
					break;
			}
			break;
	}

	return false;
}

static bool amqp_connect_handler(struct amqp_thread_context *context)
{
	bool ret = false;
	int status;
	amqp_rpc_reply_t reply;
	struct amqp_connection_info info;
	char *tmp_url = NULL;
	char *vhost = NULL;

	if (!context->config.url) {
		l_info("AMQP broker URL is not set!");
		return false;
	}

	tmp_url =  l_strdup(context->config.url);

	if (amqp_parse_url(tmp_url, &info) != AMQP_STATUS_OK) {
		l_warn("Cannot parse URL: '%s'", tmp_url);
		goto cleanup;
	}

	amqp_connection_close(context->conn_state, AMQP_REPLY_SUCCESS);

	status = amqp_socket_open(amqp_get_socket(context->conn_state),
						info.host, info.port);

	if (status != AMQP_STATUS_OK) {
		l_error("amqp_socket_open() failed: %i", status);
		goto cleanup;
	}

	vhost = l_strdup_printf("/%s", info.vhost);

	reply = amqp_login(context->conn_state, vhost, 0, AMQP_DEFAULT_FRAME_SIZE, 0,
		AMQP_SASL_METHOD_PLAIN, info.user, info.password);

	if (!is_reply_ok(&reply)) {
		l_error("Login failed");
		goto cleanup;
	}

	l_info("Connected to 'amqp://%s:***@%s:%i%s'",
			info.user, info.host, info.port, vhost);

	amqp_channel_open(context->conn_state, 1);
	reply = amqp_get_rpc_reply(context->conn_state);

	if (!is_reply_ok(&reply)) {
		l_error("Channel failed");
		goto cleanup;
	}

	l_info("Channel opened");
	ret = true;

cleanup:
	l_free(tmp_url);
	l_free(vhost);

	return ret;
}

static bool amqp_exchange_handler(struct amqp_thread_context *context)
{
	amqp_rpc_reply_t reply;

	amqp_exchange_declare(context->conn_state, 1,
			amqp_cstring_bytes(context->config.exchange), /* name */
			amqp_cstring_bytes("topic"), /* type */
			0, /* passive */
			1, /* durable */
			0, /* auto_delete */
			0, /* internal */
			amqp_empty_table /* arguments */);

	reply = amqp_get_rpc_reply(context->conn_state);

	if (!is_reply_ok(&reply)) {
		l_error("Exchange declaration failed");
		return false;
	}

	l_info("Exchange '%s' declared", context->config.exchange);
	return true;
}

static void amqp_publish_handler(struct amqp_thread_context *context, uint8_t *data, size_t size)
{
	amqp_rpc_reply_t reply;
	amqp_basic_properties_t props;
	amqp_bytes_t body;

	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
	props.content_type = amqp_cstring_bytes("application/octet-stream");
	props.delivery_mode = 2; /* persistent delivery mode */

	body.len = size;
	body.bytes = data;

	amqp_basic_publish(context->conn_state, 1,
			amqp_cstring_bytes(context->config.exchange), /* name */
			amqp_cstring_bytes(context->config.routing_key), /* key */
			0, 0,
			&props,
			body);

	reply = amqp_get_rpc_reply(context->conn_state);

	if (!is_reply_ok(&reply))
		l_error("Publish failed");
}

static void destroy_connection(struct amqp_thread_context *context)
{
	context->amqp_state = AMQP_STATE_DISCONNECTED;

	if (context->conn_state) {
		amqp_connection_close(context->conn_state, AMQP_REPLY_SUCCESS);
		amqp_destroy_connection(context->conn_state);
	}

	context->conn_state = NULL;
	context->sock = NULL;
}

static bool new_connection(struct amqp_thread_context *context)
{
	context->conn_state = amqp_new_connection();
	if (!context->conn_state)
		return false;

	context->sock = amqp_tcp_socket_new(context->conn_state);
	if (!context->sock) {
		amqp_destroy_connection(context->conn_state);
		context->conn_state = NULL;

		return false;
	}

	return true;
}

static inline bool url_is_set(struct amqp_thread_context *context)
{
	return context->config.url && (strcmp(context->config.url, "") != 0);
}

static inline bool set_timer(int fd, int delay)
{
	struct itimerspec newitimspec = {0};
	newitimspec.it_value.tv_sec = delay;

	return timerfd_settime(fd, 0, &newitimspec, NULL) == 0;
}

static void connect_with_delay(struct amqp_thread_context *context, int delay)
{
	if (context->amqp_state == AMQP_STATE_CONNECTING) {
		l_warn("Reconnect already in progress...");
		return;
	}

	if (url_is_set(context) && set_timer(context->tim_fd, delay))
	{
		context->amqp_state = AMQP_STATE_CONNECTING;
	}
}

static bool try_to_connect(struct amqp_thread_context *context)
{
	l_info("AMQP trying to connect...");

	if (!new_connection(context)) {
		goto reconnect;
	}

	if (!amqp_connect_handler(context))
	{
		destroy_connection(context);
		goto reconnect;
	}

	if (!amqp_exchange_handler(context))
	{
		destroy_connection(context);
		goto reconnect;
	}

	context->amqp_state = AMQP_STATE_CONNECTED;
	return true;

reconnect:
	connect_with_delay(context, DEFAULT_RECONNECT_DELAY);
	return false;
}

static void control_message_handler(struct amqp_thread_context *context)
{
	struct message msg;

	while (recv(context->fd, &msg, sizeof(msg), 0) == sizeof(msg))
	{
		switch (msg.type) {
			case SET_URL:
				l_free((void *)context->config.url);
				context->config.url = l_strdup(msg.url.url);

				destroy_connection(context);
				connect_with_delay(context, 1);
				return;

			case GET_URL: {
				struct message ret_msg = {0};

				ret_msg.type = GET_URL;
				strncpy(ret_msg.url.url,
						context->config.url,
						sizeof(ret_msg.url.url) - 1);

				send(context->fd, &ret_msg, sizeof(ret_msg), 0);
			} return;

			case SET_EXCHANGE:
				l_free((void *)context->config.exchange);
				context->config.exchange = l_strdup(msg.exchange.exchange);

				if (context->amqp_state == AMQP_STATE_CONNECTED) {
					destroy_connection(context);
					connect_with_delay(context, 1);
				}
				return;

			case GET_EXCHANGE: {
				struct message ret_msg = {0};

				ret_msg.type = GET_EXCHANGE;
				strncpy(ret_msg.exchange.exchange,
					 context->config.exchange,
					 sizeof(ret_msg.exchange.exchange) - 1);

				send(context->fd, &ret_msg, sizeof(ret_msg), 0);
			} return;

			case SET_ROUTING_KEY:
				l_free((void *)context->config.routing_key);
				context->config.routing_key = l_strdup(msg.routing_key.routing_key);
				return;

			case GET_ROUTING_KEY: {
				struct message ret_msg = {0};

				ret_msg.type = GET_ROUTING_KEY;
				strncpy(ret_msg.routing_key.routing_key,
						context->config.routing_key,
						sizeof(ret_msg.routing_key.routing_key) - 1);
				send(context->fd, &ret_msg, sizeof(ret_msg), 0);
			} return;

			case GET_READY_STATUS: {
				struct message ret_msg = {0};

				ret_msg.type = GET_READY_STATUS;
				ret_msg.is_ready.is_ready = (context->amqp_state == AMQP_STATE_CONNECTED);

				send(context->fd, &ret_msg, sizeof(ret_msg), 0);
			} return;

			case PUBLISH:
				if (!context->conn_state)
					return;

				amqp_publish_handler(context, msg.publish.data, msg.publish.size);
				return;

			case STOP:
				context->stop = true;
				return;
		}
	}
}

static void *amqp_thread(void *user_data)
{
	struct amqp_thread_context *context = user_data;

	fd_set read_fds;
	int max_fd = -1;

	if (url_is_set(context))
		try_to_connect(context);

	while (true)
	{
		FD_ZERO(&read_fds);

		FD_SET(context->tim_fd, &read_fds);
		if (context->tim_fd > max_fd)
			max_fd = context->tim_fd;
        https://github.com/homersoft/bluez/pull/61/commits
		FD_SET(context->fd, &read_fds);
		if (context->fd > max_fd)
			max_fd = context->fd;

		if (context->sock) {
			int fd = amqp_socket_get_sockfd(context->sock);

			FD_SET(fd, &read_fds);
			if (fd > max_fd)
				max_fd = fd;
		}

		select(max_fd + 1, &read_fds, NULL, NULL, NULL);

		if (FD_ISSET(context->tim_fd, &read_fds)) {
			uint64_t no_expir;

			if (read(context->tim_fd, &no_expir, sizeof(no_expir)) == sizeof(no_expir))
			{
				destroy_connection(context);
				try_to_connect(context);
			}
		}

		if (FD_ISSET(context->fd, &read_fds))
			control_message_handler(context);

		if (context->stop)
			break;

		if (context->sock && FD_ISSET(amqp_socket_get_sockfd(context->sock), &read_fds)) {
			amqp_rpc_reply_t ret;
			amqp_envelope_t envelope;

			amqp_maybe_release_buffers(context->conn_state);
			ret = amqp_consume_message(context->conn_state, &envelope, NULL, 0);

			if (!is_reply_ok(&ret)) {
				destroy_connection(context);
				connect_with_delay(context, DEFAULT_RECONNECT_DELAY);
			}

			amqp_destroy_envelope(&envelope);
		}
	}

	destroy_connection(context);

	close(context->tim_fd);
	close(context->fd);

	l_free(context->config.url);
	l_free(context->config.exchange);
	l_free(context->config.routing_key);

	return context;
}

struct mesh_amqp *mesh_amqp_new(void)
{
	struct mesh_amqp *amqp = l_new(struct mesh_amqp, 1);
	memset(amqp, 0, sizeof(*amqp));

	return amqp;
}

void mesh_amqp_start(struct mesh_amqp *amqp, struct mesh_amqp_config *config)
{
	pthread_attr_t attr;
	int fds[2];

	struct amqp_thread_context *thread_context = l_new(struct amqp_thread_context, 1);
	memset(thread_context, 0, sizeof(*thread_context));

	socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	thread_context->fd = fds[1];
	thread_context->tim_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (thread_context->tim_fd < 0) {
		l_warn("Failed to create timer! Thread will not be started.");
		return;
	}

	if (config) {
		thread_context->config.url = l_strdup(config->url ?: "");
		thread_context->config.exchange = l_strdup(config->exchange ?: "");
		thread_context->config.routing_key = l_strdup(config->routing_key ?: "");
	}

	amqp->thread_started = !pthread_create(&amqp->thread, &attr, amqp_thread, thread_context);
	amqp->queue = l_queue_new();
	amqp->ret_queue = l_queue_new();
	amqp->io = l_io_new(fds[0]);

	l_io_set_close_on_destroy(amqp->io, true);
	l_io_set_read_handler(amqp->io, amqp_read_handler, amqp, NULL);
}

void mesh_amqp_free(struct mesh_amqp *amqp)
{
	if (amqp->thread_started) {
		void *ret;

		mesh_amqp_stop(amqp);
		pthread_join(amqp->thread, &ret);

		l_free(ret);
	}

	l_io_destroy(amqp->io);
	l_queue_destroy(amqp->queue, l_free);
	l_queue_destroy(amqp->ret_queue, l_free);
	l_free(amqp);
}

static void awaiting_timeout(struct l_timeout *timeout, void *user_data)
{
	bool *expired = user_data;
	*expired = true;
}

static void *get_ret_message(struct mesh_amqp *amqp)
{
	/* ELL DBus API requires that getters are blocking,
	   so keep iterating the loop while we wait for reply from the thread". */

	bool expired = false;
	struct message *ret_msg;
	struct l_timeout *timeout;

	if (!amqp->thread_started)
		return NULL;

	timeout = l_timeout_create_ms(100, awaiting_timeout, &expired, NULL);

	while (1) {
		ret_msg = l_queue_pop_head(amqp->ret_queue);
		if (ret_msg)
			break;

		if (expired) {
			l_error("amqp: command timed out");
			break;
		}

		l_main_iterate(0);
	}

	l_timeout_remove(timeout);
	return ret_msg;
}

static void send_message(struct mesh_amqp *amqp, struct message *msg)
{
	l_queue_push_tail(amqp->queue, msg);
	l_io_set_write_handler(amqp->io, amqp_write_handler, amqp, NULL);
}

static struct message *new_message(enum message_type type)
{
	struct message *msg = l_new(struct message, 1);
	memset(msg, 0, sizeof(*msg));

	msg->type = type;

	return msg;
}

char *mesh_amqp_get_url(struct mesh_amqp *amqp)
{
	char *url;
	struct message *ret_msg;

	send_message(amqp, new_message(GET_URL));
	ret_msg = get_ret_message(amqp);
	if (!ret_msg)
		return NULL;

	url = l_strdup(ret_msg->url.url);
	l_free(ret_msg);

	return url;
}

void mesh_amqp_set_url(struct mesh_amqp *amqp, const char *url)
{
	struct message *msg = new_message(SET_URL);
	strncpy(msg->url.url, url ?: "", sizeof(msg->url.url) - 1);

	send_message(amqp, msg);
}

char *mesh_amqp_get_exchange(struct mesh_amqp *amqp)
{
	char *exchange;
	struct message *ret_msg;

	send_message(amqp, new_message(GET_EXCHANGE));
	ret_msg = get_ret_message(amqp);
	if (!ret_msg)
		return NULL;

	exchange = l_strdup(ret_msg->exchange.exchange);
	l_free(ret_msg);

	return exchange;
}

void mesh_amqp_set_exchange(struct mesh_amqp *amqp, const char *exchange)
{
	struct message *msg = new_message(SET_EXCHANGE);
	strncpy(msg->exchange.exchange, exchange ?: "", sizeof(msg->exchange.exchange) - 1);

	send_message(amqp, msg);
}

char *mesh_amqp_get_routing_key(struct mesh_amqp *amqp)
{
	char *routing_key;
	struct message *ret_msg;

	send_message(amqp, new_message(GET_ROUTING_KEY));
	ret_msg = get_ret_message(amqp);
	if (!ret_msg)
		return NULL;

	routing_key = l_strdup(ret_msg->routing_key.routing_key);
	l_free(ret_msg);

	return routing_key;
}

void mesh_amqp_set_routing_key(struct mesh_amqp *amqp, const char *routing_key)
{
	struct message *msg = new_message(SET_ROUTING_KEY);
	strncpy(msg->routing_key.routing_key,
			routing_key ?: "",
			sizeof(msg->routing_key.routing_key) - 1);

	send_message(amqp, msg);
}

void mesh_amqp_publish(struct mesh_amqp *amqp, const void *data, size_t size)
{
	struct message *msg = new_message(PUBLISH);

	msg->publish.size = size;
	memcpy(msg->publish.data, data, sizeof(msg->publish.data));

	send_message(amqp, msg);
}

void mesh_amqp_stop(struct mesh_amqp *amqp)
{
	struct message *msg = new_message(STOP);

	send(l_io_get_fd(amqp->io), msg, sizeof(*msg), 0);
	l_free(msg);
}

bool mesh_amqp_is_ready(struct mesh_amqp *amqp)
{
	bool is_ready;
	struct message *ret_msg;

	send_message(amqp, new_message(GET_READY_STATUS));
	ret_msg = get_ret_message(amqp);
	if (!ret_msg)
		return false;

	is_ready = ret_msg->is_ready.is_ready;
	l_free(ret_msg);

	return is_ready;
}
