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


struct message;
struct mesh_amqp;

typedef void (*complete_cb_t)(struct message *msg, struct mesh_amqp *amqp);

enum message_type {
	SET_URL,
	SET_EXCHANGE,
	SET_ROUTING_KEY,
	PUBLISH,
	STOP,
	STATE_CHANGED,
	REMOTE_CONTROL,
};

enum amqp_state {
	AMQP_STATE_DISCONNECTED = 0,
	AMQP_STATE_CONNECTING,
	AMQP_STATE_CONNECTED,
};

struct set_complete_ctx {
	mesh_amqp_set_complete_cb_t complete_cb;
	void *user_data;
};

struct message {
	enum message_type type;

	complete_cb_t complete_cb;
	void *user_data;

	union {
		struct message_url {
			char value[255];
		} url;
		struct message_exchange {
			char value[64];
		} exchange;
		struct message_routing_key
		{
			char value[64];
		} routing_key;
		struct message_publish {
			size_t size;
			uint8_t data[384];
		} publish;
		struct message_state_changed {
			enum amqp_state state;
		} state_changed;
		struct message_remote_control {
			size_t msg_len;
			struct fd_msg msg;
		} rc;
	};
};

struct mesh_amqp {
    struct mesh_amqp_config config;
    pthread_t thread;
    struct l_queue *queue;
    struct l_io *io;
    bool thread_started;
    enum amqp_state amqp_state;
    mesh_amqp_rc_send_cb_t rc_send_cb;
    void *user_data;
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

static bool amqp_read_handler(struct l_io *io, void *user_data)
{
	struct mesh_amqp *amqp = user_data;
	struct message msg = {0};

	if (recv(l_io_get_fd(io), &msg, sizeof(msg), 0) == sizeof(msg))
	{
		switch (msg.type)
		{
			case STATE_CHANGED:
				amqp->amqp_state = msg.state_changed.state;
				return true;

			case SET_URL:
			case SET_EXCHANGE:
			case SET_ROUTING_KEY:
				if (msg.complete_cb)
					msg.complete_cb(&msg, amqp);
				return true;

			case REMOTE_CONTROL:;
				amqp->rc_send_cb(&msg.rc.msg, msg.rc.msg_len,
							amqp->user_data);
				return true;

			case PUBLISH:
			case STOP:
				break;
		}
	}

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
		l_error("library exception: %s",
				amqp_error_string2(reply->library_error));
		break;

	case AMQP_RESPONSE_SERVER_EXCEPTION:
		switch (reply->reply.id)
		{
			case AMQP_CONNECTION_CLOSE_METHOD:
			{
				amqp_connection_close_t *m =
				(amqp_connection_close_t *)reply->reply.decoded;
				l_error("server exception: %.*s",
					(int)m->reply_text.len,
					(char *)m->reply_text.bytes);
				break;
			}

			case AMQP_CHANNEL_CLOSE_METHOD:
			{
				amqp_channel_close_t *m =
				(amqp_channel_close_t *)reply->reply.decoded;
				l_error("server exception: %.*s",
					(int)m->reply_text.len,
					(char *)m->reply_text.bytes);
				break;
			}

			default:
				l_error("server exception: 0x%08x",
							reply->reply.id);
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
		l_warn("Cannot parse URL: '%s'", context->config.url);
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
			1, /* auto_delete */
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
	char *key = l_strdup_printf("mon.%s.raw", context->config.routing_key);

	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
	props.content_type = amqp_cstring_bytes("application/octet-stream");
	props.delivery_mode = 2; /* persistent delivery mode */

	body.len = size;
	body.bytes = data;

	amqp_basic_publish(context->conn_state, 1,
			amqp_cstring_bytes(context->config.exchange), /* name */
			amqp_cstring_bytes(key), /* key */
			0, 0,
			&props,
			body);

	reply = amqp_get_rpc_reply(context->conn_state);

	if (!is_reply_ok(&reply))
		l_error("Publish failed");

	l_free(key);
}

static void config_set_url(struct mesh_amqp_config *config, const char *url)
{
	l_free(config->url);
	config->url = l_strdup(url ?: "");
}

static void config_set_exchange(struct mesh_amqp_config *config,
				const char *exchange)
{
	l_free(config->exchange);
	config->exchange = l_strdup(exchange ?: "");
}

static void config_set_routing_key(struct mesh_amqp_config *config,
				   const char *routing_key)
{
	l_free(config->routing_key);
	config->routing_key = l_strdup(routing_key ?: "");
}

static inline bool url_is_empty(const char *url)
{
	return (!url || strcmp(url, "") == 0);
}

static bool url_is_valid(const char *url)
{
	bool valid;
	char *tmp_url;
	struct amqp_connection_info info;

	if (url_is_empty(url))
		return false;

	tmp_url = l_strdup(url);

	valid = amqp_parse_url(tmp_url, &info) == AMQP_STATUS_OK;
	l_free(tmp_url);

	return valid;
}

static inline bool set_timer(int fd, int delay)
{
	struct itimerspec newitimspec = {0};
	newitimspec.it_value.tv_sec = delay;

	return timerfd_settime(fd, 0, &newitimspec, NULL) == 0;
}

static void set_amqp_state(struct amqp_thread_context *context, enum amqp_state amqp_state)
{
	struct message ret_msg = {0};

	ret_msg.type = STATE_CHANGED;
	ret_msg.state_changed.state = amqp_state;

	context->amqp_state = amqp_state;

	send(context->fd, &ret_msg, sizeof(ret_msg), 0);
}

static void destroy_connection(struct amqp_thread_context *context)
{
	set_amqp_state(context, AMQP_STATE_DISCONNECTED);

	if (context->conn_state) {
		amqp_connection_close(context->conn_state, AMQP_REPLY_SUCCESS);
		amqp_destroy_connection(context->conn_state);
	}

	context->conn_state = NULL;
	context->sock = NULL;

	l_info("AMQP disconnected");
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

static void connect_with_delay(struct amqp_thread_context *context, int delay)
{
	if (context->amqp_state == AMQP_STATE_CONNECTING) {
		l_warn("Reconnect already in progress...");
		return;
	}

	if (!set_timer(context->tim_fd, delay))
	{
		l_warn("amqp: failed to start timer");
		return;
	}

	set_amqp_state(context, AMQP_STATE_CONNECTING);
}

static bool amqp_consume(struct amqp_thread_context *context)
{
	amqp_rpc_reply_t reply;

	char *name = l_strdup_printf("rc.%s.raw", context->config.routing_key);

	amqp_queue_declare(context->conn_state, 1,
			amqp_cstring_bytes(name), /* name */
			0, /* passive */
			0, /* durable */
			1, /* exclusive */
			1, /* auto_delete */
			amqp_empty_table); /* args */

	reply = amqp_get_rpc_reply(context->conn_state);
	if (!is_reply_ok(&reply)) {
		l_info("Queue declaration failed");
		return false;
	}

	l_info("Queue: '%s' declared", name);

	amqp_queue_bind(context->conn_state, 1, /* channel */
			amqp_cstring_bytes(name), /* queue name */
			amqp_cstring_bytes(context->config.exchange), /* exchange */
			amqp_cstring_bytes(name), /* routing_key */
			amqp_empty_table); /* args */

	reply = amqp_get_rpc_reply(context->conn_state);
	if (!is_reply_ok(&reply)) {
		l_info("Bind failed");
		return false;
	}

	l_info("Exchange: '%s' bound with queue: '%s'", context->config.exchange, name);

	amqp_basic_consume(context->conn_state, 1,
			amqp_cstring_bytes(name), /* queue name */
			amqp_empty_bytes, /* tag */
			0, /* no_local */
			0, /* no_ack */
			1, /* exclusive */
			amqp_empty_table); /* args */

	reply = amqp_get_rpc_reply(context->conn_state);
	if (!is_reply_ok(&reply)) {
		l_info("Consume failed");
		return false;
	}

	l_info("Consumer started");

	l_free(name);

	return true;
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

	if (!amqp_consume(context))
	{
		destroy_connection(context);
		goto reconnect;
	}

	set_amqp_state(context, AMQP_STATE_CONNECTED);
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
		case SET_URL: {
			struct message ret_msg = {0};

			config_set_url(&context->config, msg.url.value);

			ret_msg.type = SET_URL;
			ret_msg.complete_cb = msg.complete_cb;
			ret_msg.user_data = msg.user_data;

			strncpy(ret_msg.url.value, context->config.url,
						sizeof(ret_msg.url) - 1);

			send(context->fd, &ret_msg, sizeof(ret_msg), 0);

			if (context->amqp_state == AMQP_STATE_CONNECTED)
				destroy_connection(context);

			if (url_is_valid(context->config.url))
				try_to_connect(context);
		} return;

		case SET_EXCHANGE: {
			struct message ret_msg = {0};

			config_set_exchange(&context->config,
							msg.exchange.value);

			ret_msg.type = SET_EXCHANGE;
			ret_msg.complete_cb = msg.complete_cb;
			ret_msg.user_data = msg.user_data;

			strncpy(ret_msg.exchange.value,
						context->config.exchange,
						sizeof(ret_msg.exchange) - 1);

			send(context->fd, &ret_msg, sizeof(ret_msg), 0);

			if (context->amqp_state == AMQP_STATE_CONNECTED) {
				destroy_connection(context);

				if (url_is_valid(context->config.url))
					try_to_connect(context);
			}
		} return;

		case SET_ROUTING_KEY: {
			struct message ret_msg = {0};

			config_set_routing_key(&context->config,
							msg.routing_key.value);

			ret_msg.type = SET_ROUTING_KEY;
			ret_msg.complete_cb = msg.complete_cb;
			ret_msg.user_data = msg.user_data;

			strncpy(ret_msg.routing_key.value,
					context->config.routing_key,
					sizeof(ret_msg.routing_key) - 1);

			send(context->fd, &ret_msg, sizeof(ret_msg), 0);
		}	return;

		case PUBLISH:
			if (!context->conn_state)
				return;

			amqp_publish_handler(context, msg.publish.data,
							msg.publish.size);
			return;

		case STOP:
			context->stop = true;
			return;

		case REMOTE_CONTROL:
		case STATE_CHANGED:
			return;
		}
	}
}

static void *amqp_thread(void *user_data)
{
	struct amqp_thread_context *context = user_data;

	fd_set read_fds;
	int max_fd = -1;

	while (true)
	{
		FD_ZERO(&read_fds);

		FD_SET(context->tim_fd, &read_fds);
		if (context->tim_fd > max_fd)
			max_fd = context->tim_fd;

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

				if (url_is_valid(context->config.url))
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
			struct message msg;


			amqp_maybe_release_buffers(context->conn_state);
			ret = amqp_consume_message(context->conn_state, &envelope, NULL, 0);

			if (!is_reply_ok(&ret)) {
				destroy_connection(context);
				connect_with_delay(context, DEFAULT_RECONNECT_DELAY);
				goto cleanup;
			}

			if (envelope.message.body.len < sizeof(msg.rc.msg)) {
				l_warn("Too short message");
				amqp_basic_nack(context->conn_state, 1,
						envelope.delivery_tag, 0, 0);
				goto cleanup;
			}

			if ((sizeof(msg.rc.msg) + 384) <
						envelope.message.body.len) {
				l_warn("Too long message");
				amqp_basic_nack(context->conn_state, 1,
						envelope.delivery_tag, 0, 0);
				goto cleanup;
			}

			amqp_basic_ack(context->conn_state, 1,
				       envelope.delivery_tag, 0);

			msg.type = REMOTE_CONTROL;

			memcpy(&msg.rc.msg, envelope.message.body.bytes,
						envelope.message.body.len);
			msg.rc.msg_len = envelope.message.body.len;

			send(context->fd, &msg, sizeof(msg), 0);
		cleanup:
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

struct mesh_amqp *mesh_amqp_new(mesh_amqp_rc_send_cb_t rc_send_cb, void *user_data)
{
	struct mesh_amqp *amqp = l_new(struct mesh_amqp, 1);
	memset(amqp, 0, sizeof(*amqp));

	amqp->rc_send_cb = rc_send_cb;
	amqp->user_data = user_data;

	config_set_url(&amqp->config, "");
	config_set_exchange(&amqp->config, "");
	config_set_routing_key(&amqp->config, "");

	return amqp;
}

void mesh_amqp_start(struct mesh_amqp *amqp)
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
		l_free(thread_context);
		return;
	}

	config_set_url(&thread_context->config, amqp->config.url);
	config_set_exchange(&thread_context->config, amqp->config.exchange);
	config_set_routing_key(&thread_context->config, amqp->config.routing_key);

	amqp->thread_started = !pthread_create(&amqp->thread, &attr, amqp_thread, thread_context);
	amqp->queue = l_queue_new();
	amqp->io = l_io_new(fds[0]);

	l_io_set_close_on_destroy(amqp->io, true);
	l_io_set_read_handler(amqp->io, amqp_read_handler, amqp, NULL);
}

void mesh_amqp_free(struct mesh_amqp *amqp)
{
	if (amqp->thread_started) {
		mesh_amqp_stop(amqp);
	}

	l_free(amqp->config.url);
	l_free(amqp->config.exchange);
	l_free(amqp->config.routing_key);

	l_io_destroy(amqp->io);
	l_queue_destroy(amqp->queue, l_free);
	l_free(amqp);
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

const char *mesh_amqp_get_url(struct mesh_amqp *amqp)
{
	return amqp->config.url;
}

static struct set_complete_ctx *new_set_complete_ctx(struct mesh_amqp *amqp,
		mesh_amqp_set_complete_cb_t complete_cb, void *user_data)
{
	struct set_complete_ctx *ctx = l_new(struct set_complete_ctx, 1);
	ctx->complete_cb = complete_cb;
	ctx->user_data = user_data;

	return ctx;
}

static void url_set_complete(struct message *msg, struct mesh_amqp *amqp)
{
	struct set_complete_ctx *ctx = msg->user_data;

	l_debug("url: '%s'", msg->url.value);
	config_set_url(&amqp->config, msg->url.value);

	if (ctx->complete_cb)
		ctx->complete_cb(ctx->user_data);

	l_free(ctx);
}

void mesh_amqp_set_url(struct mesh_amqp *amqp, const char *url,
			mesh_amqp_set_complete_cb_t complete, void *user_data)
{
	struct message *msg = new_message(SET_URL);
	msg->complete_cb = url_set_complete;
	msg->user_data = new_set_complete_ctx(amqp, complete, user_data);

	strncpy(msg->url.value, url ?: "", sizeof(msg->url.value) - 1);

	send_message(amqp, msg);
}

const char *mesh_amqp_get_exchange(struct mesh_amqp *amqp)
{
	return amqp->config.exchange;
}

static void exchange_set_complete(struct message *msg, struct mesh_amqp *amqp)
{
	struct set_complete_ctx *ctx = msg->user_data;

	l_debug("exchange: '%s'", msg->exchange.value);
	config_set_exchange(&amqp->config, msg->exchange.value);

	if (ctx->complete_cb)
		ctx->complete_cb(ctx->user_data);

	l_free(ctx);
}

void mesh_amqp_set_exchange(struct mesh_amqp *amqp, const char *exchange,
			mesh_amqp_set_complete_cb_t complete, void *user_data)
{
	struct message *msg = new_message(SET_EXCHANGE);
	msg->complete_cb = exchange_set_complete;
	msg->user_data = new_set_complete_ctx(amqp, complete, user_data);

	strncpy(msg->exchange.value, exchange ?: "",
					sizeof(msg->exchange.value) - 1);

	send_message(amqp, msg);
}

const char *mesh_amqp_get_routing_key(struct mesh_amqp *amqp)
{
	return amqp->config.routing_key;
}

static void routing_key_set_complete(struct message *msg, struct mesh_amqp *amqp)
{
	struct set_complete_ctx *ctx = msg->user_data;

	l_debug("routing_key: '%s'", msg->routing_key.value);
	config_set_routing_key(&amqp->config, msg->routing_key.value);

	if (ctx->complete_cb)
		ctx->complete_cb(ctx->user_data);

	l_free(ctx);
}

void mesh_amqp_set_routing_key(struct mesh_amqp *amqp, const char *routing_key,
			mesh_amqp_set_complete_cb_t complete, void *user_data)
{
	struct message *msg = new_message(SET_ROUTING_KEY);
	msg->complete_cb = routing_key_set_complete;
	msg->user_data = new_set_complete_ctx(amqp, complete, user_data);

	strncpy(msg->routing_key.value, routing_key ?: "",
				sizeof(msg->routing_key.value) - 1);

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
	struct message msg = {.type = STOP};
	void *ret;

	send(l_io_get_fd(amqp->io), &msg, sizeof(msg), 0);

	pthread_join(amqp->thread, &ret);
	amqp->thread_started = false;

	l_free(ret);
}

bool mesh_amqp_is_ready(struct mesh_amqp *amqp)
{
	return amqp->amqp_state == AMQP_STATE_CONNECTED;
}
