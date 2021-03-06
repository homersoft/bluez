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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mesh/fd_msg.h"

struct mesh_amqp;
struct mesh_node;

enum mesh_amqp_state {
	MESH_AMQP_STATE_DISCONNECTED = 0,
	MESH_AMQP_STATE_CONNECTING,
	MESH_AMQP_STATE_CONNECTED,
};

struct mesh_amqp_config {
	char *url;
	char *exchange;
	char *identity;
	char *uuid;
};

typedef void (*mesh_amqp_complete_cb_t)(bool result, void *user_data);
typedef void (*mesh_amqp_rc_send_cb_t)(struct fd_msg *msg, size_t msg_len,
							void *user_data);

struct mesh_amqp *mesh_amqp_new(mesh_amqp_rc_send_cb_t rc_send_cb,
						struct mesh_node *node);
void mesh_amqp_free(struct mesh_amqp *amqp);

const char *mesh_amqp_get_url(struct mesh_amqp *amqp);
void mesh_amqp_set_url(struct mesh_amqp *amqp, const char *url,
			mesh_amqp_complete_cb_t complete, void *user_data);

const char *mesh_amqp_get_exchange(struct mesh_amqp *amqp);
void mesh_amqp_set_exchange(struct mesh_amqp *amqp, const char *exchange,
			mesh_amqp_complete_cb_t complete, void *user_data);

const char *mesh_amqp_get_identity(struct mesh_amqp *amqp);
void  mesh_amqp_set_identity(struct mesh_amqp *amqp, const char *identity,
			mesh_amqp_complete_cb_t complete, void *user_data);

enum mesh_amqp_state mesh_amqp_get_state(struct mesh_amqp *amqp);

void mesh_amqp_publish(struct mesh_amqp *amqp, const void *data, size_t size);
void mesh_amqp_subscribe(struct mesh_amqp *amqp, const char *topic,
			mesh_amqp_complete_cb_t complete, void *user_data);
void mesh_amqp_unsubscribe(struct mesh_amqp *amqp, const char *topic,
			mesh_amqp_complete_cb_t complete, void *user_data);

void mesh_amqp_start(struct mesh_amqp *amqp);
void mesh_amqp_stop(struct mesh_amqp *amqp);

bool mesh_amqp_is_ready(struct mesh_amqp *amqp);

struct l_queue *mesh_amqp_get_opcodes_whitelist(struct mesh_amqp *amqp);
