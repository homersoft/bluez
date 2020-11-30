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

struct mesh_amqp;

struct mesh_amqp_config {
	char *url;
	char *exchange;
	char *routing_key;
};

struct mesh_amqp_rc_message {
    uint8_t flags;
    uint16_t app_idx;
    uint16_t net_idx;
    uint8_t element_idx;
    uint16_t dst_addr;
    uint8_t ttl;
    uint16_t data_len;
    uint8_t data[384];
} __attribute__((packed));

typedef void (*mesh_amqp_set_complete_cb_t)(void *user_data);
typedef void (*mesh_amqp_rc_send_cb_t)(struct mesh_amqp_rc_message *msg,
					void *user_data);

struct mesh_amqp *mesh_amqp_new(mesh_amqp_rc_send_cb_t rc_send_cb, void *user_data);
void mesh_amqp_free(struct mesh_amqp *amqp);

const char *mesh_amqp_get_url(struct mesh_amqp *amqp);
void mesh_amqp_set_url(struct mesh_amqp *amqp, const char *url,
		       mesh_amqp_set_complete_cb_t complete, void *user_data);

const char *mesh_amqp_get_exchange(struct mesh_amqp *amqp);
void mesh_amqp_set_exchange(struct mesh_amqp *amqp, const char *exchange,
			mesh_amqp_set_complete_cb_t complete, void *user_data);

const char *mesh_amqp_get_routing_key(struct mesh_amqp *amqp);
void  mesh_amqp_set_routing_key(struct mesh_amqp *amqp, const char *routing_key,
			mesh_amqp_set_complete_cb_t complete, void *user_data);

void mesh_amqp_publish(struct mesh_amqp *amqp, const void *data, size_t size);

void mesh_amqp_start(struct mesh_amqp *amqp);
void mesh_amqp_stop(struct mesh_amqp *amqp);

bool mesh_amqp_is_ready(struct mesh_amqp *amqp);
