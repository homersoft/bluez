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

struct mesh_amqp;

struct mesh_amqp *mesh_amqp_new(void);
void mesh_amqp_free(struct mesh_amqp *amqp);

const char *mesh_amqp_get_url(struct mesh_amqp *amqp);
bool mesh_amqp_set_url(struct mesh_amqp *amqp, const char *url);
const char *mesh_amqp_get_exchange(struct mesh_amqp *amqp);
bool mesh_amqp_set_exchange(struct mesh_amqp *amqp, const char *exchange);
const char *mesh_amqp_get_routing_key(struct mesh_amqp *amqp);
bool mesh_amqp_set_routing_key(struct mesh_amqp *amqp, const char *routing_key);
void mesh_amqp_publish(struct mesh_amqp *amqp, const void *data, size_t size);
void mesh_amqp_close(struct mesh_amqp *amqp);
void mesh_amqp_start(struct mesh_amqp *amqp);
