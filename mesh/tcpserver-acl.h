/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Silvair Inc. All rights reserved.
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
#include <stddef.h>
#include <stdbool.h>

#include <ell/dbus.h>

struct tcpserver_acl;


typedef bool (*on_acl_entry_changed)(struct tcpserver_acl *acl,
			     uint8_t *identity, void *user_data, bool removed);


struct tcpserver_acl *tcpserver_acl_new(const char *config_path,
			const char *dbus_path,
			on_acl_entry_changed on_acl_entry_changed_callback,
			void *user_data);

void tcpserver_acl_destroy(struct tcpserver_acl *acl);

bool tcpserver_acl_dbus_init(struct tcpserver_acl *acl, struct l_dbus *bus);

size_t tcpserver_acl_psk_get(struct tcpserver_acl *acl,
		const char *identity, uint8_t *psk, unsigned int max_psk_len);
