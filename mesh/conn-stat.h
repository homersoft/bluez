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
#include <stdbool.h>
#include <stdint.h>

#include <ell/dbus.h>


struct conn_stat {
	char		*dbus_path;
	struct l_dbus	*dbus;

	bool		connected;
	const char	*last_error;
	uint64_t	tx_msgs_cnt;
	uint64_t	rx_msgs_cnt;
	uint64_t	last_tx_msg_timestamp;
	uint64_t	last_rx_msg_timestamp;
};


struct conn_stat *conn_stat_new(struct l_dbus *dbus,
			const char *adapter_dbus_path, const char *name);

void conn_stat_destroy(struct conn_stat *conn_stat);

bool conn_stat_dbus_init(struct l_dbus *bus);

void conn_stat_connected_set(struct conn_stat *conn_stat, bool connected);

void conn_stat_message_sent(struct conn_stat *conn_stat);

void conn_stat_message_received(struct conn_stat *conn_stat);
