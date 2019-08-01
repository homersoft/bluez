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
#include <time.h>

#include <ell/ell.h>

#include "mesh/conn-stat.h"
#include "mesh/dbus.h"
#include "mesh/util.h"


static const char *PROPERTY_CONNECTED = "Connected";
static const char *PROPERTY_LAST_ERROR = "LastError";
static const char *PROPERTY_TX_MSG_CNT = "TransmittedMsgCount";
static const char *PROPERTY_RX_MSG_CNT = "ReceivedMsgCount";
static const char *PROPERTY_LAST_TX_MSG_TS = "LastTransmittedMsgTimestamp";
static const char *PROPERTY_LAST_RX_MSG_TS = "LastReceivedMsgTimestamp";

static const char *CONN_STAT_IFACE = "org.bluez.mesh.ConnectionStat1"
;


static bool connected_getter(struct l_dbus *dbus,
			     struct l_dbus_message *message,
			     struct l_dbus_message_builder *builder,
			     void *user_data)
{
	struct conn_stat *conn_stat = user_data;

	return l_dbus_message_builder_append_basic(builder, 'b',
						   &conn_stat->connected);
}

static bool last_error_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct conn_stat *conn_stat = user_data;

	if (!conn_stat->last_error)
		return false;

	return l_dbus_message_builder_append_basic(builder, 's',
						   conn_stat->last_error);
}

static bool transmitted_msg_count_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct conn_stat *conn_stat = user_data;

	return l_dbus_message_builder_append_basic(builder, 't',
						   &conn_stat->tx_msgs_cnt);
}

static bool received_msg_count_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct conn_stat *conn_stat = user_data;

	return l_dbus_message_builder_append_basic(builder, 't',
						   &conn_stat->rx_msgs_cnt);
}

static bool last_transmitted_msg_timestamp_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct conn_stat *conn_stat = user_data;

	return l_dbus_message_builder_append_basic(builder, 't',
					   &conn_stat->last_tx_msg_timestamp);
}

static bool last_received_msg_timestamp_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct conn_stat *conn_stat = user_data;

	return l_dbus_message_builder_append_basic(builder, 't',
					&conn_stat->last_rx_msg_timestamp);
}

static void setup_adpt_status_iface(struct l_dbus_interface *iface)
{
	l_dbus_interface_property(iface, PROPERTY_CONNECTED, 0, "b",
				  connected_getter, NULL);

	l_dbus_interface_property(iface, PROPERTY_LAST_ERROR, 0, "s",
				  last_error_getter, NULL);

	l_dbus_interface_property(iface, PROPERTY_TX_MSG_CNT, 0, "t",
				  transmitted_msg_count_getter, NULL);

	l_dbus_interface_property(iface, PROPERTY_RX_MSG_CNT, 0, "t",
				  received_msg_count_getter, NULL);

	l_dbus_interface_property(iface, PROPERTY_LAST_TX_MSG_TS, 0, "t",
				  last_transmitted_msg_timestamp_getter, NULL);

	l_dbus_interface_property(iface, PROPERTY_LAST_RX_MSG_TS, 0, "t",
				  last_received_msg_timestamp_getter, NULL);
}

bool conn_stat_dbus_init(void)
{
	if (!l_dbus_register_interface(dbus_get_bus(), CONN_STAT_IFACE,
				       setup_adpt_status_iface, NULL, false)) {

		l_info("Unable to register %s interface",
		       CONN_STAT_IFACE);

		return false;
	}

	return true;
}

static bool create_dbus_object(struct conn_stat *conn_stat)
{
	if (!l_dbus_object_add_interface(dbus_get_bus(),
					 conn_stat->dbus_path,
					 L_DBUS_INTERFACE_PROPERTIES,
					 conn_stat)) {
		l_error("Failed to add D-Bus interface: '%s' to object: '%s'",
			L_DBUS_INTERFACE_PROPERTIES, conn_stat->dbus_path);

		return false;
	}

	if (!l_dbus_object_add_interface(dbus_get_bus(),
					 conn_stat->dbus_path,
					 CONN_STAT_IFACE, conn_stat)) {
		l_error("Failed to add D-Bus interface: '%s' to object: '%s'",
			CONN_STAT_IFACE, conn_stat->dbus_path);

		return false;
	}

	return true;
}

static void destroy_dbus_object(struct conn_stat *conn_stat)
{
	l_dbus_object_remove_interface(dbus_get_bus(),
				       conn_stat->dbus_path,
				       L_DBUS_INTERFACE_PROPERTIES);

	l_dbus_object_remove_interface(dbus_get_bus(),
				       conn_stat->dbus_path,
				       CONN_STAT_IFACE);

	l_dbus_unregister_object(dbus_get_bus(), conn_stat->dbus_path);
}

struct conn_stat *conn_stat_new(struct l_dbus *dbus,
				const char *adapter_dbus_path, const char *name)
{
	struct conn_stat *conn_stat;

	conn_stat = l_new(struct conn_stat, 1);

	conn_stat->dbus_path	= l_strdup_printf("%s/%s",
						      adapter_dbus_path, name);

	if (!create_dbus_object(conn_stat)) {
		l_error("Failed to create D-Bus object.");
		goto fail;
	}

	return conn_stat;

fail:
	conn_stat_destroy(conn_stat);
	return NULL;
}

void conn_stat_destroy(struct conn_stat *conn_stat)
{
	destroy_dbus_object(conn_stat);

	if (conn_stat->dbus_path)
		l_free(conn_stat->dbus_path);

	l_free(conn_stat);
}

void conn_stat_connected_set(struct conn_stat *conn_stat, bool connected)
{
	if (conn_stat->connected == connected)
		return;

	if (connected) {
		conn_stat->tx_msgs_cnt = 0;
		conn_stat->rx_msgs_cnt = 0;
		conn_stat->last_tx_msg_timestamp = 0;
		conn_stat->last_rx_msg_timestamp = 0;
	}

	conn_stat->connected = connected;

	l_dbus_property_changed(dbus_get_bus(), conn_stat->dbus_path,
					CONN_STAT_IFACE, PROPERTY_CONNECTED);

}

void conn_stat_message_sent(struct conn_stat *conn_stat)
{
	conn_stat->tx_msgs_cnt++;
	conn_stat->last_tx_msg_timestamp = time(NULL);
}

void conn_stat_message_received(struct conn_stat *conn_stat)
{
	conn_stat->rx_msgs_cnt++;
	conn_stat->last_rx_msg_timestamp = time(NULL);
}
