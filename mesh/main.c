/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017-2018  Intel Corporation. All rights reserved.
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
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>

#include <sys/stat.h>
#include <ell/ell.h>

#include <dbus/dbus.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "mesh/mesh.h"
#include "mesh/net.h"
#include "mesh/dbus.h"
#include "mesh/storage.h"

static const struct option main_options[] = {
	{ "index",	required_argument,	NULL, 'i' },
	{ "config",	optional_argument,	NULL, 'c' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "debug-bus",	no_argument,		NULL, 'b' },
	{ "system-bus",	no_argument,		NULL, 'S' },
	{ "session-bus",	no_argument,		NULL, 's' },
	{ "help",	no_argument,		NULL, 'h' },
	{ }
};

struct mesh_config {
	int hci_idx;
	char *cfg_dir;
	struct l_dbus *dbus;
};

static void usage(void)
{
	l_info("");
	l_info("Usage:\n"
	       "\tmeshd [options]\n");
	l_info("Options:\n"
	       "\t-i, --index <hcinum>  Use specified controller\n"
	       "\t-c, --config          Configuration directory\n"
	       "\t--debug               Enable debug output\n"
	       "\t--debug-bus           Enable dbus debug output\n"
	       "\t--system-bus          Connect to system bus (default)\n"
	       "\t--session-bus         Connect to session bus\n"
	       "\t--help                Show %s information\n", __func__);
}

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	struct mesh_config *cfg = user_data;

	l_info("Request name %s",
		success ? "success" : "failed");

	if (success) {
		dbus_init(dbus);

		if (!mesh_init(cfg->hci_idx, cfg->cfg_dir))
			l_error("Failed to initialize mesh");
	} else
		l_main_quit();
}

static void ready_callback(void *user_data)
{
	struct mesh_config *cfg = user_data;

	l_info("D-Bus ready");
	l_dbus_name_acquire(cfg->dbus, BLUEZ_MESH_NAME, false, false, false,
						request_name_callback, cfg);

}

static void disconnect_callback(void *user_data)
{
	l_main_quit();
}

static void signal_handler(uint32_t signo, void *user_data)
{
	static bool terminated;

	if (terminated)
		return;

	l_info("Terminating");
	l_main_quit();
	terminated = true;
}

int main(int argc, char *argv[])
{
	int status;
	bool dbus_debug = false;
	enum l_dbus_bus dbus_bus = L_DBUS_SYSTEM_BUS;
	struct l_dbus *dbus = NULL;
	const char *config_dir = NULL;
	int index = MGMT_INDEX_NONE;
	struct mesh_config cfg;

	if (!l_main_init())
		return -1;

	l_log_set_stderr();

	for (;;) {
		int opt;
		const char *str;

		opt = getopt_long(argc, argv, "i:c:", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'i':
			if (strlen(optarg) > 3 && !strncmp(optarg, "hci", 3))
				str = optarg + 3;
			else
				str = optarg;
			if (!isdigit(*str)) {
				l_error("Invalid controller index value");
				status = EXIT_FAILURE;
				goto done;
			}

			index = atoi(str);

			break;
		case 'd':
			l_debug_enable("*");
			break;
		case 'c':
			config_dir = optarg;
			break;
		case 'b':
			dbus_debug = true;
			break;
		case 'S':
			dbus_bus = L_DBUS_SYSTEM_BUS;
			break;
		case 's':
			dbus_bus = L_DBUS_SESSION_BUS;
			break;
		case 'h':
			usage();
			status = EXIT_SUCCESS;
			goto done;
		default:
			usage();
			status = EXIT_FAILURE;
			goto done;
		}
	}

	umask(0077);

	cfg.cfg_dir = (char *)config_dir;
	cfg.hci_idx = index;

	dbus = l_dbus_new_default(dbus_bus);
	if (!dbus) {
		l_error("unable to connect to D-Bus");
		status = EXIT_FAILURE;
		goto done;
	}

	cfg.dbus = dbus;

	if (dbus_debug)
		l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);

	l_dbus_set_ready_handler(dbus, ready_callback, &cfg, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	if (!l_dbus_object_manager_enable(dbus)) {
		l_error("Failed to enable Object Manager");
		status = EXIT_FAILURE;
		goto done;
	}

	status = l_main_run_with_signal(signal_handler, NULL);

done:
	mesh_cleanup();
	l_dbus_destroy(dbus);
	l_main_exit();

	return status;
}
