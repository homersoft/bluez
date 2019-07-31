/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/stat.h>
#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "mesh/mesh.h"
#include "mesh/dbus.h"
#include "mesh/mesh-io.h"

static const struct option main_options[] = {
	{ "index",	required_argument,	NULL, 'i' },
	{ "io",		required_argument,	NULL, 'I' },
	{ "config",	optional_argument,	NULL, 'c' },
	{ "nodetach",	no_argument,		NULL, 'n' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "dbus-debug",	no_argument,		NULL, 'b' },
	{ "help",	no_argument,		NULL, 'h' },
	{ }
};

static void usage(void)
{
	fprintf(stderr,
		"Usage:\n"
	       "\tbluetooth-meshd [options]\n");
	fprintf(stderr,
		"Options:\n"
	       "\t--index <hcinum>  Equivalent of `--io=generic:<hcinum>`\n"
	       "\t--io <io>         Use specified io (default: generic)\n"
	       "\t--config          Configuration directory\n"
	       "\t--nodetach        Run in foreground\n"
	       "\t--debug           Enable debug output\n"
	       "\t--dbus-debug      Enable D-Bus debugging\n"
	       "\t--help            Show %s information\n", __func__);
	fprintf(stderr,
	       "io:\n"
	       "\tgeneric[:<index>]\n"
	       "\t\tUse generic HCI io on interface hci<index>, or the first\n"
	       "\t\tavailable one\n"
	       "\tsilvair:<tty>\n"
	       "\t\tUse Silvair Radio SLIP protocol on <tty>\n");
}

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	l_info("Request name %s",
		success ? "success": "failed");

	if (success)
		dbus_init(dbus);
	else
		l_main_quit();
}

static void ready_callback(void *user_data)
{
	struct l_dbus *dbus = user_data;

	l_info("D-Bus ready");
	l_dbus_name_acquire(dbus, BLUEZ_MESH_NAME, false, false, false,
						request_name_callback, NULL);

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

static bool parse_io(const char *optarg, enum mesh_io_type *type, void **opts)
{
	if (strstr(optarg, "generic") == optarg) {
		int *index = l_new(int, 1);

		*type = MESH_IO_TYPE_GENERIC;
		*opts = index;

		optarg += strlen("generic");
		if (!*optarg) {
			*index = MGMT_INDEX_NONE;
			return true;
		}

		if (*optarg != ':')
			return false;

		optarg++;

		if (sscanf(optarg, "hci%d", index) == 1)
			return true;

		if (sscanf(optarg, "%d", index) == 1)
			return true;

		return false;
	}

	if (strstr(optarg, "silvair") == optarg) {
		*type = MESH_IO_TYPE_SILVAIR;

		optarg += strlen("silvair");

		if (*optarg != ':')
			return false;

		optarg++;

		*opts = l_strdup(optarg);

		return true;
	}

	return false;
}

int main(int argc, char *argv[])
{
	int status;
	bool detached = true;
	bool dbus_debug = false;
	struct l_dbus *dbus = NULL;
	const char *config_dir = NULL;
	enum mesh_io_type io_type = MESH_IO_TYPE_NONE;
	char *io = NULL;
	void *io_opts = NULL;

	if (!l_main_init())
		return -1;

	l_log_set_stderr();

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "i:c:ndbh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'i':
			if (io) {
				l_error("Use either --index or --io, not both");
				status = EXIT_SUCCESS;
				goto done;
			}
			io = l_strdup_printf("generic:%s", optarg);
			break;
		case 'I':
			if (io) {
				l_error("Use either --index or --io, not both");
				status = EXIT_SUCCESS;
				goto done;
			}
			io = l_strdup(optarg);
			break;
		case 'n':
			detached = false;
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

	if (!io)
		io = l_strdup_printf("generic");

	if (!parse_io(io, &io_type, &io_opts)) {
		l_error("Invalid io: %s", io);
		status = EXIT_FAILURE;
		goto done;
	}

	if ((io_type == MESH_IO_TYPE_NONE) && !io_opts) {
		int *index = l_new(int, 1);
		*index = MGMT_INDEX_NONE;
		io_type = MESH_IO_TYPE_GENERIC;
		io_opts = index;
	}

	if (!mesh_init(config_dir, io_type, io_opts)) {
		l_error("Failed to initialize mesh");
		status = EXIT_FAILURE;
		goto done;
	}

	if (!detached)
		umask(0077);

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	if (!dbus) {
		l_error("unable to connect to D-Bus");
		status = EXIT_FAILURE;
		goto done;
	}

	if (dbus_debug)
		l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);
	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	if (!l_dbus_object_manager_enable(dbus)) {
		l_error("Failed to enable Object Manager");
		status = EXIT_FAILURE;
		goto done;
	}

	status = l_main_run_with_signal(signal_handler, NULL);

done:
	if (io)
		l_free(io);

	if (io_opts)
		l_free(io_opts);

	mesh_cleanup();
	l_dbus_destroy(dbus);
	l_main_exit();

	return status;
}
