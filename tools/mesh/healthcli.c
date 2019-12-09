/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Silvair Inc. All rights reserved.
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

#include <stdio.h>
#include <stdbool.h>

#include <ell/ell.h>

#include "src/shared/shell.h"
#include "src/shared/util.h"

#include "mesh/mesh-defs.h"

#include "tools/mesh/util.h"
#include "tools/mesh/model.h"
#include "tools/mesh/keys.h"
#include "tools/mesh/mesh-db.h"
#include "tools/mesh/remote.h"
#include "tools/mesh/health-model.h"
#include "tools/mesh/healthcli.h"

#define MIN_COMPOSITION_LEN 16
#define NO_RESPONSE 0xFFFFFFFF

/* Default timeout for getting a response to a sent command (seconds) */
#define DEFAULT_TIMEOUT 2

struct health_cmd {
	uint32_t opcode;
	uint32_t rsp;
	const char *desc;
};

struct pending_req {
	struct l_timeout *timer;
	const struct health_cmd *cmd;
	uint16_t addr;
};

static struct l_queue *requests;

static void *send_data;
static model_send_msg_func_t send_msg;

static uint32_t rsp_timeout = DEFAULT_TIMEOUT;
static uint16_t target = UNASSIGNED_ADDRESS;
static uint32_t parms[8];

static struct health_cmd cmds[] = {
	{ OP_ATTENTION_SET, OP_ATTENTION_STATUS, "AttentionSet" },
	{ OP_ATTENTION_STATUS, NO_RESPONSE, "AttentionStatus"},
};

static const struct health_cmd *get_cmd(uint32_t opcode)
{
	uint32_t n;

	for (n = 0; n < L_ARRAY_SIZE(cmds); n++) {
		if (opcode == cmds[n].opcode)
			return &cmds[n];
	}

	return NULL;
}

static const char *opcode_str(uint32_t opcode)
{
	const struct health_cmd *cmd;

	cmd = get_cmd(opcode);
	if (!cmd)
		return "Unknown";

	return cmd->desc;
}

static void free_request(void *a)
{
	struct pending_req *req = a;

	l_timeout_remove(req->timer);
	l_free(req);
}

static struct pending_req *get_req_by_rsp(uint16_t addr, uint32_t rsp)
{
	const struct l_queue_entry *entry;

	entry = l_queue_get_entries(requests);

	for (; entry; entry = entry->next) {
		struct pending_req *req = entry->data;

		if (req->addr == addr && req->cmd->rsp == rsp)
			return req;
	}

	return NULL;
}

static void wait_rsp_timeout(struct l_timeout *timeout, void *user_data)
{
	struct pending_req *req = user_data;

	bt_shell_printf("No response for \"%s\" from %4.4x\n",
						req->cmd->desc, req->addr);

	l_queue_remove(requests, req);
	free_request(req);
}

static void add_request(uint32_t opcode)
{
	struct pending_req *req;
	const struct health_cmd *cmd;

	cmd = get_cmd(opcode);
	if (!cmd)
		return;

	req = l_new(struct pending_req, 1);
	req->cmd = cmd;
	req->addr = target;
	req->timer = l_timeout_create(rsp_timeout,
				wait_rsp_timeout, req, NULL);
	l_queue_push_tail(requests, req);
}

static bool msg_recvd(uint16_t src, uint16_t idx, uint8_t *data,
							uint16_t len)
{
	uint32_t opcode;
	int n;
	struct pending_req *req;

	if (mesh_opcode_get(data, len, &opcode, &n)) {
		len -= n;
		data += n;
	} else
		return false;

	bt_shell_printf("Received %s %08x\n", opcode_str(opcode), opcode);

	req = get_req_by_rsp(src, (opcode & ~OP_UNRELIABLE));
	if (req) {
		free_request(req);
		l_queue_remove(requests, req);
	}

	switch (opcode & ~OP_UNRELIABLE) {
	default:
		return false;

	/* Per Mesh Profile 4.3.3.15 */
	case OP_ATTENTION_STATUS:
		bt_shell_printf("Node %4.4x attention status %d\n",
				src, data[0]);

		break;
	}

	return true;
}

static uint32_t read_input_parameters(int argc, char *argv[])
{
	uint32_t i;

	if (!argc)
		return 0;

	--argc;
	++argv;

	if (!argc || argv[0][0] == '\0')
		return 0;

	for (i = 0; i < L_ARRAY_SIZE(parms) && i < (uint32_t) argc; i++) {
		if (sscanf(argv[i], "%x", &parms[i]) != 1)
			break;
	}

	return i;
}

static void cmd_timeout_set(int argc, char *argv[])
{
	if (read_input_parameters(argc, argv) != 1)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	rsp_timeout = parms[0];

	bt_shell_printf("Timeout to wait for remote node's response: %d secs\n",
								rsp_timeout);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_dst_set(int argc, char *argv[])
{
	uint32_t dst;
	char *end;

	dst = strtol(argv[1], &end, 16);

	if (end != (argv[1] + 4)) {
		bt_shell_printf("Bad unicast address %s: "
				"expected format 4 digit hex\n", argv[1]);
		target = UNASSIGNED_ADDRESS;

		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Talking to node %4.4x\n", dst);
	target = dst;
	set_menu_prompt("health", argv[1]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static bool health_send(uint8_t *buf, uint16_t len, uint32_t opcode)
{
	const struct health_cmd *cmd;
	bool res;

	if (IS_UNASSIGNED(target)) {
		bt_shell_printf("Destination not set\n");
		return false;
	}

	cmd = get_cmd(opcode);
	if (!cmd)
		return false;

	if (get_req_by_rsp(target, cmd->rsp)) {
		bt_shell_printf("Another command is pending\n");
		return false;
	}

	res = send_msg(send_data, target, APP_IDX_DEV_REMOTE, buf, len);
	if (!res)
		bt_shell_printf("Failed to send \"%s\"\n", opcode_str(opcode));

	if (cmd->rsp != NO_RESPONSE)
		add_request(opcode);

	return res;
}

static bool tx_setup(model_send_msg_func_t send_func, void *user_data)
{
	if (!send_func)
		return false;

	send_msg = send_func;
	send_data = user_data;

	return true;
}

static void cmd_attention_set(int argc, char *argv[])
{
	uint16_t n;
	uint8_t msg[32];

	n = mesh_opcode_set(OP_ATTENTION_SET, msg);

	/* By default, set attention timer to 3 seconds */
	msg[n++] = (read_input_parameters(argc, argv) == 1) ? parms[0] : 3;

	if (!health_send(msg, n, OP_ATTENTION_SET))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static const struct bt_shell_menu health_menu = {
	.name = "health",
	.desc = "Health Model Submenu",
	.entries = {
	{"target", "<unicast>", cmd_dst_set,
				"Set target node to configure"},
	{"timeout", "<seconds>", cmd_timeout_set,
				"Set response timeout (seconds)"},
	{"attention-set", "[seconds]", cmd_attention_set,
				"Set attention timeout (seconds)"},
	{} },
};

static struct model_info cli_info = {
	.ops = {
		.set_send_func = tx_setup,
		.set_pub_func = NULL,
		.recv = msg_recvd,
		.bind = NULL,
		.pub = NULL
	},
	.mod_id = HEALTH_CLIENT_MODEL_ID,
	.vendor_id = VENDOR_ID_INVALID
};

struct model_info *healthcli_init(void *user_data)
{
	bt_shell_add_submenu(&health_menu);

	return &cli_info;
}

void healthcli_cleanup(void)
{
	l_queue_destroy(requests, free_request);
}
