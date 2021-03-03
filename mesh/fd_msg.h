#ifndef __FD_MSG_H__
#define __FD_MSG_H__

#include <stdint.h>

/* FD message
 *
 *	Flags:
 *
 *		+-------+-----------------------------+
 *		|  bit  |         description         |
 *		+-------+-----------------------------+
 *		|   0   | 0 - app_key / 1 - dev_key   |
 *		|   1   | 0 - local / 1 - remote      |
 *		|   2   | 1 - segmented message       |
 *		| 2 - 7 | RFU                         |
 *		+-------+-----------------------------+
 *
 *		Example:
 *			flags == 0x00: (app_key)
 *			flags == 0x01: (dev_key_local)
 *			flags == 0x03: (dev_key_remote)
 *
 *	TTL:
 *		0x00 - 0x7F - User defined TTL
 *		0xFF - Default TTL
 */

#define FD_MSG_IS_SEGMENTED(msg) (msg->flags & 0x04)

struct fd_msg {
	uint8_t flags;
	uint16_t src_addr;
	uint16_t dst_addr;
	uint8_t element_idx;
	uint16_t app_idx;
	uint16_t net_idx;
	uint8_t ttl;
	uint8_t label[16];
	uint64_t timestamp;
	uint8_t data[];
} __attribute__((packed));


#endif // __FD_MSG_H__
