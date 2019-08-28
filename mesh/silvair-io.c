#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "ell/util.h"
#include "ell/random.h"

#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"
#include "mesh/silvair-io.h"

#define SLIP_END     0300
#define SLIP_ESC     0333
#define SLIP_ESC_END 0334
#define SLIP_ESC_ESC 0335

enum silvair_phy {
	SILVAIR_PHY_1MBIT	= 0x03,
	SILVAIR_PHY_2MBIT	= 0x04,
	SILVAIR_PHY_NONE	= 0xff,
};

enum silvair_pwr {
	SILVAIR_PWR_PLUS_8_DBM		= 0x08,
	SILVAIR_PWR_PLUS_7_DBM		= 0x07,
	SILVAIR_PWR_PLUS_6_DBM		= 0x06,
	SILVAIR_PWR_PLUS_5_DBM		= 0x05,
	SILVAIR_PWR_PLUS_4_DBM		= 0x04,
	SILVAIR_PWR_PLUS_3_DBM		= 0x03,
	SILVAIR_PWR_PLUS_2_DBM		= 0x02,
	SILVAIR_PWR_ZERO_DBM		= 0x00,
	SILVAIR_PWR_MINUS_4_DB		= 0xFC,
	SILVAIR_PWR_MINUS_8_DBM		= 0xF8,
	SILVAIR_PWR_MINUS_12_DBM	= 0xF4,
	SILVAIR_PWR_MINUS_16_DBM	= 0xF0,
	SILVAIR_PWR_MINUS_20_DBM	= 0xEC,
	SILVAIR_PWR_MINUS_30_DBM	= 0xFF,
	SILVAIR_PWR_MINUS_40_DBM	= 0xD8,
};

enum silvair_pkt_type {
	SILVAIR_EVT_RX		= 0x06,
	SILVAIR_CMD_TX		= 0x18,
	SILVAIR_CMD_RX		= 0x19,
	SILVAIR_CMD_BOOTLOADER	= 0x1A,
	SILVAIR_CMD_FILTER	= 0x1B,
	SILVAIR_EVT_RESET	= 0x1C,
};

struct silvair_pkt_hdr {
	uint8_t				hdr_len;
	uint8_t				pld_len;
	uint8_t				version;
	uint16_t			counter;
	enum silvair_pkt_type		type :8;
} __packed;

struct silvair_rx_evt_hdr {
	uint8_t		hdr_len;
	uint8_t		crc;
	uint8_t		channel;
	uint8_t		rssi;
	uint16_t	counter;
	uint32_t	timestamp;
} __packed;

struct silvair_adv_hdr {
	uint8_t		type	: 4;
	uint8_t		__rfu1	: 2;
	uint8_t		tx_add	: 1;
	uint8_t		rx_add	: 1;
	uint8_t		size	: 6;
	uint8_t		__rfu2	: 2;
} __packed;

struct silvair_rx_evt_pld {
	uint32_t		access_address;
	struct silvair_adv_hdr	header;
	uint8_t			__unused;
	uint8_t			address[6];
	uint8_t			adv_data[0];
} __packed;

struct silvair_tx_cmd_hdr {
	uint8_t			hdr_len;
	uint8_t			channels[8];
	enum silvair_phy	phy : 8;
	enum silvair_pwr	pwr : 8;
	uint16_t		counter;
} __packed;

struct silvair_tx_cmd_pld {
	uint32_t		access_address;
	struct silvair_adv_hdr	header;
	uint8_t			__unused;
	uint8_t			address[6];
	uint8_t			adv_data[0];
} __packed;


typedef bool (*write_cb)(struct mesh_io *io, uint8_t *buf, size_t size,
					uint32_t instant, send_data_cb cb);

static void process_evt_rx(struct mesh_io *io,
					uint32_t instant,
					const struct silvair_pkt_hdr *pkt_hdr,
					size_t len,
					process_packet_cb cb)
{
	const struct silvair_rx_evt_hdr *rx_hdr;
	const struct silvair_rx_evt_pld *rx_pld;
	const uint8_t *adv;
	int8_t rssi;

	if (len < sizeof(*rx_hdr))
		return;

	rx_hdr = (struct silvair_rx_evt_hdr *)(pkt_hdr + 1);
	len -= sizeof(*rx_hdr);

	if (len < sizeof(*rx_pld))
		return;

	rssi = rx_hdr->rssi;

	rx_pld = (struct silvair_rx_evt_pld *)(rx_hdr + 1);

	adv = rx_pld->adv_data;

	while (adv < (const uint8_t *)rx_pld + pkt_hdr->pld_len) {
		uint8_t field_len = adv[0];

		/* Check for the end of advertising data */
		if (field_len == 0)
			break;

		/* Do not continue data parsing if got incorrect length */
		if (adv + field_len + 1 >
			(const uint8_t *)rx_pld + pkt_hdr->pld_len)
			break;

		cb(io->pvt, rssi, instant, adv + 1, field_len);

		adv += field_len + 1;
	}
}

void silvair_process_packet(struct mesh_io *io, uint8_t *buf, size_t size,
					uint32_t instant, process_packet_cb cb)
{
	const struct silvair_pkt_hdr *pkt_hdr;
	size_t len = size;

	if (len < sizeof(*pkt_hdr))
		return;

	pkt_hdr = (struct silvair_pkt_hdr *)buf;
	len -= sizeof(*pkt_hdr);

	switch (pkt_hdr->type) {
	case SILVAIR_EVT_RX:
		process_evt_rx(io, instant, pkt_hdr, len, cb);
		break;
	case SILVAIR_EVT_RESET:
	case SILVAIR_CMD_TX:
	case SILVAIR_CMD_RX:
	case SILVAIR_CMD_BOOTLOADER:
	case SILVAIR_CMD_FILTER:
		break;
	}
}

void silvair_process_slip(struct mesh_io *io, struct slip *slip,
					uint8_t *buf, size_t size,
					uint32_t instant, process_packet_cb cb)
{
	for (uint8_t *i = buf; i != buf + size; ++i) {
		switch (*i) {
		case SLIP_END:
			if (slip->offset)
				silvair_process_packet(io, slip->buf,
							slip->offset, instant,
							cb);

			slip->offset = 0;
			break;

		case SLIP_ESC:
			slip->esc = true;
			break;

		default:
			if (!slip->esc) {
				slip->buf[slip->offset++] = *i;
				break;
			}

			switch (*i) {
			case SLIP_ESC_ESC:
				slip->buf[slip->offset++] = SLIP_ESC;
				break;

			case SLIP_ESC_END:
				slip->buf[slip->offset++] = SLIP_END;
				break;

			default:
				slip->offset = 0;
			}

			slip->esc = false;
		}
	}
}

static bool slip_write(struct mesh_io *io, uint8_t *buf, size_t size,
					uint32_t instant, send_data_cb cb)
{
	static const uint8_t end = SLIP_END;
	static const uint8_t esc_end[2] = { SLIP_ESC, SLIP_ESC_END };
	static const uint8_t esc_esc[2] = { SLIP_ESC, SLIP_ESC_ESC };

	if (!cb(io->pvt, instant, &end, 1))
		return false;

	for (uint8_t *i = buf; i != buf + size; ++i) {
		switch (*i) {
		case SLIP_END:
			if (!cb(io->pvt, instant, esc_end, 2))
				return false;
			break;

		case SLIP_ESC:
			if (!cb(io->pvt, instant, esc_esc, 2))
				return false;
			break;

		default:
			if (cb(io->pvt, instant, i, 1) != 1)
				return false;
		}
	}

	if (!cb(io->pvt, instant, &end, 1))
		return false;

	return true;
}

static bool simple_write(struct mesh_io *io, uint8_t *buf, size_t size,
					uint32_t instant, send_data_cb cb)
{
	return cb(io->pvt, instant, buf, size);
}


static bool send_packet(struct mesh_io *io, uint8_t *buf, size_t size,
				uint32_t instant,
				write_cb write, send_data_cb cb)
{
	uint8_t data[512] = { 0 };
	struct silvair_pkt_hdr *pkt_hdr;
	struct silvair_tx_cmd_hdr *tx_hdr;
	struct silvair_tx_cmd_pld *tx_pld;
	uint8_t *adv_data;
	int len;

	pkt_hdr = (struct silvair_pkt_hdr *)data;
	tx_hdr = (struct silvair_tx_cmd_hdr *)(pkt_hdr + 1);
	tx_pld = (struct silvair_tx_cmd_pld *)(tx_hdr + 1);
	adv_data = tx_pld->adv_data;

	pkt_hdr->hdr_len = sizeof(*pkt_hdr);
	pkt_hdr->pld_len = sizeof(*tx_hdr) + sizeof(*tx_pld) +
							size + 1;
	pkt_hdr->version = 1;
	pkt_hdr->counter = 0; // TODO: L_CPU_TO_BE16(pvt->counter);
	pkt_hdr->type = SILVAIR_CMD_TX;

	tx_hdr->hdr_len = sizeof(*tx_hdr);
	tx_hdr->channels[3] = 0xe0;
	tx_hdr->phy = SILVAIR_PHY_1MBIT;
	tx_hdr->pwr = SILVAIR_PWR_MINUS_8_DBM;

	tx_pld->access_address = L_CPU_TO_BE32(0x8e89bed6);
	/* ADV_NOCONN_IND */
	tx_pld->header.type = 2;

	/* bdaddress + type tag + data */
	tx_pld->header.size = 6 + size + 1;
	tx_hdr->counter = 0; // TODO: L_CPU_TO_BE16(pvt->counter + 1);

	l_getrandom(tx_pld->address, sizeof(tx_pld->address));
	tx_pld->address[5] |= 0xc0;

	adv_data[0] = size;
	memcpy(adv_data + 1, buf, size);

	len = pkt_hdr->hdr_len + pkt_hdr->pld_len;

	return write(io, data, len, instant, cb);
}

bool silvair_send_packet(struct mesh_io *io, uint8_t *buf, size_t size,
					uint32_t instant, send_data_cb cb)
{
	return send_packet(io, buf, size, instant, simple_write, cb);
}

bool silvair_send_slip(struct mesh_io *io, uint8_t *buf, size_t size,
					uint32_t instant, send_data_cb cb)
{
	return send_packet(io, buf, size, instant, slip_write, cb);
}
