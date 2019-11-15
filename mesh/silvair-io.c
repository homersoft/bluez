#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <ell/ell.h>

#include "mesh/mesh-io.h"
#include "mesh/mesh-io-api.h"
#include "mesh/silvair-io.h"


#define SLIP_END     0300
#define SLIP_ESC     0333
#define SLIP_ESC_END 0334
#define SLIP_ESC_ESC 0335

static const uint32_t silvair_access_address		= 0x8e89bed6;
static const uint16_t keep_alive_watchdog_perios_ms	= 10000;

static const uint8_t silvair_channels[8] = {
	0x00, 0x00, 0x00, 0x0e,
	0x00, 0x00, 0x00, 0x00,
};

enum silvair_adv_type {
	SILVAIR_ADV_TYPE_ADV_IND		= 0x00,
	SILVAIR_ADV_TYPE_ADV_DIRECT_IND		= 0x01,
	SILVAIR_ADV_TYPE_ADV_NONCONN_IND	= 0x02,
};

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
	SILVAIR_CMD_KEEP_ALIVE	= 0x1D,
};

struct silvair_pkt_hdr {
	uint8_t			hdr_len;
	uint8_t			pld_len;
	uint8_t			version;
	uint16_t		counter;
	enum silvair_pkt_type	type :8;
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
	uint8_t	type	: 4;
	uint8_t	__rfu1	: 2;
	uint8_t	tx_add	: 1;
	uint8_t	rx_add	: 1;
	uint8_t	size	: 6;
	uint8_t	__rfu2	: 2;
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

struct silvair_keep_alive_cmd_pld {
	uint8_t		silvair_version_len;

	/* Max supported version: AA.BB.CC-rcDD-12345678\0*/
	char		silvair_version[23];
	uint32_t	reset_reason;
	uint32_t	uptime;
	uint8_t		last_fault_len;
	uint8_t		last_fault[128];
} __packed;


static bool io_write(struct silvair_io *io,
				uint8_t *buf,
				size_t size);

static bool simple_write(struct silvair_io *io,
				uint8_t *buf,
				size_t size)
{
	int w = write(l_io_get_fd(io->l_io), buf, size);

	return (w > 0 && (size_t)w == size);
}

static bool slip_write(struct silvair_io *io,
				uint8_t *buf,
				size_t size)
{
	static uint8_t end = SLIP_END;
	static uint8_t esc_end[2] = { SLIP_ESC, SLIP_ESC_END };
	static uint8_t esc_esc[2] = { SLIP_ESC, SLIP_ESC_ESC };

	if (!simple_write(io, &end, 1))
		return false;

	for (uint8_t *i = buf; i != buf + size; ++i) {
		switch (*i) {

		case SLIP_END:
			if (!simple_write(io, esc_end, 2))
				return false;
			break;

		case SLIP_ESC:
			if (!simple_write(io, esc_esc, 2))
				return false;
			break;

		default:
			if (simple_write(io, i, 1) != 1)
				return false;
		}
	}

	if (!simple_write(io, &end, 1))
		return false;

	return true;
}

static bool io_write(struct silvair_io *io,
				uint8_t *buf,
				size_t size)
{
	if (io->slip.kernel_support)
		return simple_write(io, buf, size);
	else
		return slip_write(io, buf, size);
}

static void process_evt_rx(struct silvair_io *io,
				const struct silvair_pkt_hdr *pkt_hdr,
				size_t len,
				void *user_data)
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

		io->process_rx_cb(io, rssi, adv + 1, field_len, user_data);
		adv += field_len + 1;
	}
}

static void process_evt_keep_alive(struct silvair_io *io,
				const struct silvair_pkt_hdr *pkt_hdr,
				size_t len)
{
	const struct silvair_keep_alive_cmd_pld *keep_alive_pld;

	keep_alive_pld = (struct silvair_keep_alive_cmd_pld *)(pkt_hdr + 1);

	l_info("Version: %s, uptime %u", keep_alive_pld->silvair_version,
							keep_alive_pld->uptime);
}

static void process_packet(struct silvair_io *io,
				uint8_t *buf,
				size_t size,
				void *user_data)
{
	const struct silvair_pkt_hdr *pkt_hdr;
	size_t len = size;

	if (len < sizeof(*pkt_hdr))
		return;

	pkt_hdr = (struct silvair_pkt_hdr *)buf;
	len -= sizeof(*pkt_hdr);

	if (len < pkt_hdr->pld_len)
		return;

	switch (pkt_hdr->type) {

	case SILVAIR_EVT_RX:
		process_evt_rx(io, pkt_hdr, len, user_data);
		break;

	case SILVAIR_CMD_KEEP_ALIVE:
		process_evt_keep_alive(io, pkt_hdr, len);
		break;

	case SILVAIR_EVT_RESET:
	case SILVAIR_CMD_TX:
	case SILVAIR_CMD_RX:
	case SILVAIR_CMD_BOOTLOADER:
	case SILVAIR_CMD_FILTER:
		break;
	}
}

static void process_slip(struct silvair_io *io,
				struct slip *slip,
				uint8_t *buf,
				size_t size,
				void *user_data)
{
	for (uint8_t *i = buf; i != buf + size; ++i) {
		switch (*i) {
		case SLIP_END:
			if (slip->offset)
				process_packet(io, slip->buf, slip->offset,
								user_data);
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

		if (slip->offset >= sizeof(slip->buf)) {
			slip->offset = 0;
			slip->esc = false;
			return;
		}
	}
}

static int build_packet(uint8_t *data,
				uint8_t *buf,
				size_t size,
				enum silvair_pkt_type type)
{
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
	pkt_hdr->counter = 0;
	pkt_hdr->type = type;

	tx_hdr->hdr_len = sizeof(*tx_hdr);
	memcpy(tx_hdr->channels, silvair_channels, sizeof(tx_hdr->channels));
	tx_hdr->phy = SILVAIR_PHY_1MBIT;
	tx_hdr->pwr = SILVAIR_PWR_MINUS_8_DBM;

	tx_pld->access_address = silvair_access_address;
	tx_pld->header.type = SILVAIR_ADV_TYPE_ADV_NONCONN_IND;

	/* bdaddress + type tag + data */
	tx_pld->header.size = 6 + size + 1;
	tx_hdr->counter = 0;

	l_getrandom(tx_pld->address, sizeof(tx_pld->address));
	tx_pld->address[5] |= 0xc0;

	adv_data[0] = size;
	memcpy(adv_data + 1, buf, size);

	len = pkt_hdr->hdr_len + pkt_hdr->pld_len;
	return len;
}

static bool send_message(struct silvair_io *io,
				uint8_t *buf,
				size_t size)
{
	int len = 0;
	uint8_t data[512] = { 0 };

	len = build_packet(&data[0], buf, size, SILVAIR_CMD_TX);
	return io_write(io, data, len);
}

static bool send_keep_alive_request(struct silvair_io *io,
				uint8_t *buf,
				size_t size)
{
	int len = 0;
	uint8_t data[512] = { 0 };

	len = build_packet(&data[0], buf, size, SILVAIR_CMD_KEEP_ALIVE);
	return io_write(io, data, len);
}

static bool io_send(struct silvair_io *io,
				uint8_t *buf,
				size_t size,
				enum packet_type type)
{
	switch (type) {

	case PACKET_TYPE_MESSAGE:
		return send_message(io, buf, size);

	case PACKET_TYPE_KEEP_ALIVE:
		return send_keep_alive_request(io, NULL, 0);

	default:
		l_error("Unsupported type to be sent");
		break;
	}

	return false;
}

static void silvair_process_rx(struct silvair_io *io,
			uint8_t *buf,
			size_t size,
			void *user_data)
{
	if (io->slip.kernel_support)
		process_packet(io, buf, size, user_data);
	else
		process_slip(io, &io->slip, buf, size, user_data);
}

static bool io_read_callback(struct l_io *l_io, void *user_data)
{
	struct silvair_io *io = user_data;
	struct mesh_io *mesh_io = io->context;
	uint8_t buf[512];
	int r, fd;

	fd = l_io_get_fd(l_io);

	if (fd < 0) {
		l_error("fd error");
		return false;
	}

	r = read(fd, buf, sizeof(buf));

	if (r <= 0) {
		l_info("read error");
		return false;
	}

	silvair_process_rx(io, buf, r, mesh_io);
	return true;
}

void silvair_process_tx(struct silvair_io *io,
				uint8_t *buf,
				size_t size,
				enum packet_type type)
{
	if (!io_send(io, buf, size, PACKET_TYPE_MESSAGE)) {
		l_error("write failed: %s", strerror(errno));
		return;
	}
}

struct silvair_io *silvair_io_new(int fd,
				keep_alive_tmout_cb tmout_cb,
				bool kernel_support,
				process_packet_cb rx_cb,
				void *context)
{
	struct silvair_io *io = l_new(struct silvair_io, 1);

	if (!rx_cb) {
		l_error("initialization failed: process_rx_cb is NULL");
		return NULL;
	}

	io->context = context;
	io->slip.offset = 0;
	io->slip.esc = false;

	io->l_io = l_io_new(fd);
	io->slip.kernel_support = kernel_support;

	io->process_rx_cb = rx_cb;

	if (!l_io_set_read_handler(io->l_io, io_read_callback, io, NULL)) {
		l_error("l_io_set_read_handler failed");
		return false;
	}

	if (tmout_cb)
		io->keep_alive_watchdog =
			l_timeout_create_ms(keep_alive_watchdog_perios_ms,
				tmout_cb, io, NULL);
	return io;
}

void silvair_io_kepp_alive_wdt_refresh(struct silvair_io *io)
{
	if (!io)
		return;

	if (!io->keep_alive_watchdog)
		return;

	l_timeout_modify_ms(io->keep_alive_watchdog,
					keep_alive_watchdog_perios_ms);
}
