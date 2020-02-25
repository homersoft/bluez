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

#define FRAME_BUFFER_SIZE 512
#define SLIP_FRAME_BUFFER_SIZE ((2*FRAME_BUFFER_SIZE) + 2)
#define OUT_RINGBUF_SIZE 4096

#define SLIP_END	0300
#define SLIP_ESC	0333
#define SLIP_ESC_END	0334
#define SLIP_ESC_ESC	0335

static bool io_read_callback(struct l_io *l_io, void *user_data);

static const uint32_t silvair_access_address		= 0x8e89bed6;
static const uint16_t keep_alive_watchdog_period_ms	= 1000;
static const uint16_t disconnect_watchdog_period_ms	= 10000;

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
	enum silvair_pkt_type	type:8;
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
	uint8_t	type:4;
	uint8_t	__rfu1:2;
	uint8_t	tx_add:1;
	uint8_t	rx_add:1;
	uint8_t	size:6;
	uint8_t	__rfu2:2;
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
	enum silvair_phy	phy:8;
	enum silvair_pwr	pwr:8;
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


static void io_error_callback(void *user_data)
{
	struct silvair_io *io = user_data;

	if (io->error_cb)
		io->error_cb(io);
}

static int io_write_tls(struct silvair_io *io, uint8_t *buf, size_t buf_len)
{
	int err;
	int ret;

	if (io->tls_read_wants_write) {
		io->tls_read_wants_write = false;

		l_io_set_read_handler(io->l_io, io_read_callback, io, NULL);
	}

	ret = SSL_write(io->tls_conn, buf, buf_len);
	err = SSL_get_error(io->tls_conn, ret);

	if (err == SSL_ERROR_WANT_READ) {
		io->tls_write_wants_read = true;

		l_io_set_write_handler(io->l_io, NULL, NULL, NULL);
		l_io_set_read_handler(io->l_io, io_read_callback, io, NULL);
	}

	return ret;
}

static bool io_write_callback(struct l_io *l_io, void *user_data)
{
	struct silvair_io *io = user_data;

	if (io->tls_conn) {
		int ret;
		void *buf;
		size_t buf_len;

		buf = l_ringbuf_peek(io->out_ringbuf, 0, &buf_len);

		ret = io_write_tls(io, buf, buf_len);

		switch (SSL_get_error(io->tls_conn, ret)) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return true;

		case SSL_ERROR_NONE:
			break;

		default:
			goto error;
		}

		l_ringbuf_drain(io->out_ringbuf, ret);
	} else {
		(void)l_ringbuf_write(io->out_ringbuf, l_io_get_fd(l_io));
	}

	return l_ringbuf_len(io->out_ringbuf);

error:
	io_error_callback(io);
	return false;
}

static bool simple_write(struct silvair_io *io,
				uint8_t *buf,
				size_t size)
{
	if (l_ringbuf_avail(io->out_ringbuf) < size) {
		l_warn("Write failed. Not enough space in the buffer.");
		return false;
	}

	(void)l_ringbuf_append(io->out_ringbuf, buf, size);

	return l_io_set_write_handler(io->l_io, io_write_callback, io, NULL);
}

static bool slip_write(struct silvair_io *io, uint8_t *buf, size_t size)
{
	static uint8_t end = SLIP_END;
	static uint8_t esc_end[2] = { SLIP_ESC, SLIP_ESC_END };
	static uint8_t esc_esc[2] = { SLIP_ESC, SLIP_ESC_ESC };

	uint8_t slip_buf[SLIP_FRAME_BUFFER_SIZE] = { 0 };
	size_t idx = 0;

	slip_buf[idx++] = end;

	for (uint8_t *i = buf; i != buf + size; ++i) {
		switch (*i) {
		case SLIP_END:
			if (idx + sizeof(esc_end) >= sizeof(slip_buf))
				return false;

			memcpy(slip_buf + idx, esc_end, sizeof(esc_end));
			idx += sizeof(esc_end);
			break;

		case SLIP_ESC:
			if (idx + sizeof(esc_esc) >= sizeof(slip_buf))
				return false;

			memcpy(slip_buf + idx, esc_esc, sizeof(esc_esc));
			idx += sizeof(esc_esc);
			break;

		default:
			if (idx + sizeof(*i) >= sizeof(slip_buf))
				return false;

			slip_buf[idx++] = *i;
			break;
		}
	}

	if (idx + sizeof(end) >= sizeof(slip_buf))
		return false;

	slip_buf[idx++] = end;

	return simple_write(io, slip_buf, idx);
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
		if (io->disconnect_watchdog) {
			l_timeout_remove(io->disconnect_watchdog);
			io->disconnect_watchdog = NULL;
		}
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
				uint8_t *buf,
				size_t size,
				void *user_data)
{
	struct slip *slip = &io->slip;

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

	pkt_hdr = (struct silvair_pkt_hdr *)data;
	pkt_hdr->hdr_len = sizeof(*pkt_hdr);
	pkt_hdr->pld_len = 0;
	pkt_hdr->version = 1;
	pkt_hdr->counter = 0;
	pkt_hdr->type = type;

	if (pkt_hdr->type == SILVAIR_CMD_TX) {
		struct silvair_tx_cmd_hdr *tx_hdr;
		struct silvair_tx_cmd_pld *tx_pld;
		uint8_t *adv_data;

		tx_hdr = (struct silvair_tx_cmd_hdr *)(pkt_hdr + 1);
		tx_pld = (struct silvair_tx_cmd_pld *)(tx_hdr + 1);
		adv_data = tx_pld->adv_data;

		pkt_hdr->pld_len = sizeof(*tx_hdr) + sizeof(*tx_pld) + size;

		tx_hdr->hdr_len = sizeof(*tx_hdr);
		memcpy(tx_hdr->channels, silvair_channels,
						sizeof(tx_hdr->channels));
		tx_hdr->phy = SILVAIR_PHY_1MBIT;
		tx_hdr->pwr = SILVAIR_PWR_MINUS_8_DBM;

		tx_pld->access_address = silvair_access_address;
		tx_pld->header.type = SILVAIR_ADV_TYPE_ADV_NONCONN_IND;

		tx_pld->header.size = sizeof(tx_pld->address) + size;
		tx_hdr->counter = 0;

		l_getrandom(tx_pld->address, sizeof(tx_pld->address));
		tx_pld->address[5] |= 0xc0;

		adv_data[0] = size;
		memcpy(adv_data + 1, buf, size);
	}

	if (pkt_hdr->type == SILVAIR_CMD_KEEP_ALIVE) {
		struct silvair_keep_alive_cmd_pld *keep_alive_pld;

		keep_alive_pld =
			(struct silvair_keep_alive_cmd_pld *)(pkt_hdr + 1);
		memset(keep_alive_pld, 0, sizeof(*keep_alive_pld));

		pkt_hdr->pld_len = sizeof(*keep_alive_pld);
	}

	return pkt_hdr->hdr_len + pkt_hdr->pld_len;
}

static bool send_message(struct silvair_io *io,
				uint8_t *buf,
				size_t size)
{
	int len = 0;
	uint8_t data[FRAME_BUFFER_SIZE] = { 0 };

	len = build_packet(&data[0], buf, size, SILVAIR_CMD_TX);
	return io_write(io, data, len);
}

static bool send_keep_alive_request(struct silvair_io *io,
				uint8_t *buf,
				size_t size)
{
	int len = 0;
	uint8_t data[FRAME_BUFFER_SIZE] = { 0 };

	len = build_packet(&data[0], buf, size, SILVAIR_CMD_KEEP_ALIVE);
	return io_write(io, data, len);
}

static void silvair_process_rx(struct silvair_io *io,
			uint8_t *buf,
			size_t size,
			void *user_data)
{
	if (io->slip.kernel_support)
		process_packet(io, buf, size, user_data);
	else
		process_slip(io, buf, size, user_data);
}

static int io_read_tls(struct silvair_io *io, uint8_t *buf, size_t buf_len)
{
	int err;
	int ret;

	if (io->tls_write_wants_read) {
		io->tls_write_wants_read = false;

		l_io_set_write_handler(io->l_io, io_write_callback, io, NULL);
	}

	ret = SSL_read(io->tls_conn, buf, buf_len);
	err = SSL_get_error(io->tls_conn, ret);

	if (err == SSL_ERROR_WANT_WRITE) {
		io->tls_read_wants_write = true;

		l_io_set_read_handler(io->l_io, NULL, NULL, NULL);
		l_io_set_write_handler(io->l_io, io_write_callback, io, NULL);
	}

	return ret;
}

static bool io_read_callback(struct l_io *l_io, void *user_data)
{
	struct silvair_io *io = user_data;
	struct mesh_io *mesh_io = io->context;
	uint8_t buf[512];
	int r, fd;

	fd = l_io_get_fd(l_io);

	if (fd < 0) {
		l_error("l_io_get_fd error");
		goto error;
	}

	if (io->tls_conn) {
		r = io_read_tls(io, buf, sizeof(buf));

		switch (SSL_get_error(io->tls_conn, r)) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return true;

		case SSL_ERROR_NONE:
			break;

		default:
			goto error;
		}
	} else {
		r = read(fd, buf, sizeof(buf));

		if (r <= 0) {

			if (r != 0) {
				l_error("read error");
				goto error;
			}

			/* Disconnect and remove client from the queue */
			goto error;
		}
	}

	silvair_process_rx(io, buf, r, mesh_io);
	return true;

error:
	io_error_callback(io);
	return false;
}

static void io_disconnect_callback(struct l_io *l_io, void *user_data)
{
	struct silvair_io *io = user_data;

	if (io->disconnect_cb)
		io->disconnect_cb(io);
}

static void sivair_io_send_keepalive(struct silvair_io *io)
{
	if (!send_keep_alive_request(io, NULL, 0)) {
		l_error("write failed: %s", strerror(errno));
		io_error_callback(io);
	}
}

/* This is the communication related timer's callback. It waits for the
 * specified amount of time for the SILVAIR_CMD_KEEP_ALIVE response from
 * the client.
 *
 * The timer will be stopped and cleared when:
 *    - SILVAIR_CMD_KEEP_ALIVE response has been received
 *    - keep_alive_message_timeout() has been refreshed when new mesh packed
 *      has been received
 */
static void keep_alive_communication_timeout(struct l_timeout *timeout,
								void *user_data)
{
	l_error("Keep alive error");
	io_error_callback(user_data);
}

/* This is the internal keep alive timer's callback which should be refreshed
 * when new mesh packet has been received. The refresh can be performed by
 * calling the silvair_io_keep_alive_wdt_refresh() function.
 *
 * When the internal keep_alive_message_timeout() timeouts, the
 * keep_alive_communication_timeout() timer is started in order to check if the
 * UART or ETH cable is connected
 */
static void keep_alive_message_timeout(struct l_timeout *timeout,
								void *user_data)
{
	/* No mesh messages occurred in specified amount of the time.
	 * Check if the communication is still set up
	 */
	struct silvair_io *io = user_data;

	l_info("Keep alive: checking for the communication fd %d...",
							l_io_get_fd(io->l_io));

	/* Send keep alive request */
	sivair_io_send_keepalive(io);
	io->disconnect_watchdog =
		l_timeout_create_ms(disconnect_watchdog_period_ms,
				keep_alive_communication_timeout, io, NULL);
}

void silvair_io_send_message(struct silvair_io *io, uint8_t *buf, size_t size)
{
	if (!send_message(io, buf, size))
		l_error("write failed: %s", strerror(errno));
}

struct silvair_io *silvair_io_new(int fd,
				bool kernel_support,
				process_packet_cb rx_cb,
				io_error_cb error_cb,
				io_disconnect_cb disc_cb,
				void *context, SSL *tls_conn)
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

	io->out_ringbuf = l_ringbuf_new(OUT_RINGBUF_SIZE);

	io->process_rx_cb = rx_cb;
	io->error_cb = error_cb;
	io->tls_conn = tls_conn;

	/* io read destroy callback will be called when io_read_callback */
	 /* return false */
	if (!l_io_set_read_handler(io->l_io, io_read_callback, io, NULL)) {
		l_error("l_io_set_read_handler failed");
		return false;
	}

	io->disconnect_cb = disc_cb;
	if (!l_io_set_disconnect_handler(io->l_io, io_disconnect_callback, io,
								NULL)) {
		l_error("l_io_set_disconnect_handler failed");
		return false;
	}

	io->keep_alive_watchdog =
		l_timeout_create_ms(keep_alive_watchdog_period_ms,
					keep_alive_message_timeout, io, NULL);

	/* Send keep alive request */
	sivair_io_send_keepalive(io);
	return io;
}

void silvair_io_keep_alive_wdt_refresh(struct silvair_io *io)
{
	if (!io)
		return;

	if (!io->keep_alive_watchdog)
		return;

	if (io->disconnect_watchdog) {
		l_timeout_remove(io->disconnect_watchdog);
		io->disconnect_watchdog = NULL;
		l_info("Connection OK");
	}

	l_timeout_modify_ms(io->keep_alive_watchdog,
					keep_alive_watchdog_period_ms);
}

int silvair_io_get_fd(struct silvair_io *io)
{
	return l_io_get_fd(io->l_io);
}

void silvair_io_destroy(struct silvair_io *io)
{
	if (!io)
		return;

	io_error_callback(io);

	if (io->l_io)
		l_io_destroy(io->l_io);

	if (io->out_ringbuf)
		l_ringbuf_free(io->out_ringbuf);

	if (io->keep_alive_watchdog)
		l_timeout_remove(io->keep_alive_watchdog);

	if (io->disconnect_watchdog)
		l_timeout_remove(io->disconnect_watchdog);

	if (io->tls_conn)
		SSL_free(io->tls_conn);
}
