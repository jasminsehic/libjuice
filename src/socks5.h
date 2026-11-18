/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_SOCKS5_H
#define JUICE_SOCKS5_H

#include "udp.h"

typedef struct socks5 {
	char host[256];
	char username[256];
	char password[256];
	uint16_t port;
	bool proxy_hostnames;
	socket_t control_sock;
	socket_t udp_sock;
	addr_record_t relay;
} socks5_t;

int socks5_open(socks5_t *proxy, const udp_socket_config_t *config);
void socks5_close(socks5_t *proxy);
int socks5_send(socks5_t *proxy, const addr_record_t *dst, const char *data, size_t size);
int socks5_send_domain(socks5_t *proxy, const char *host, uint16_t port, const char *data, size_t size);
int socks5_encode_domain(const char *host, uint16_t port, unsigned char *buffer, size_t size);
int socks5_recv(socks5_t *proxy, char *buffer, size_t size, addr_record_t *src);
int socks5_encode_address(const addr_record_t *record, unsigned char *buffer, size_t size);
int socks5_decode_address(const unsigned char *buffer, size_t size, addr_record_t *record);

#endif
