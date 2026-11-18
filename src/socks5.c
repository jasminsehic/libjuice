/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "socks5.h"
#include "tcp.h"
#include "timestamp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SOCKS5_TIMEOUT 5000
#define SOCKS5_MAX_HEADER 22
#define SOCKS5_MAX_DATAGRAM 65507

static int wait_socket(socket_t sock, short events, timestamp_t deadline) {
	while (true) {
		timediff_t remaining = deadline - current_timestamp();
		if (remaining <= 0)
			return -1;
		struct pollfd pfd = {sock, events, 0};
		int ret = poll(&pfd, 1, (int)remaining);
		if (ret > 0)
			return (pfd.revents & events) && !(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) ? 0 : -1;
		if (ret == 0 || sockerrno != SEINTR)
			return -1;
	}
}

static int write_all(socket_t sock, const unsigned char *buffer, size_t size, timestamp_t deadline) {
#ifdef MSG_NOSIGNAL
	int flags = MSG_NOSIGNAL;
#else
	int flags = 0;
#endif
	while (size) {
		if (wait_socket(sock, POLLOUT, deadline))
			return -1;
		int ret = send(sock, (const char *)buffer, (int)size, flags);
		if (ret < 0 && (sockerrno == SEINTR || sockerrno == SEWOULDBLOCK || sockerrno == SEAGAIN))
			continue;
		if (ret <= 0)
			return -1;
		buffer += ret;
		size -= (size_t)ret;
	}
	return 0;
}

static int read_all(socket_t sock, unsigned char *buffer, size_t size, timestamp_t deadline) {
	while (size) {
		if (wait_socket(sock, POLLIN, deadline))
			return -1;
		int ret = recv(sock, (char *)buffer, (int)size, 0);
		if (ret < 0 && (sockerrno == SEINTR || sockerrno == SEWOULDBLOCK || sockerrno == SEAGAIN))
			continue;
		if (ret <= 0)
			return -1;
		buffer += ret;
		size -= (size_t)ret;
	}
	return 0;
}

int socks5_encode_address(const addr_record_t *record, unsigned char *buffer, size_t size) {
	if (record->addr.ss_family == AF_INET && size >= 7) {
		const struct sockaddr_in *addr = (const struct sockaddr_in *)&record->addr;
		buffer[0] = 1;
		memcpy(buffer + 1, &addr->sin_addr, 4);
		memcpy(buffer + 5, &addr->sin_port, 2);
		return 7;
	}
	if (record->addr.ss_family == AF_INET6 && size >= 19) {
		const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)&record->addr;
		buffer[0] = 4;
		memcpy(buffer + 1, &addr->sin6_addr, 16);
		memcpy(buffer + 17, &addr->sin6_port, 2);
		return 19;
	}
	return -1;
}

int socks5_decode_address(const unsigned char *buffer, size_t size, addr_record_t *record) {
	memset(record, 0, sizeof(*record));
	record->socktype = SOCK_DGRAM;
	if (size >= 7 && buffer[0] == 1) {
		struct sockaddr_in *addr = (struct sockaddr_in *)&record->addr;
		addr->sin_family = AF_INET;
		memcpy(&addr->sin_addr, buffer + 1, 4);
		memcpy(&addr->sin_port, buffer + 5, 2);
		record->len = sizeof(*addr);
		return 7;
	}
	if (size >= 19 && buffer[0] == 4) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&record->addr;
		addr->sin6_family = AF_INET6;
		memcpy(&addr->sin6_addr, buffer + 1, 16);
		memcpy(&addr->sin6_port, buffer + 17, 2);
		record->len = sizeof(*addr);
		addr_unmap_inet6_v4mapped((struct sockaddr *)&record->addr, &record->len);
		return 19;
	}
	return -1;
}

static int associate(socks5_t *proxy, const addr_record_t *server, timestamp_t deadline) {
	socket_t sock = proxy->control_sock = tcp_create_socket(server);
	if (sock == INVALID_SOCKET)
		return -1;
#ifdef SO_NOSIGPIPE
	const sockopt_t enabled = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (const char *)&enabled, sizeof(enabled)))
		return -1;
#endif
	if (wait_socket(sock, POLLOUT, deadline))
		return -1;
	int err = 0;
	socklen_t errlen = sizeof(err);
	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen) || err)
		return -1;

	unsigned char method = *proxy->username ? 2 : 0;
	unsigned char greeting[] = {5, 1, method};
	unsigned char response[258];
	if (write_all(sock, greeting, sizeof(greeting), deadline) ||
	    read_all(sock, response, 2, deadline) || response[0] != 5 || response[1] != method)
		return -1;

	if (method == 2) {
		unsigned char auth[513];
		size_t ulen = strlen(proxy->username), plen = strlen(proxy->password);
		auth[0] = 1;
		auth[1] = (unsigned char)ulen;
		memcpy(auth + 2, proxy->username, ulen);
		auth[2 + ulen] = (unsigned char)plen;
		memcpy(auth + 3 + ulen, proxy->password, plen);
		if (write_all(sock, auth, 3 + ulen + plen, deadline) ||
		    read_all(sock, response, 2, deadline) || response[0] != 1 || response[1] != 0)
			return -1;
	}

	// RFC 1928: UDP ASSOCIATE with an unspecified client endpoint.
	const unsigned char request[] = {5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
	if (write_all(sock, request, sizeof(request), deadline) ||
	    read_all(sock, response, 4, deadline) || response[0] != 5 ||
	    response[1] != 0 || response[2] != 0)
		return -1;

	unsigned char type = response[3];
	if (type == 1 || type == 4) {
		size_t length = type == 1 ? 7 : 19;
		response[0] = type;
		if (read_all(sock, response + 1, length - 1, deadline) ||
		    socks5_decode_address(response, length, &proxy->relay) < 0)
			return -1;
	} else if (type == 3) {
		if (read_all(sock, response, 1, deadline) || !response[0])
			return -1;
		size_t length = response[0];
		if (read_all(sock, response, length + 2, deadline))
			return -1;
		char service[8];
		snprintf(service, sizeof(service), "%u",
		         (unsigned int)response[length] * 256 + response[length + 1]);
		response[length] = 0;
		if (addr_resolve((const char *)response, service, SOCK_DGRAM, &proxy->relay, 1) <= 0)
			return -1;
	} else {
		return -1;
	}

	uint16_t port = addr_get_port((const struct sockaddr *)&proxy->relay.addr);
	if (!port)
		return -1;
	if (addr_is_any((const struct sockaddr *)&proxy->relay.addr)) {
		proxy->relay = *server;
		proxy->relay.socktype = SOCK_DGRAM;
		addr_set_port((struct sockaddr *)&proxy->relay.addr, port);
	}
	addr_record_t relay = proxy->relay, local;
	if (udp_get_bound_addr(proxy->udp_sock, &local))
		return -1;
	if (local.addr.ss_family == AF_INET6)
		addr_map_inet6_v4mapped(&relay.addr, &relay.len);
	// Only the associated UDP relay may send to this socket.
	return connect(proxy->udp_sock, (const struct sockaddr *)&relay.addr, relay.len);
}

int socks5_open(socks5_t *proxy, const udp_socket_config_t *config) {
	char service[8];
	snprintf(service, sizeof(service), "%hu", proxy->port);
	addr_record_t records[8];
	int count = addr_resolve(proxy->host, service, SOCK_STREAM, records, 8);
	if (count <= 0)
		return -1;
	if (count > 8)
		count = 8;

	timestamp_t deadline = current_timestamp() + SOCKS5_TIMEOUT;
	for (int i = 0; i < count && current_timestamp() < deadline; ++i) {
		proxy->udp_sock = udp_create_socket(config);
		if (proxy->udp_sock == INVALID_SOCKET)
			return -1;
		if (associate(proxy, records + i, deadline) == 0)
			return 0;
		socks5_close(proxy);
	}
	return -1;
}

void socks5_close(socks5_t *proxy) {
	if (proxy->control_sock != INVALID_SOCKET) {
		closesocket(proxy->control_sock);
		proxy->control_sock = INVALID_SOCKET;
	}
	if (proxy->udp_sock != INVALID_SOCKET) {
		closesocket(proxy->udp_sock);
		proxy->udp_sock = INVALID_SOCKET;
	}
}

int socks5_send(socks5_t *proxy, const addr_record_t *dst, const char *data, size_t size) {
	if (proxy->control_sock == INVALID_SOCKET || proxy->udp_sock == INVALID_SOCKET ||
	    dst->socktype != SOCK_DGRAM)
		return -1;
	unsigned char header[SOCKS5_MAX_HEADER] = {0};
	int length = socks5_encode_address(dst, header + 3, sizeof(header) - 3);
	if (length < 0)
		return -1;
	size_t header_size = (size_t)length + 3;
	if (size > SOCKS5_MAX_DATAGRAM - header_size)
		return -SEMSGSIZE;

	unsigned char stack[4096 + SOCKS5_MAX_HEADER];
	unsigned char *packet = stack;
	if (size + header_size > sizeof(stack)) {
		packet = malloc(size + header_size);
		if (!packet)
			return -1;
	}
	memcpy(packet, header, header_size);
	if (size)
		memcpy(packet + header_size, data, size);
	int ret = send(proxy->udp_sock, (const char *)packet, (int)(size + header_size), 0);
	if (ret < 0)
		ret = -sockerrno;
	else if ((size_t)ret == size + header_size)
		ret = (int)size;
	else
		ret = -1;
	if (packet != stack)
		free(packet);
	return ret;
}

int socks5_recv(socks5_t *proxy, char *buffer, size_t size, addr_record_t *src) {
	unsigned char packet[4096 + SOCKS5_MAX_HEADER + 1];
	addr_record_t outer;
	int ret = udp_recvfrom(proxy->udp_sock, (char *)packet, sizeof(packet), &outer);
	if (ret < 0) {
		int err = sockerrno;
		return err == SEMSGSIZE ? 0 : -err;
	}
	if (ret < 10 || (size_t)ret == sizeof(packet) ||
	    !addr_record_is_equal(&outer, &proxy->relay, true) ||
	    packet[0] || packet[1] || packet[2])
		return 0;

	int length = socks5_decode_address(packet + 3, (size_t)ret - 3, src);
	if (length < 0 || ret <= length + 3 || (size_t)(ret - length - 3) > size)
		return 0;
	ret -= length + 3;
	memcpy(buffer, packet + length + 3, (size_t)ret);
	return ret;
}
