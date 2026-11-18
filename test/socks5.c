/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"

#include "socks5.h"
#include "thread.h"
#include "timestamp.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static int test_addresses(void) {
	const char *hosts[] = {"192.0.2.1", "2001:db8::1"};
	for (int i = 0; i < 2; ++i) {
		addr_record_t original = {0}, decoded;
		original.socktype = SOCK_DGRAM;
		if (i == 0) {
			struct sockaddr_in *addr = (struct sockaddr_in *)&original.addr;
			addr->sin_family = AF_INET;
			addr->sin_port = htons(3478);
			inet_pton(AF_INET, hosts[i], &addr->sin_addr);
			original.len = sizeof(*addr);
		} else {
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&original.addr;
			addr->sin6_family = AF_INET6;
			addr->sin6_port = htons(3478);
			inet_pton(AF_INET6, hosts[i], &addr->sin6_addr);
			original.len = sizeof(*addr);
		}
		unsigned char buffer[19];
		int len = socks5_encode_address(&original, buffer, sizeof(buffer));
		if (len != (i == 0 ? 7 : 19) ||
		    socks5_decode_address(buffer, (size_t)len, &decoded) != len ||
		    !addr_record_is_equal(&original, &decoded, true) ||
		    socks5_decode_address(buffer, (size_t)len - 1, &decoded) >= 0)
			return -1;
	}
	return 0;
}

static int test_refused(void) {
	juice_config_t config = {0};
	juice_agent_t *agent = juice_create(&config);
	if (!agent)
		return -1;

	socket_t refused = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t addrlen = sizeof(addr);
	int ret = -1;
	if (refused == INVALID_SOCKET ||
	    bind(refused, (const struct sockaddr *)&addr, sizeof(addr)) ||
	    getsockname(refused, (struct sockaddr *)&addr, &addrlen))
		goto done;

	juice_socks5_proxy_t proxy = {"127.0.0.1", ntohs(addr.sin_port), NULL, NULL};
	if (juice_set_socks5_proxy(agent, &proxy) != JUICE_ERR_SUCCESS ||
	    juice_set_ice_tcp_mode(agent, JUICE_ICE_TCP_MODE_ACTIVE) == JUICE_ERR_SUCCESS ||
	    juice_gather_candidates(agent) == JUICE_ERR_SUCCESS ||
	    juice_get_state(agent) != JUICE_STATE_FAILED ||
	    juice_gather_candidates(agent) == JUICE_ERR_SUCCESS)
		goto done;

	char sdp[JUICE_MAX_SDP_STRING_LEN];
	if (juice_get_local_description(agent, sdp, sizeof(sdp)) != JUICE_ERR_SUCCESS ||
	    strstr(sdp, "typ host"))
		goto done;

	closesocket(refused);
	refused = INVALID_SOCKET;
	juice_destroy(agent);
	agent = NULL;
	config.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	agent = juice_create(&config);
	if (!agent || juice_set_socks5_proxy(agent, &proxy) == JUICE_ERR_SUCCESS)
		goto done;
	ret = 0;

done:
	if (refused != INVALID_SOCKET)
		closesocket(refused);
	juice_destroy(agent);
	return ret;
}

#ifndef NO_SERVER

typedef struct proxy_fixture {
	socket_t listener;
	socket_t relay;
	socket_t egress;
	uint16_t port;
	uint16_t turn_port;
	bool require_auth;
	atomic(bool) stop;
	atomic(bool) ready;
	atomic(bool) saw_peer;
	atomic(bool) saw_server;
	thread_t thread;
} proxy_fixture_t;

static void sleep_ms(unsigned int ms) {
#ifdef _WIN32
	Sleep(ms);
#else
	struct timespec ts = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000};
	nanosleep(&ts, NULL);
#endif
}

static bool wait_flag(atomic(bool) *flag) {
	timestamp_t deadline = current_timestamp() + 5000;
	while (!atomic_load(flag) && current_timestamp() < deadline)
		sleep_ms(20);
	return atomic_load(flag);
}

static int transfer(socket_t sock, unsigned char *buffer, size_t size, bool writing) {
	timestamp_t deadline = current_timestamp() + 5000;
	while (size) {
		timediff_t remaining = deadline - current_timestamp();
		if (remaining <= 0)
			return -1;
		struct pollfd pfd = {sock, writing ? POLLOUT : POLLIN, 0};
		if (poll(&pfd, 1, (int)remaining) <= 0 || !(pfd.revents & pfd.events))
			return -1;
#ifdef MSG_NOSIGNAL
		int flags = MSG_NOSIGNAL;
#else
		int flags = 0;
#endif
		int ret = writing ? send(sock, (const char *)buffer, (int)size, flags)
		                  : recv(sock, (char *)buffer, (int)size, 0);
		if (ret <= 0)
			return -1;
		size -= (size_t)ret;
		buffer += ret;
	}
	return 0;
}

static int negotiate(proxy_fixture_t *proxy, socket_t sock) {
	unsigned char buffer[10];
	unsigned char method = proxy->require_auth ? 2 : 0;
	if (transfer(sock, buffer, 3, false) || buffer[0] != 5 || buffer[1] != 1 ||
	    buffer[2] != method)
		return -1;
	buffer[0] = 5;
	buffer[1] = method;
	if (transfer(sock, buffer, 2, true))
		return -1;
	if (proxy->require_auth) {
		const unsigned char auth[] = {1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'};
		unsigned char actual[sizeof(auth)];
		if (transfer(sock, actual, sizeof(actual), false) || memcmp(auth, actual, sizeof(auth)))
			return -1;
		buffer[0] = 1;
		buffer[1] = 0;
		if (transfer(sock, buffer, 2, true))
			return -1;
	}
	const unsigned char request[] = {5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
	if (transfer(sock, buffer, sizeof(buffer), false) || memcmp(buffer, request, sizeof(request)))
		return -1;
	uint16_t relay_port = udp_get_port(proxy->relay);
	unsigned char reply[] = {5, 0, 0, 1, 127, 0, 0, 1,
	                         (unsigned char)(relay_port >> 8), (unsigned char)relay_port};
	return transfer(sock, reply, sizeof(reply), true);
}

static thread_return_t THREAD_CALL proxy_run(void *arg) {
	proxy_fixture_t *proxy = arg;
	socket_t control = INVALID_SOCKET;
	while (!atomic_load(&proxy->stop)) {
		struct pollfd pfd = {proxy->listener, POLLIN, 0};
		if (poll(&pfd, 1, 50) > 0) {
			control = accept(proxy->listener, NULL, NULL);
			break;
		}
	}
	if (control == INVALID_SOCKET)
		return (thread_return_t)0;
#ifdef SO_NOSIGPIPE
	const sockopt_t enabled = 1;
	setsockopt(control, SOL_SOCKET, SO_NOSIGPIPE, (const char *)&enabled, sizeof(enabled));
#endif
	if (negotiate(proxy, control))
		goto done;

	atomic_store(&proxy->ready, true);
	addr_record_t client = {0};
	while (!atomic_load(&proxy->stop)) {
		struct pollfd pfds[] = {{control, POLLIN, 0}, {proxy->relay, POLLIN, 0},
		                       {proxy->egress, POLLIN, 0}};
		int ready = poll(pfds, 3, 50);
		if (ready < 0 || pfds[0].revents)
			break;
		if (pfds[1].revents & POLLIN) {
			unsigned char buffer[4096];
			addr_record_t src;
			int len = udp_recvfrom(proxy->relay, (char *)buffer, sizeof(buffer), &src);
			if (len <= 10 || buffer[0] || buffer[1] || buffer[2] || buffer[3] != 1)
				continue;
			client = src;
			addr_record_t dst = {0};
			struct sockaddr_in *addr = (struct sockaddr_in *)&dst.addr;
			addr->sin_family = AF_INET;
			memcpy(&addr->sin_addr, buffer + 4, 4);
			memcpy(&addr->sin_port, buffer + 8, 2);
			dst.len = sizeof(*addr);
			dst.socktype = SOCK_DGRAM;
			if (ntohs(addr->sin_port) == proxy->port)
				atomic_store(&proxy->saw_server, true);
			else {
				if (proxy->turn_port)
					continue; // Force TURN for this test.
				atomic_store(&proxy->saw_peer, true);
			}
			udp_sendto(proxy->egress, (const char *)buffer + 10, (size_t)len - 10, &dst);
		}
		if (pfds[2].revents & POLLIN) {
			unsigned char buffer[4096] = {0, 0, 0, 1};
			addr_record_t src;
			int len = udp_recvfrom(proxy->egress, (char *)buffer + 10, sizeof(buffer) - 10, &src);
			if (len <= 0 || !client.len || src.addr.ss_family != AF_INET)
				continue;
			const struct sockaddr_in *addr = (const struct sockaddr_in *)&src.addr;
			memcpy(buffer + 4, &addr->sin_addr, 4);
			memcpy(buffer + 8, &addr->sin_port, 2);
			udp_sendto(proxy->relay, (const char *)buffer, (size_t)len + 10, &client);
		}
	}

done:
	closesocket(control);
	return (thread_return_t)0;
}

typedef struct test_peer {
	juice_agent_t *other;
	bool proxied;
	bool relay_only;
	atomic(bool) received;
	atomic(bool) gathered;
} test_peer_t;

static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	test_peer_t *peer = user_ptr;
	if (peer->proxied && peer->relay_only && !strstr(sdp, "typ relay"))
		return;
	juice_add_remote_candidate(peer->other, sdp);
}

static void on_gathered(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	test_peer_t *peer = user_ptr;
	atomic_store(&peer->gathered, true);
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)agent;
	test_peer_t *peer = user_ptr;
	if (size == 4 && memcmp(data, "test", 4) == 0)
		atomic_store(&peer->received, true);
}

static bool connected(juice_agent_t *agent) {
	juice_state_t state = juice_get_state(agent);
	return state == JUICE_STATE_CONNECTED || state == JUICE_STATE_COMPLETED;
}

static int test_connection(bool turn) {
	juice_server_credentials_t credentials = {"turn-user", "turn-password", 0};
	juice_server_config_t server_config = {0};
	server_config.bind_address = "127.0.0.1";
	server_config.external_address = "127.0.0.1";
	server_config.credentials = &credentials;
	server_config.credentials_count = 1;
	juice_server_t *server = juice_server_create(&server_config);
	if (!server)
		return -1;

	proxy_fixture_t fixture = {0};
	fixture.listener = fixture.relay = fixture.egress = INVALID_SOCKET;
	fixture.port = juice_server_get_port(server);
	fixture.turn_port = turn ? fixture.port : 0;
	fixture.require_auth = turn;
	bool started = false;
	int ret = -1;
	juice_agent_t *a = NULL, *b = NULL;
	test_peer_t pa = {0}, pb = {0};
	pa.proxied = true;
	pa.relay_only = turn;

	udp_socket_config_t udp_config = {"127.0.0.1", 0, 0};
	fixture.relay = udp_create_socket(&udp_config);
	fixture.egress = udp_create_socket(&udp_config);
	fixture.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t addrlen = sizeof(addr);
	if (!fixture.port || fixture.relay == INVALID_SOCKET || fixture.egress == INVALID_SOCKET ||
	    fixture.listener == INVALID_SOCKET ||
	    bind(fixture.listener, (const struct sockaddr *)&addr, sizeof(addr)) ||
	    getsockname(fixture.listener, (struct sockaddr *)&addr, &addrlen) ||
	    listen(fixture.listener, 1))
		goto done;
	if (thread_init(&fixture.thread, proxy_run, &fixture))
		goto done;
	started = true;

	juice_turn_server_t turn_server = {"127.0.0.1", credentials.username, credentials.password,
	                                  fixture.port};
	juice_config_t config = {0};
	config.bind_address = "127.0.0.1";
	config.cb_candidate = on_candidate;
	config.cb_gathering_done = on_gathered;
	config.cb_recv = on_recv;
	config.user_ptr = &pa;
	if (turn) {
		config.turn_servers = &turn_server;
		config.turn_servers_count = 1;
	} else {
		config.stun_server_host = "127.0.0.1";
		config.stun_server_port = fixture.port;
	}
	a = juice_create(&config);
	config.stun_server_host = NULL;
	config.turn_servers = NULL;
	config.turn_servers_count = 0;
	config.user_ptr = &pb;
	b = juice_create(&config);
	if (!a || !b)
		goto done;
	pa.other = b;
	pb.other = a;

	juice_socks5_proxy_t proxy = {"127.0.0.1", ntohs(addr.sin_port),
	                             turn ? "user" : NULL, turn ? "pass" : NULL};
	char sdp[JUICE_MAX_SDP_STRING_LEN];
	if (juice_set_socks5_proxy(a, &proxy) ||
	    juice_get_local_description(a, sdp, sizeof(sdp)) ||
	    juice_set_remote_description(b, sdp) ||
	    juice_get_local_description(b, sdp, sizeof(sdp)) ||
	    juice_set_remote_description(a, sdp) ||
	    juice_gather_candidates(a) || juice_gather_candidates(b) ||
	    !wait_flag(&fixture.ready) || !wait_flag(&pa.gathered))
		goto done;

	if (juice_get_local_description(a, sdp, sizeof(sdp)) || strstr(sdp, "typ host") ||
	    !strstr(sdp, turn ? "typ relay" : "typ srflx") ||
	    !atomic_load(&fixture.saw_server))
		goto done;

	timestamp_t deadline = current_timestamp() + 5000;
	while ((!connected(a) || !connected(b)) && current_timestamp() < deadline)
		sleep_ms(20);
	if (!connected(a) || !connected(b))
		goto done;

	char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	if (!turn) {
		char expected[JUICE_MAX_ADDRESS_STRING_LEN], actual[JUICE_MAX_ADDRESS_STRING_LEN];
		snprintf(expected, sizeof(expected), "127.0.0.1:%hu", udp_get_port(fixture.egress));
		if (juice_get_selected_addresses(b, NULL, 0, actual, sizeof(actual)) ||
		    strcmp(actual, expected))
			goto done;
	}
	if (juice_get_selected_candidates(a, local, sizeof(local), NULL, 0) ||
	    (turn && !strstr(local, "typ relay")) ||
	    (!turn && (!atomic_load(&fixture.saw_peer) || strstr(local, "typ relay"))) ||
	    juice_send(a, "test", 4) || juice_send(b, "test", 4) ||
	    !wait_flag(&pa.received) || !wait_flag(&pb.received))
		goto done;

	atomic_store(&fixture.stop, true);
	thread_join(fixture.thread, NULL);
	started = false;
	deadline = current_timestamp() + 5000;
	while (juice_get_state(a) != JUICE_STATE_FAILED && current_timestamp() < deadline)
		sleep_ms(20);
	if (juice_get_state(a) != JUICE_STATE_FAILED || juice_send(a, "test", 4) == JUICE_ERR_SUCCESS)
		goto done;

	ret = 0;

done:
	atomic_store(&fixture.stop, true);
	if (started)
		thread_join(fixture.thread, NULL);
	juice_destroy(a);
	juice_destroy(b);
	if (fixture.listener != INVALID_SOCKET)
		closesocket(fixture.listener);
	if (fixture.relay != INVALID_SOCKET)
		closesocket(fixture.relay);
	if (fixture.egress != INVALID_SOCKET)
		closesocket(fixture.egress);
	juice_server_destroy(server);
	return ret;
}

#endif

int test_socks5(void) {
	if (test_addresses() || test_refused())
		return -1;
#ifndef NO_SERVER
	if (test_connection(false) || test_connection(true))
		return -1;
#endif
	return 0;
}
