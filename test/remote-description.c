/**
 * Copyright (c) 2026
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "agent.h"

#include <stdio.h>
#include <string.h>

int test_remote_description_early_stun(void) {
	juice_config_t config = {0};
	juice_agent_t *agent = juice_create(&config);
	if (!agent)
		return -1;

	// Pretend that gathering has finished, so a genuine, authenticated ICE
	// Binding request can be processed without starting a network socket.
	agent->state = JUICE_STATE_CONNECTING;
	agent->mode = AGENT_MODE_CONTROLLED;

	stun_message_t request = {0};
	request.msg_class = STUN_CLASS_REQUEST;
	request.msg_method = STUN_METHOD_BINDING;
	request.priority = 123456789;
	request.has_ice_controlling = true;
	request.ice_controlling = 1;
	snprintf(request.credentials.username, sizeof(request.credentials.username), "%s:%s",
	         agent->local.ice_ufrag, "remote");

	char packet[512];
	int const size = stun_write(packet, sizeof(packet), &request, agent->local.ice_pwd);
	if (size <= 0) {
		juice_destroy(agent);
		return -1;
	}

	// An early connectivity check arrives from the public, NAT-mapped endpoint.
	struct sockaddr_in address = {0};
	address.sin_family = AF_INET;
	address.sin_port = htons(17212);
	if (inet_pton(AF_INET, "79.127.184.208", &address.sin_addr) != 1) {
		juice_destroy(agent);
		return -1;
	}
	addr_record_t source = {0};
	memcpy(&source.addr, &address, sizeof(address));
	source.len = sizeof(address);
	source.socktype = SOCK_DGRAM;

	// The Binding response cannot be transmitted without a socket, but the
	// receive path must still learn a remote peer-reflexive ICE candidate.
	(void)agent_input(agent, packet, (size_t)size, &source, NULL);
	bool const learned = agent->remote.candidates_count == 1 &&
	                     agent->candidate_pairs_count == 1 && agent->entries_count == 1 &&
	                     agent->remote.candidates[0].type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE &&
	                     agent->candidate_pairs[0].remote == &agent->remote.candidates[0] &&
	                     agent->entries[0].pair == &agent->candidate_pairs[0] &&
	                     addr_record_is_equal(&agent->entries[0].record, &source, true);
	if (!learned) {
		fprintf(stderr, "Early STUN Binding request did not create the expected ICE pair\n");
		juice_destroy(agent);
		return -1;
	}

	ice_candidate_pair_t *pair = &agent->candidate_pairs[0];
	agent_stun_entry_t *entry = &agent->entries[0];
	uint32_t const original_priority = pair->remote->priority;
	uint64_t const original_pair_priority = pair->priority;

	// The remote SDP arrives later and advertises a private host candidate,
	// plus the endpoint already learned by the early peer-reflexive check.
	// Existing pairs remain stable; signaling supplies the authoritative
	// type, priority and foundation, without creating a duplicate pair.
	char const sdp[] =
	    "a=ice-ufrag:remote\r\n"
	    "a=ice-pwd:0123456789012345678901\r\n"
	    "a=candidate:1 1 UDP 2100000000 172.18.0.6 51029 typ host\r\n"
	    "a=candidate:2 1 UDP 2114000000 79.127.184.208 17212 typ srflx\r\n";
	if (juice_set_remote_description(agent, sdp) != JUICE_ERR_SUCCESS) {
		fprintf(stderr, "Failed to apply late remote SDP\n");
		juice_destroy(agent);
		return -1;
	}

	// Previously registered pairs must not silently change their remote
	// candidate when agent_set_remote_description() replaces the description.
	bool const preserved = pair->remote &&
	                       pair->remote == &agent->remote.candidates[0] &&
	                       pair->remote->type == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE &&
	                       pair->remote->priority == 2114000000 &&
	                       original_priority != pair->remote->priority &&
	                       strcmp(pair->remote->foundation, "2") == 0 &&
	                       pair->priority != original_pair_priority &&
	                       addr_record_is_equal(&pair->remote->resolved, &source, true) &&
	                       addr_record_is_equal(&entry->record, &source, true) &&
	                       agent->remote.candidates_count == 2 &&
	                       agent->candidate_pairs_count == 2 &&
	                       agent->entries_count == 2 &&
	                       agent->ordered_pairs[0] == pair;
	if (!preserved) {
		char candidate[ADDR_MAX_STRING_LEN];
		char transport[ADDR_MAX_STRING_LEN];
		if (pair->remote)
			addr_record_to_string(&pair->remote->resolved, candidate, sizeof(candidate));
		else
			snprintf(candidate, sizeof(candidate), "missing");
		addr_record_to_string(&entry->record, transport, sizeof(transport));
		fprintf(stderr,
		        "BUG: late remote SDP overwrote a live early-check candidate: "
		        "pair remote=%s (type=%d), transport=%s\n",
		        candidate, pair->remote ? (int)pair->remote->type : -1, transport);
	}

	// The same reconciliation must also work for candidates received later
	// through the trickle API, without resetting a succeeded/nominated pair.
	bool const first_update_ok = preserved;
	pair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
	pair->nominated = true;
	char const trickled[] =
	    "a=candidate:3 1 UDP 2115000000 79.127.184.208 17212 typ srflx";
	bool const trickle_ok =
	    juice_add_remote_candidate(agent, trickled) == JUICE_ERR_SUCCESS &&
	    pair->remote == &agent->remote.candidates[0] &&
	    pair->remote->priority == 2115000000 &&
	    strcmp(pair->remote->foundation, "3") == 0 &&
	    pair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED && pair->nominated &&
	    agent->candidate_pairs_count == 2 && agent->entries_count == 2 &&
	    agent->ordered_pairs[0] == pair &&
	    addr_record_is_equal(&entry->record, &source, true);
	if (!trickle_ok)
		fprintf(stderr, "Trickled candidate metadata / pair priority regression failed\n");

	juice_destroy(agent);
	return first_update_ok && trickle_ok ? 0 : -1;
}
