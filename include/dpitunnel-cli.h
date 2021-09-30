#ifndef DPITUNNEL_CLI_H
#define DPITUNNEL_CLI_H

#include <map>
#include <string>

enum Desync_zero_attacks {
	DESYNC_ZERO_FAKE,
	DESYNC_ZERO_RST,
	DESYNC_ZERO_RSTACK,
	DESYNC_ZERO_NONE
};

enum Desync_first_attacks {
	DESYNC_FIRST_DISORDER,
	DESYNC_FIRST_DISORDER_FAKE,
	DESYNC_FIRST_SPLIT,
	DESYNC_FIRST_SPLIT_FAKE,
	DESYNC_FIRST_NONE
};

static const std::map<Desync_zero_attacks, std::string> ZERO_ATTACKS_NAMES = {
	{DESYNC_ZERO_FAKE, "fake"},
	{DESYNC_ZERO_RST, "rst"},
	{DESYNC_ZERO_RSTACK, "rstack"}
};

static const std::map<Desync_first_attacks, std::string> FIRST_ATTACKS_NAMES = {
	{DESYNC_FIRST_DISORDER, "disorder"},
	{DESYNC_FIRST_DISORDER_FAKE, "disorder_fake"},
	{DESYNC_FIRST_SPLIT, "split"},
	{DESYNC_FIRST_SPLIT_FAKE, "split_fake"}
};

struct Profile_s {
	unsigned int buffer_size = 512;
	unsigned int split_position = 3;
	unsigned short fake_packets_ttl = 10;
	unsigned short window_size = 0;
	short window_scale_factor = -1;

	std::string doh_server = "https://dns.google/dns-query";

	bool split_at_sni = false;
	bool desync_attacks = false;
	bool doh = false;

	Desync_zero_attacks desync_zero_attack = DESYNC_ZERO_NONE;
	Desync_first_attacks desync_first_attack = DESYNC_FIRST_NONE;
};

struct Settings_perst_s {
	unsigned short test_ssl_handshake_timeout = 5;
	unsigned short packet_capture_timeout = 5000;
	unsigned int count_hops_connect_timeout = 1000;
	int server_port = 8080;
	std::string server_address = "0.0.0.0";
	std::string ca_bundle_path = "./ca.bundle";
	std::string ca_bundle;
	bool daemon = false;
};

#endif //DPITUNNEL_CLI_H
