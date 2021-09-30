#include "dpitunnel-cli.h"

#include "autoconf.h"
#include "desync.h"
#include "dns.h"
#include "netiface.h"
#include "packet.h"
#include "profiles.h"
#include "ssl.h"
#include "socket.h"
#include "utils.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <future>
#include <mutex>
#include <thread>
#include <signal.h>
#include <unordered_map>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <poll.h>
#include <unistd.h>

const std::string CONNECTION_ESTABLISHED_RESPONSE("HTTP/1.1 200 Connection established\r\n\r\n");
const std::string CONNECTION_ERROR_RESPONSE("HTTP/1.1 0 Connection establish problem (read logs)\r\n\r\n");
const std::string PROCESS_NAME("DPITunnel-cli");
int Interrupt_pipe[2];
std::atomic<bool> stop_flag;
struct Settings_perst_s Settings_perst;
struct Profile_s Profile;
extern std::map<std::string, struct Profile_s> Profiles;
std::mutex Threads_map_mutex;
std::unordered_map<std::thread::id, std::thread> Threads;

void process_client_cycle(int client_socket) {
	// last_char indicates position of string end
	unsigned int last_char;

	// Set timeouts
	struct timeval timeout_sock;
	timeout_sock.tv_sec = 0;
	timeout_sock.tv_usec = 10;
	if(setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout_sock, sizeof(timeout_sock)) < 0 ||
		setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout_sock, sizeof(timeout_sock)) < 0) {
		std::cerr << "Can't setsockopt on socket. Errno: " << std::strerror(errno) << std::endl;
		close(client_socket);
		return;
	}

	// Receive with timeout
	struct timeval timeout_recv;
	timeout_recv.tv_sec = 5;
	timeout_recv.tv_usec = 0;

	std::string buffer(Profile.buffer_size, ' ');

	if(recv_string(client_socket, buffer, last_char, &timeout_recv) == -1) {
		close(client_socket);
		return;
	}

	bool is_https;
	std::string server_host;
	std::string server_ip;
	int server_port;
	std::string server_method;
	if(parse_request(buffer, server_method, server_host, server_port) == -1) {
		std::cerr << "Can't parse first request" << std::endl;
		send_string(client_socket, CONNECTION_ERROR_RESPONSE, CONNECTION_ERROR_RESPONSE.size());
		close(client_socket);
		return;
	}
	is_https = server_method == "CONNECT";
	// Remove proxy connection specific parts
	if(!is_https) {
		size_t method_end_position = buffer.find(' ');
		if(method_end_position != std::string::npos) {
			if(buffer.find("http://", method_end_position + 1) == method_end_position + 1) {
				buffer.erase(method_end_position + 1, 7);
				last_char -= 7;
			}
			if(buffer.find(server_host, method_end_position + 1) == method_end_position + 1) {
				buffer.erase(method_end_position + 1, server_host.size());
				last_char -= server_host.size();
			}
		}

		size_t proxy_connection_hdr_start = buffer.find("Proxy-Connection: keep-alive\r\n");
		if(proxy_connection_hdr_start != std::string::npos) {
			buffer.erase(proxy_connection_hdr_start, 30);
			last_char -= 30;
		}
	}

	// Resolve server ip
	if(resolve_host(server_host, server_ip) == -1) {
		send_string(client_socket, CONNECTION_ERROR_RESPONSE, CONNECTION_ERROR_RESPONSE.size());
		close(client_socket);
		return;
	}

	// If need get SYN, ACK packet sent by server during handshake
	std::atomic<bool> flag(true);
	std::atomic<int> local_port(-1);
	std::atomic<int> status;
	std::thread sniff_thread;
	std::string sniffed_packet;
	if(Profile.desync_attacks) {
		sniff_thread = std::thread(sniff_handshake_packet, &sniffed_packet,
					server_ip, server_port, &local_port, &flag, &status);
	}

	// Connect to remote server
	int server_socket;
	if(init_remote_server_socket(server_socket, server_ip, server_port) == -1) {
		if(Profile.desync_attacks) {
			// Stop sniff thread
			flag.store(false);
			if(sniff_thread.joinable()) sniff_thread.join();
		}
		send_string(client_socket, CONNECTION_ERROR_RESPONSE, CONNECTION_ERROR_RESPONSE.size());
		close(client_socket);
		return;
	}

	// Disable TCP Nagle's algorithm
	int yes = 1;
	if(setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof(yes)) < 0
		|| setsockopt(server_socket, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof(yes)) < 0) {
		std::cerr << "Can't disable TCP Nagle's algorithm with setsockopt(). Errno: "
				<< std::strerror(errno) << std::endl;
		if(Profile.desync_attacks) {
			// Stop sniff thread
			flag.store(false);
			if(sniff_thread.joinable()) sniff_thread.join();
		}
		send_string(client_socket, CONNECTION_ERROR_RESPONSE, CONNECTION_ERROR_RESPONSE.size());
		close(server_socket);
		close(client_socket);
		return;
	}

	// Get local port to choose proper SYN, ACK packet
	struct sockaddr_in local_addr;
	socklen_t len = sizeof(local_addr);
	if(getsockname(server_socket, (struct sockaddr *) &local_addr, &len) == -1) {
		std::cerr << "Failed to get local port. Errno: " << std::strerror(errno) << std::endl;
		if(Profile.desync_attacks) {
			// Stop sniff thread
			flag.store(false);
			if(sniff_thread.joinable()) sniff_thread.join();
		}
		send_string(client_socket, CONNECTION_ERROR_RESPONSE, CONNECTION_ERROR_RESPONSE.size());
		close(server_socket);
		close(client_socket);
		return;
	}
	local_port.store(ntohs(local_addr.sin_port));

	if(is_https)
		if(send_string(client_socket, CONNECTION_ESTABLISHED_RESPONSE, CONNECTION_ESTABLISHED_RESPONSE.size()) == -1) {
			close(server_socket);
			close(client_socket);
			return;
		}

	if(Profile.desync_attacks) {
		// Get received SYN, ACK packet
		if(sniff_thread.joinable()) sniff_thread.join();
		if(status.load() == -1) {
			std::cerr << "Failed to capture handshake packet" << std::endl;
			send_string(client_socket, CONNECTION_ERROR_RESPONSE, CONNECTION_ERROR_RESPONSE.size());
			close(server_socket);
			close(client_socket);
			return;
		}
		// Get first client packet
		if(is_https) {
				if(recv_string(client_socket, buffer, last_char, &timeout_recv) == -1) {
					close(server_socket);
					close(client_socket);
					return;
				}
		}
		do_desync_attack(server_socket, server_ip, server_port, local_port,
					is_https, sniffed_packet, buffer, last_char);
	// Send packet we received previously if it's http connection
	} else if(!is_https) {
		if(send_string(server_socket, buffer, last_char) == -1) {
			send_string(client_socket, CONNECTION_ERROR_RESPONSE, CONNECTION_ERROR_RESPONSE.size());
			close(server_socket);
			close(client_socket);
			return;
		}
	}

	// Make sockets non-blocking
        if(fcntl(client_socket, F_SETFL, fcntl(client_socket, F_GETFL, 0) | O_NONBLOCK) == -1 ||
		fcntl(server_socket, F_SETFL, fcntl(client_socket, F_GETFL, 0) | O_NONBLOCK) == -1) {
                std::cerr << "Failed to make sockets non-blocking. Errno: " << std::strerror(errno) << std::endl;
        }

	// Client process loop
	struct pollfd fds[3];

	// fds[0] is client socket
	fds[0].fd = client_socket;
	fds[0].events = POLLIN;

	// fds[1] is remote server socket
	fds[1].fd = server_socket;
	fds[1].events = POLLIN;

	// fds[2] is interrupt pipe
	fds[2].fd = Interrupt_pipe[0];
	fds[2].events = POLLIN;

	// Set poll() timeout
	int timeout = -1;

	bool is_transfer_failure = false;

	while(!stop_flag.load() && !is_transfer_failure) {
		int ret = poll(fds, 3, timeout);

		// Check state
		if (ret == -1) {
			std::cerr << "Poll error. Errno:" << std::strerror(errno) << std::endl;
			break;
		} else if (ret == 0)
                                continue;
		else {
			if(fds[0].revents & POLLERR || fds[1].revents & POLLERR ||
			   fds[0].revents & POLLHUP || fds[1].revents & POLLHUP ||
			   fds[0].revents & POLLNVAL || fds[1].revents & POLLNVAL)
				break;

			// Process client socket
			if (fds[0].revents & POLLIN) {
				// Transfer data
				if(recv_string(client_socket, buffer, last_char) == -1)
                			is_transfer_failure = true;

				if(send_string(server_socket, buffer, last_char) == -1)
                        		is_transfer_failure = true;
			}

			// Process server socket
			if (fds[1].revents & POLLIN) {
				// Transfer data
				if(recv_string(server_socket, buffer, last_char) == -1)
					is_transfer_failure = true;

                                if(send_string(client_socket, buffer, last_char) == -1)
					is_transfer_failure = true;
			}

			fds[0].revents = 0;
			fds[1].revents = 0;
			fds[2].revents = 0;
		}
	}

	close(server_socket);
	close(client_socket);
}

void accept_client_cycle(int server_socket) {

	struct pollfd fds[2];

	// fds[0] is a server socket
	fds[0].fd = server_socket;
	fds[0].events = POLLIN;

	// fds[1] is an interrupt pipe
	fds[1].fd = Interrupt_pipe[0];
	fds[1].events = POLLIN;

	// Set poll() timeout
	int timeout = -1;

	while(!stop_flag.load()) {
		int ret = poll(fds, 2, timeout);

		// Check state
		if (ret == -1) {
			std::cerr << "Poll error. Errno:" << std::strerror(errno) << std::endl;
			break;
		} else if (ret == 0)
				continue; // Timeout happened
		else {
			if (fds[0].revents & POLLERR ||
				fds[0].revents & POLLHUP ||
				fds[0].revents & POLLNVAL)
				break;

			//Accept client
			if (fds[0].revents & POLLIN) {
				int client_socket;
				struct sockaddr_in client_address;
				socklen_t client_address_size = sizeof(client_address);

				client_socket = accept(server_socket,
							(sockaddr *) &client_address,
							&client_address_size);
				if(client_socket == -1) {
					std::cerr << "Can't accept client socket. Error: "
							<< std::strerror(errno) << std::endl;
					break;
				}

				// Create new thread
				auto thread_starter = std::promise<void>();
				std::thread t1([starter_future = thread_starter.get_future(), socket = client_socket]() mutable {
					starter_future.wait();
					process_client_cycle(socket);
					// Remove thread from map, contains all running threads
					{
						std::lock_guard<std::mutex> lock(Threads_map_mutex);
						if(!stop_flag.load()) {
							auto found = Threads.find(std::this_thread::get_id());
							if(found != Threads.end()) {
								found->second.detach();
								Threads.erase(std::this_thread::get_id());
							}
						}
					}
					});
				// Add thread to map, contains all running threads
				{
					std::lock_guard<std::mutex> lock(Threads_map_mutex);
					Threads.emplace(t1.get_id(), std::move(t1));
				}
				thread_starter.set_value();
				
			}

			fds[0].revents = 0;
			fds[1].revents = 0;
		}
	}

	// Wait for all threads to finish
	for(auto & imap : Threads)
		if(imap.second.joinable()) imap.second.join();
}

int parse_cmdline(int argc, char* argv[]) {

	const struct option options[] = {
		{"ip", required_argument, 0, 0}, // id 0
		{"port", required_argument, 0, 0}, // id 1
		{"buffer-size", required_argument, 0, 0}, // id 2
		{"split-position", required_argument, 0, 0}, // id 3
		{"ttl", required_argument, 0, 0}, // id 4
		{"use-doh", no_argument, 0, 0}, // id 5
		{"doh-server", required_argument, 0, 0}, //id 6
		{"ca-bundle-path", required_argument, 0, 0}, // id 7
		{"split-at-sni", no_argument, 0, 0}, // id 8
		{"desync-attacks", required_argument, 0, 0}, // id 9
		{"auto", no_argument, 0, 0}, // id 10
		{"help", no_argument, 0, 0}, // id 11
		{"daemon", no_argument, 0, 0}, // id 12
		{"wsize", required_argument, 0, 0}, // id 13
		{"wsfactor", required_argument, 0, 0}, // id 14
		{"profile", required_argument, 0, 0}, // id 15
		{NULL, 0, NULL, 0}
	};

	int res, opt_id = 0;
	std::string curr_profile_name = "";
	struct Profile_s profile;
	while((res = getopt_long_only(argc, argv, "", options, &opt_id)) != -1) {
		if(res) return -1;
		switch(opt_id) {
			case 0: // ip
				Settings_perst.server_address = std::string(optarg);

				break;

			case 1: // port
				Settings_perst.server_port = atoi(optarg);
				if(Settings_perst.server_port < 0 || Settings_perst.server_port > 65535) {
					std::cerr << "-port invalid argument" << std::endl;
					return -1;
				}

				break;

			case 2: // buffer-size
				profile.buffer_size = atoi(optarg);
				if(profile.buffer_size < 128 || profile.buffer_size > 65535) {
					std::cerr << "-buffer-size invalid argument" << std::endl;
					return -1;
				}

				break;

			case 3: // split-position
				profile.split_position = atoi(optarg);
				if(profile.split_position > 65535) {
					std::cerr << "-split-position invalid argument" << std::endl;
					return -1;
				}

				break;

			case 4: // ttl
				profile.fake_packets_ttl = atoi(optarg);
				if(profile.fake_packets_ttl < 1 || profile.fake_packets_ttl > 255) {
					std::cerr << "-ttl invalid argument" << std::endl;
					return -1;
				}

				break;

			case 5: // use-doh
				profile.doh = true;

				break;

			case 6: // doh-server
				profile.doh_server = optarg;

				break;

			case 7: // ca-bundle-path
				Settings_perst.ca_bundle_path = optarg;

				break;

			case 8: // split-at-sni
				profile.split_at_sni = true;

				break;

			case 9: // desync-attacks
				{
					profile.desync_attacks = true;
					char *e,*p = optarg;
					while(p) {
						e = strchr(p,',');
						if(e) *e++=0;

						if(!strcmp(p, ZERO_ATTACKS_NAMES.at(DESYNC_ZERO_FAKE).c_str()))
							profile.desync_zero_attack = DESYNC_ZERO_FAKE;
						else if(!strcmp(p, ZERO_ATTACKS_NAMES.at(DESYNC_ZERO_RST).c_str()))
							profile.desync_zero_attack = DESYNC_ZERO_RST;
						else if(!strcmp(p, ZERO_ATTACKS_NAMES.at(DESYNC_ZERO_RSTACK).c_str()))
							profile.desync_zero_attack = DESYNC_ZERO_RSTACK;
						else if(!strcmp(p, FIRST_ATTACKS_NAMES.at(DESYNC_FIRST_DISORDER).c_str()))
							profile.desync_first_attack = DESYNC_FIRST_DISORDER;
						else if(!strcmp(p, FIRST_ATTACKS_NAMES.at(DESYNC_FIRST_DISORDER_FAKE).c_str()))
							profile.desync_first_attack = DESYNC_FIRST_DISORDER_FAKE;
						else if(!strcmp(p, FIRST_ATTACKS_NAMES.at(DESYNC_FIRST_SPLIT).c_str()))
							profile.desync_first_attack = DESYNC_FIRST_SPLIT;
						else if(!strcmp(p, FIRST_ATTACKS_NAMES.at(DESYNC_FIRST_SPLIT_FAKE).c_str()))
							profile.desync_first_attack = DESYNC_FIRST_SPLIT_FAKE;
						else {
							std::cerr << "-desync-attacks invalid argument" << std::endl;
							return -1;
						}

						p = e;
					}
				}

				break;
			case 10: // auto
				run_autoconf();

				return -2;

			case 11: // help

				return -1;

			case 12: // daemon
				Settings_perst.daemon = true;

				break;

			case 13: // wsize
				profile.window_size = atoi(optarg);
				if(profile.window_size < 1 || profile.window_size > 65535) {
					std::cerr << "-wsize invalid argument" << std::endl;
					return -1;
				}

				break;

			case 14: // wsfactor
				profile.window_scale_factor = atoi(optarg);
				if(profile.window_scale_factor < 0 || profile.window_scale_factor > 14) {
					std::cerr << "-wsfactor invalid argument" << std::endl;
					return -1;
				}

				break;

			case 15: // profile
				{
					std::string temp = optarg;
					if(!curr_profile_name.empty())
						add_profile(curr_profile_name, profile);

					curr_profile_name = temp;
				}

				break;

		}
	}

	if(!curr_profile_name.empty())
		add_profile(curr_profile_name, profile);
	else
		Profile = profile;

	return 0;
}

void print_help() {
	std::cout << "Help!" << std::endl;
}

void print_info() {
	std::cout << "Proxy running on " << Settings_perst.server_address << ':' << Settings_perst.server_port << "..." << std::endl
	<< "To get help run program with --help argument." << std::endl
	<< "To auto configure run program with --auto argument" << std::endl;
}

void sig_int_handler(int signum) {
	// Stop program
	stop_flag.store(true);
	// Interrupt poll()
	close(Interrupt_pipe[0]);
	close(Interrupt_pipe[1]);	
}

int main(int argc, char* argv[]) {
	// Set process name
        prctl(PR_SET_NAME, PROCESS_NAME.c_str(), NULL, NULL, NULL);
        std::strcpy(argv[0], PROCESS_NAME.c_str());

	// Init
	stop_flag.store(false);
	std::srand(std::time(nullptr));
	int res = parse_cmdline(argc, argv);
	if(res == -1) {
		print_help();
		return -1; //exit_failure();
	} else if(res == -2)
		return 0;
	ignore_sigpipe();

	// Init interrupt pipe (used to interrupt poll() calls)
	pipe(Interrupt_pipe);

	// If we have profiles, choose profile
	if(!Profiles.empty())
		if(change_profile() == -1)
			return -1; //exit_failure();

	if(Profile.doh)
		if(load_ca_bundle() == -1)
			return -1; //exit_failure();

	// Create server socket
	int server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(server_socket == -1) {
		std::cerr << "Server socket creation failure. Errno: " << std::strerror(errno) << std::endl;
		return -1; //exit_failure();
	}

	// Make address/port reusable
	int opt = 1;
	if(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		std::cerr << "Can't setsockopt on server socket. Errno: " << std::strerror(errno) << std::endl;
        	return -1; //exit_failure();
	}

	// Server address options
	struct sockaddr_in server_address;
	server_address.sin_family = AF_INET;
	inet_pton(AF_INET, Settings_perst.server_address.c_str(), &(server_address.sin_addr));
	server_address.sin_port = htons(Settings_perst.server_port);

	// Bind socket
	if(bind(server_socket, (struct sockaddr *) &server_address, sizeof(server_address)) == -1)
	{
		std::cerr << "Can't bind server socket. Errno: " << std::strerror(errno) << std::endl;
		return -1; //exit_failure();
	}

	// Listen to socket
	if(listen(server_socket, 4096) == -1)
	{
		std::cerr << "Can't listen to server socket. Errno: " << std::strerror(errno) << std::endl;
		return -1; //exit_failure();
	}

	// Show info
	print_info();

	if(Settings_perst.daemon)
		daemonize();

	// Start route monitor thread to correctly change profiles
	std::thread t1;
	if(!Profiles.empty())
		t1 = std::thread(route_monitor_thread);

	// Register ctrl-c and terminate handlers
	struct sigaction signalAction;
	signalAction.sa_handler = sig_int_handler;
	sigemptyset(&signalAction.sa_mask);
	signalAction.sa_flags = 0;
	sigaction(SIGINT, &signalAction, NULL);
	sigaction(SIGTERM, &signalAction, NULL);

	// Start accepting clients
	std::thread t2(accept_client_cycle, server_socket);
	t2.join();

	// Oops, seems users asked program to exit or accept_client_cycle_crashed

	// Deinit
	std::cout << "Quitting..." << std::endl;
	if(t1.joinable()) t1.join();
	close(server_socket);

	return 0;
}
