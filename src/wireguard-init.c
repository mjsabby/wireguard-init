#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <stdbool.h>

/* WireGuard tools headers */
#include "ipc.h"
#include "config.h"
#include "containers.h"
#include "encoding.h"

/* Configuration - Edit these for your setup */
#define ETH_INTERFACE "eth0"
#define ETH_IP_ADDRESS "192.168.50.1"
#define ETH_NETMASK "255.255.255.0"
#define WG_INTERFACE "wg0"
#define WG_IP_ADDRESS "192.168.60.1"
#define WG_NETMASK "255.255.255.0"
#define WG_MTU 1420 /* Standard: 1500 - 80 (WireGuard overhead) */
#define WG_CONFIG_PATH "/wireguard.bin"
#define HTTP_PORT 8082

#include <fcntl.h>

static int set_interface_mtu(const char *ifname, int mtu)
{
	int sock;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror("socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_mtu = mtu;

	if (ioctl(sock, SIOCSIFMTU, &ifr) < 0)
	{
		perror("SIOCSIFMTU");
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

static int bring_interface_up(const char *ifname)
{
	int sock;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror("socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
	{
		perror("SIOCGIFFLAGS");
		close(sock);
		return -1;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
	{
		perror("SIOCSIFFLAGS");
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

static int set_interface_address(const char *ifname, const char *ip, const char *netmask)
{
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *addr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror("socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	/* Set IP address */
	addr = (struct sockaddr_in *)&ifr.ifr_addr;
	addr->sin_family = AF_INET;
	if (inet_pton(AF_INET, ip, &addr->sin_addr) != 1)
	{
		fprintf(stderr, "Invalid IP address: %s\n", ip);
		close(sock);
		return -1;
	}

	if (ioctl(sock, SIOCSIFADDR, &ifr) < 0)
	{
		perror("SIOCSIFADDR");
		close(sock);
		return -1;
	}

	/* Set netmask */
	addr = (struct sockaddr_in *)&ifr.ifr_netmask;
	addr->sin_family = AF_INET;
	if (inet_pton(AF_INET, netmask, &addr->sin_addr) != 1)
	{
		fprintf(stderr, "Invalid netmask: %s\n", netmask);
		close(sock);
		return -1;
	}

	if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0)
	{
		perror("SIOCSIFNETMASK");
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

static int enable_ip_forwarding(void)
{
	int fd;
	const char *enable = "1\n";

	if (mount("proc", "/proc", "proc", 0, "") < 0)
	{
		if (errno == EBUSY)
		{
			/* Already mounted, ignore */
		}
		else
		{
			fprintf(stderr, "Failed to mount proc: %s\n", strerror(errno));
			return 1;
		}
	}

	fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);
	if (fd < 0)
	{
		perror("open /proc/sys/net/ipv4/ip_forward");
		return -1;
	}

	if (write(fd, enable, 2) != 2)
	{
		perror("write ip_forward");
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int add_route_for_allowedip(const char *ifname, const struct wgallowedip *allowedip)
{
	int sock;
	struct rtentry route;
	struct sockaddr_in *addr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror("socket for route");
		return -1;
	}

	memset(&route, 0, sizeof(route));

	/* Only handle IPv4 for now */
	if (allowedip->family != AF_INET)
	{
		close(sock);
		return 0; /* Skip IPv6 - not an error */
	}

	/* Set destination */
	addr = (struct sockaddr_in *)&route.rt_dst;
	addr->sin_family = AF_INET;
	memcpy(&addr->sin_addr, &allowedip->ip4, sizeof(struct in_addr));

	/* Set netmask */
	addr = (struct sockaddr_in *)&route.rt_genmask;
	addr->sin_family = AF_INET;
	/* Convert CIDR to netmask */
	if (allowedip->cidr == 32)
	{
		addr->sin_addr.s_addr = htonl(0xFFFFFFFF);
	}
	else if (allowedip->cidr == 0)
	{
		addr->sin_addr.s_addr = 0;
	}
	else
	{
		addr->sin_addr.s_addr = htonl(~((1U << (32 - allowedip->cidr)) - 1));
	}

	/* Set interface */
	route.rt_dev = (char *)ifname;
	route.rt_flags = RTF_UP;

	if (ioctl(sock, SIOCADDRT, &route) < 0)
	{
		if (errno != EEXIST)
		{ /* Ignore if route already exists */
			perror("SIOCADDRT");
			close(sock);
			return -1;
		}
	}

	close(sock);
	return 0;
}

static int add_routes_for_peers(const char *ifname)
{
	struct wgdevice *device = NULL;
	struct wgpeer *peer;
	struct wgallowedip *allowedip;
	int route_count = 0;

	/* Get device configuration to read AllowedIPs */
	if (ipc_get_device(&device, ifname) < 0)
	{
		fprintf(stderr, "Failed to get device info for routes\n");
		return -1;
	}

	/* Iterate through all peers */
	for_each_wgpeer(device, peer)
	{
		/* Iterate through all AllowedIPs for this peer */
		for_each_wgallowedip(peer, allowedip)
		{
			if (add_route_for_allowedip(ifname, allowedip) == 0)
			{
				char ip_str[INET6_ADDRSTRLEN];
				if (allowedip->family == AF_INET)
				{
					inet_ntop(AF_INET, &allowedip->ip4, ip_str, sizeof(ip_str));
					printf("  Route added: %s/%d via %s\n", ip_str, allowedip->cidr, ifname);
					route_count++;
				}
			}
		}
	}

	free_wgdevice(device);
	printf("Added %d route(s) for AllowedIPs\n", route_count);
	return 0;
}

/* ============================================================================
 * Netlink Interface Creation
 * ============================================================================ */

struct nl_req
{
	struct nlmsghdr n;
	struct ifinfomsg i;
	char buf[1024];
};

static int create_wireguard_interface(const char *ifname)
{
	int sock;
	struct nl_req req;
	struct rtattr *linkinfo, *attr, *kind;
	struct sockaddr_nl sa;
	char buf[4096];
	int ret = -1;
	int len;
	struct nlmsghdr *nh;
	struct nlmsgerr *err;

	/* Create netlink socket */
	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0)
	{
		perror("netlink socket");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
	{
		perror("netlink bind");
		close(sock);
		return -1;
	}

	/* Build netlink request to create interface */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = AF_UNSPEC;

	/* Add interface name */
	attr = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
	attr->rta_type = IFLA_IFNAME;
	attr->rta_len = RTA_LENGTH(strlen(ifname) + 1);
	strcpy(RTA_DATA(attr), ifname);
	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(attr->rta_len);

	/* Add link info for wireguard */
	linkinfo = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
	linkinfo->rta_type = IFLA_LINKINFO;
	linkinfo->rta_len = RTA_LENGTH(0);

	/* Add kind = "wireguard" */
	kind = (struct rtattr *)(((char *)linkinfo) + RTA_ALIGN(linkinfo->rta_len));
	kind->rta_type = IFLA_INFO_KIND;
	kind->rta_len = RTA_LENGTH(strlen("wireguard") + 1);
	strcpy(RTA_DATA(kind), "wireguard");
	linkinfo->rta_len = RTA_ALIGN(linkinfo->rta_len) + RTA_ALIGN(kind->rta_len);

	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(linkinfo->rta_len);

	/* Send netlink message */
	if (send(sock, &req, req.n.nlmsg_len, 0) < 0)
	{
		perror("netlink send");
		close(sock);
		return -1;
	}

	/* Read acknowledgment */
	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0)
	{
		perror("netlink recv");
		close(sock);
		return -1;
	}

	nh = (struct nlmsghdr *)buf;
	if (nh->nlmsg_type == NLMSG_ERROR)
	{
		err = (struct nlmsgerr *)NLMSG_DATA(nh);
		if (err->error == 0)
		{
			ret = 0;
		}
		else if (err->error == -EEXIST)
		{
			ret = 0;
		}
		else
		{
			fprintf(stderr, "Netlink error creating interface: %s\n", strerror(-err->error));
			ret = -1;
		}
	}

	close(sock);
	return ret;
}

__attribute__((noinline)) static int setup_wireguard(const char *config_path)
{
	char ipbuf[INET_ADDRSTRLEN];
	int fd = -1;
	int ret = -1;
	unsigned char *p;
	struct stat st;
	uint32_t iface_ip;
	uint16_t iface_cidr;
	uint16_t num_peers;
	struct wgpeer *peers;
	struct wgdevice *dev;
	struct wgallowedip *allowed;

	fd = open(config_path, O_RDONLY);
	if (fd < 0)
	{
		perror("Failed to open WireGuard config");
		return -1;
	}

	fstat(fd, &st);

	p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
	{
		perror("mmap failed");
		close(fd);
		return -1;
	}

	p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);

	dev = calloc(1, sizeof(*dev));
	strncpy(dev->name, WG_INTERFACE, IFNAMSIZ - 1);
	dev->name[IFNAMSIZ - 1] = '\0';
	memcpy(dev->private_key, p, 32);
	p += 32;

	iface_ip = *(uint32_t *)p;
	p += 4;
	iface_cidr = *(uint16_t *)p;
	p += 2;
	dev->listen_port = *(uint16_t *)p;
	p += 2;
	num_peers = *(uint16_t *)p;
	p += 2;

	peers = calloc(num_peers, sizeof(struct wgpeer));
	allowed = calloc(num_peers, sizeof(struct wgallowedip));

	for (int i = 0; i < num_peers; i++)
	{
		memcpy(peers[i].public_key, p, 32);
		p += 32;
		allowed[i].family = AF_INET;
		allowed[i].ip4.s_addr = *(uint32_t *)p;
		p += 4;
		allowed[i].cidr = *(uint16_t *)p;
		p += 2;
		peers[i].first_allowedip = peers[i].last_allowedip = &allowed[i];
		if (i > 0)
		{
			peers[i - 1].next_peer = &peers[i];
		}
	}

	dev->first_peer = &peers[0];
	dev->last_peer = &peers[num_peers - 1];

	inet_ntop(AF_INET, &iface_ip, ipbuf, sizeof(ipbuf));
	printf("[Interface]\n");
	printf("Name = %s\nAddress = %s/%u\nListenPort = %u\nPeers = %u\n", dev->name, ipbuf, iface_cidr, dev->listen_port, num_peers);

	for (int i = 0; i < num_peers; i++)
	{
		char peerip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &allowed[i].ip4, peerip, sizeof(peerip));
		printf("  [Peer %d] %s/%u\n", i, peerip, allowed[i].cidr);
	}

	munmap(p, st.st_size);

	if (ipc_set_device(dev) != 0)
	{
		perror("Failed to configure WireGuard interface");
		goto cleanup;
	}

	/* Assign IP address to WireGuard interface (before bringing up) */
	if (set_interface_address(WG_INTERFACE, WG_IP_ADDRESS, WG_NETMASK) < 0)
	{
		fprintf(stderr, "Failed to assign IP to %s\n", WG_INTERFACE);
		goto cleanup;
	}

	/* Set MTU (before bringing up) */
	if (set_interface_mtu(WG_INTERFACE, WG_MTU) < 0)
	{
		fprintf(stderr, "Warning: Failed to set MTU on %s\n", WG_INTERFACE);
		/* Continue anyway - not critical */
	}

	/* Bring WireGuard interface up */
	if (bring_interface_up(WG_INTERFACE) < 0)
	{
		fprintf(stderr, "Failed to bring up %s\n", WG_INTERFACE);
		goto cleanup;
	}

	/* Add routes for AllowedIPs (critical for server-to-peer traffic) */
	if (add_routes_for_peers(WG_INTERFACE) < 0)
	{
		fprintf(stderr, "Warning: Failed to add routes for AllowedIPs\n");
		/* Continue anyway - interface is still functional for incoming */
	}

	printf("WireGuard interface configured: %s = %s/%s\n", WG_INTERFACE, WG_IP_ADDRESS, WG_NETMASK);
	ret = 0;

cleanup:
	free(dev);
	free(peers);
	free(allowed);
	return ret;
}

/* ============================================================================
 * HTTP Statistics Server
 * ============================================================================ */

static void format_bytes(char *buf, size_t buflen, uint64_t bytes)
{
	if (bytes < 1024ULL)
		snprintf(buf, buflen, "%llu B", (unsigned long long)bytes);
	else if (bytes < 1024ULL * 1024ULL)
		snprintf(buf, buflen, "%.2f KiB", (double)bytes / 1024);
	else if (bytes < 1024ULL * 1024ULL * 1024ULL)
		snprintf(buf, buflen, "%.2f MiB", (double)bytes / (1024 * 1024));
	else
		snprintf(buf, buflen, "%.2f GiB", (double)bytes / (1024 * 1024 * 1024));
}

static void handle_http_request(int client_fd)
{
	struct wgdevice *device = NULL;
	struct wgpeer *peer;
	char response[65536];
	size_t offset = 0;
	char pubkey[WG_KEY_LEN_BASE64];
	char rx_str[64], tx_str[64];
	time_t now;
	char req_buf[1024];
	ssize_t bytes_read;
	ssize_t bytes_written;
	const char *error;

	now = time(NULL);

	/* Read request (we don't actually parse it) */
	bytes_read = read(client_fd, req_buf, sizeof(req_buf) - 1);
	if (bytes_read < 0)
	{
		perror("read request");
		return;
	}

	/* Get WireGuard device stats */
	if (ipc_get_device(&device, WG_INTERFACE) < 0)
	{
		error = "HTTP/1.0 500 Internal Server Error\r\n\r\nFailed to get WireGuard stats\n";
		bytes_written = write(client_fd, error, strlen(error));
		if (bytes_written < 0)
		{
			perror("write error response");
		}
		return;
	}

	/* Build HTTP response */
	offset += snprintf(response + offset, sizeof(response) - offset,
					   "HTTP/1.0 200 OK\r\n"
					   "Content-Type: text/plain\r\n"
					   "Connection: close\r\n"
					   "\r\n");

	offset += snprintf(response + offset, sizeof(response) - offset,
					   "WireGuard Statistics (%s)\n"
					   "==========================\n\n",
					   WG_INTERFACE);

	if (device->flags & WGDEVICE_HAS_PUBLIC_KEY)
	{
		key_to_base64(pubkey, device->public_key);
		offset += snprintf(response + offset, sizeof(response) - offset,
						   "Public Key: %s\n", pubkey);
	}

	if (device->listen_port)
	{
		offset += snprintf(response + offset, sizeof(response) - offset,
						   "Listen Port: %u\n", device->listen_port);
	}

	offset += snprintf(response + offset, sizeof(response) - offset, "\nPeers:\n");

	/* Iterate through all peers */
	for_each_wgpeer(device, peer)
	{
		key_to_base64(pubkey, peer->public_key);
		format_bytes(rx_str, sizeof(rx_str), peer->rx_bytes);
		format_bytes(tx_str, sizeof(tx_str), peer->tx_bytes);

		offset += snprintf(response + offset, sizeof(response) - offset,
						   "\n  Peer: %s\n", pubkey);

		/* Endpoint */
		if (peer->endpoint.addr.sa_family == AF_INET)
		{
			struct sockaddr_in *addr = (struct sockaddr_in *)&peer->endpoint.addr;
			char ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
			offset += snprintf(response + offset, sizeof(response) - offset,
							   "    Endpoint: %s:%u\n", ip, ntohs(addr->sin_port));
		}
		else if (peer->endpoint.addr.sa_family == AF_INET6)
		{
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&peer->endpoint.addr;
			char ip[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &addr->sin6_addr, ip, sizeof(ip));
			offset += snprintf(response + offset, sizeof(response) - offset,
							   "    Endpoint: [%s]:%u\n", ip, ntohs(addr->sin6_port));
		}

		/* Last handshake */
		if (peer->last_handshake_time.tv_sec)
		{
			long long ago = now - peer->last_handshake_time.tv_sec;
			offset += snprintf(response + offset, sizeof(response) - offset,
							   "    Last Handshake: %lld seconds ago\n", ago);
		}
		else
		{
			offset += snprintf(response + offset, sizeof(response) - offset,
							   "    Last Handshake: Never\n");
		}

		/* Transfer stats */
		offset += snprintf(response + offset, sizeof(response) - offset,
						   "    Transfer: %s received, %s sent\n", rx_str, tx_str);
		offset += snprintf(response + offset, sizeof(response) - offset,
						   "    Raw Transfer: %llu bytes received, %llu bytes sent\n",
						   (unsigned long long)peer->rx_bytes,
						   (unsigned long long)peer->tx_bytes);
	}

	/* Send response */
	bytes_written = write(client_fd, response, offset);
	if (bytes_written < 0)
	{
		perror("write response");
	}

	free_wgdevice(device);
}

__attribute__((noinline)) static int run_http_server(int port)
{
	int server_fd, client_fd;
	struct sockaddr_in addr;
	socklen_t addr_len;
	int opt;

	/* Create socket */
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0)
	{
		perror("socket");
		return -1;
	}

	/* Allow reuse */
	opt = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	/* Bind */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("bind");
		close(server_fd);
		return -1;
	}

	/* Listen */
	if (listen(server_fd, 5) < 0)
	{
		perror("listen");
		close(server_fd);
		return -1;
	}

	printf("HTTP stats server listening on port %d\n", port);

	/* Accept loop */
	while (1)
	{
		addr_len = sizeof(addr);
		client_fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len);
		if (client_fd < 0)
		{
			if (errno == EINTR)
				continue;
			perror("accept");
			continue;
		}

		/* Handle request */
		handle_http_request(client_fd);
		close(client_fd);
	}

	close(server_fd);
	return 0;
}

int main(int argc, char *argv[])
{
	if (create_wireguard_interface(WG_INTERFACE) < 0)
	{
		fprintf(stderr, "Failed to create WireGuard interface %s\n", WG_INTERFACE);
		return -1;
	}

	if (bring_interface_up("lo") < 0)
	{
		fprintf(stderr, "Failed to bring up loopback\n");
		return -1;
	}

	if (bring_interface_up(ETH_INTERFACE) < 0)
	{
		fprintf(stderr, "Failed to bring up %s\n", ETH_INTERFACE);
		return -1;
	}

	if (set_interface_address(ETH_INTERFACE, ETH_IP_ADDRESS, ETH_NETMASK) < 0)
	{
		fprintf(stderr, "Failed to assign IP to %s\n", ETH_INTERFACE);
		return -1;
	}

	if (enable_ip_forwarding() < 0)
	{
		fprintf(stderr, "Warning: Failed to enable IP forwarding\n");
		return -1;
	}

	if (setup_wireguard(WG_CONFIG_PATH) != 0)
	{
		fprintf(stderr, "WireGuard setup failed\n");
		return -1;
	}

	printf("\nStep 3: Starting HTTP server...\n");
	printf("===========================================\n");
	printf("Init complete! Access stats at:\n");
	printf("  http://%s:%d\n", ETH_IP_ADDRESS, HTTP_PORT);
	printf("===========================================\n\n");

	run_http_server(HTTP_PORT);

	/* Should never reach here */
	fprintf(stderr, "HTTP server exited unexpectedly\n");

	/* As PID 1, keep running forever even if server fails */
	while (1)
	{
		pause();
	}

	return 0;
}
