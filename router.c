#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "trie.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *mac_table;
int mac_table_len;

node_t *root;

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	/* TODO 2.2: Implement the LPM algorithm */
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
	 * the rtable are in network order already */
	int index = search(root, ip_dest);
	printf("index found: %d\n", index);
	if (index == -1)
		return NULL;
	return &rtable[index];
	/*struct route_table_entry *next = NULL;
	for (int i = 0; i < rtable_len; i++) {
		if (rtable[i].prefix == (ip_dest & rtable[i].mask)) {
			if (!next || (next && ntohl(rtable[i].mask) > ntohl(next->mask))) {
				next = &rtable[i];
				printf("index found: %d\n", i);
			}
		}
	}
	return next;*/
}

struct arp_table_entry *get_mac_entry(uint32_t given_ip) {
	/* TODO 2.4: Iterate through the MAC table and search for an entry
	 * that matches given_ip. */

	/* We can iterate thrpigh the mac_table for (int i = 0; i <
	 * mac_table_len; i++) */

	for (int i = 0; i < mac_table_len; i++)
		if (mac_table[i].ip == given_ip)
			return &mac_table[i];

	return NULL;
}

void insert_addresses(void) {
	for (int i = 0; i < rtable_len; i++)
		insert_address(root, rtable[i], i);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	mac_table = malloc(sizeof(struct  arp_table_entry) * 100);
	DIE(mac_table == NULL, "memory");
	
	rtable_len = read_rtable(argv[1], rtable);
	mac_table_len = parse_arp_table("arp_table.txt", mac_table);

	root = create_node();	
	insert_addresses();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		/* Check if we got an IPv4 packet */
		if (eth_hdr->ether_type != ntohs(0x0800)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

		uint16_t recv_sum = ntohs(ip_hdr->check);
		ip_hdr->check = 0;
		int sum_ok = (checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)) == recv_sum);
		if (!sum_ok) {
			printf("Ignored packet; checksum failed\n");
			continue;
		}

		/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */
		struct route_table_entry *next = get_best_route(ip_hdr->daddr);
		if (!next) {
			printf("Ignored packet; route not found\n");
			continue;
		}

		/* TODO 2.3: Check TTL >= 1. Update TLL. Update checksum  */
		if (ip_hdr->ttl >= 1) {
			ip_hdr->ttl--;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		} else {
			printf("Ignored packet; no more ttl\n");
			continue;
		}

		/* TODO 2.4: Update the ethernet addresses. Use get_mac_entry to find the destination MAC
		 * address. Use get_interface_mac(m.interface, uint8_t *mac) to
		 * find the mac address of our interface. */
		
		get_interface_mac(next->interface, eth_hdr->ether_shost);
		printf("interface: %d\n", next->interface);
		struct arp_table_entry *next_mac = get_mac_entry(ip_hdr->daddr);
		if (!next_mac) {
			printf("Ignored packet; no MAC found\n");
			continue;
		}
		memcpy(eth_hdr->ether_dhost, next_mac->mac, 6);

		send_to_link(next->interface, buf, len);
	}
}

