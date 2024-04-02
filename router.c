#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "trie.h"
#include "list.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *mac_table;
int mac_table_len;

queue q;

node_t *root;

void get_parsed_ip_interface(int interface, uint32_t *ip)
{
	char *my_ip = get_interface_ip(interface);
	printf("my_ip: %s\n", my_ip);
	uint8_t* curr = (uint8_t *)ip;
	char *p = strtok(my_ip, ".");
	int i = 0;
	while (p) {
		curr[i] = atoi(p);
		i++;
		p = strtok(NULL, ".");
	}
	printf("%u\n", *ip);
}

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	int index = search(root, ip_dest);
	printf("index found: %d\n", index);
	if (index == -1)
		return NULL;
	return &rtable[index];
}

struct arp_table_entry *get_mac_entry(uint32_t given_ip) {
	/* Iterates through the MAC table and search for an entry
	 * that matches given_ip. */

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
	setvbuf(stdout, NULL, _IONBF, 0);

	char buf[MAX_PACKET_LEN];

	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");
	
	rtable_len = read_rtable(argv[1], rtable);
	mac_table_len = 0;
	mac_table = NULL;

	q = queue_create();

	root = create_node();	
	insert_addresses();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		printf("got new packet\n");
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		if (eth_hdr->ether_type == ntohs(0x0806)) { // we got arp
			struct arp_header* arp_hdr = (struct arp_header*) (buf + sizeof(struct ether_header));
			printf("got arp\n");

			if (arp_hdr->op == ntohs(2)) { // we got arp reply
				printf("got arp reply\n");

				mac_table_len++;
				mac_table = realloc(mac_table, mac_table_len * sizeof (struct arp_table_entry));

				memcpy(mac_table[mac_table_len - 1].mac, arp_hdr->sha, 6);
				mac_table[mac_table_len - 1].ip = arp_hdr->spa;

				while (!queue_empty(q)) {
					void *packet = queue_deq(q);
					int *packet_len = queue_deq(q);
					
					struct iphdr *ip_hdr_packet = (struct iphdr*) (packet + sizeof(struct ether_header));

					struct route_table_entry *next = get_best_route(ip_hdr_packet->daddr);

					struct arp_table_entry *table_entry_packet = get_mac_entry(next->next_hop);
					if (!table_entry_packet) {
						queue_enq(q, packet);
						queue_enq(q, packet_len);
						break;
					}

					struct ether_header *eth_hdr_packet = (struct ether_header *)packet;

					memcpy(eth_hdr_packet->ether_dhost, table_entry_packet->mac, 6);
					
					printf("packet_len: %d\n", *packet_len);
					send_to_link(next->interface, packet, *packet_len);
				}
				continue;
			}
			if (arp_hdr->op == ntohs(1)) { // we received an arp request
				printf("got arp request\n");
				printf("%u\n", arp_hdr->tpa);

				int i, broadcast = 0;
				for (i = 0; i < 6; i++)
					if (eth_hdr->ether_dhost[i] != 0xff)
						break;
				broadcast = (i == 6);

				uint32_t *ip = malloc(sizeof(u_int32_t));
				get_parsed_ip_interface(interface, ip);

				uint8_t my_mac[6];
				get_interface_mac(interface, my_mac);
				if ((broadcast && arp_hdr->tpa == *((uint32_t *)ip)) || strncmp((char *)my_mac, (char *)arp_hdr->tha, 6) == 0) { // got broadcast or address of my interface
					printf("got arp request for us\n");

					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					memcpy(eth_hdr->ether_shost, my_mac, 6);
					memcpy(arp_hdr->sha, my_mac, 6);
					memcpy(arp_hdr->tha, eth_hdr->ether_dhost, 6);
					arp_hdr->tpa = arp_hdr->spa;
					arp_hdr->spa = *((uint32_t *) ip);
					arp_hdr->op = htons(2);
					send_to_link(interface, buf, len);

					printf("sent response to arp request\n");
					free(ip);
					continue;
				} else {
					free(ip);
					if (broadcast)
						continue;
				}
			}
		}

		/* Check if we got an IPv4 packet */
		if (eth_hdr->ether_type != ntohs(0x0800)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		uint16_t recv_sum = ntohs(ip_hdr->check);
		ip_hdr->check = 0;
		int sum_ok = (checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)) == recv_sum);
		if (!sum_ok) {
			printf("Ignored packet; checksum failed\n");
			continue;
		}

		if (ip_hdr->protocol == 1) {
			printf("got icmp packet\n");

			struct icmphdr *icmp_hdr = (struct icmphdr *)(((char *)ip_hdr) + sizeof(struct iphdr));
			if (icmp_hdr->type == 8) {				
				printf("got icmp echo\n");

				uint32_t *ip = malloc(sizeof(u_int32_t));
				get_parsed_ip_interface(interface, ip);

				if (ip_hdr->daddr == *((uint32_t *)ip)) {
					printf("got icmp echo for us\n");
					char *icmp_packet = malloc(MAX_PACKET_LEN);
					memset(icmp_packet, 0, MAX_PACKET_LEN);

					struct ether_header *eth_icmp = (struct ether_header*)icmp_packet;
					struct iphdr *ip_hdr_icmp = (struct iphdr *)(icmp_packet + sizeof(struct ether_header));

					memcpy(eth_icmp->ether_dhost, eth_hdr->ether_shost, 6);
					get_interface_mac(interface, eth_icmp->ether_shost);
					eth_icmp->ether_type = htons(0x0800);

					memcpy(ip_hdr_icmp, ip_hdr, sizeof(struct iphdr));
					ip_hdr_icmp->protocol = 1; // for icmp
					ip_hdr_icmp->ttl = 64;
					ip_hdr_icmp->tot_len = 16 + 2 * sizeof(struct iphdr);
					ip_hdr_icmp->daddr = ip_hdr->saddr;


					/*char *first_64 = malloc(8); // 8 bytes is 64 bits
					memcpy(first_64, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);*/

					struct icmphdr *icmp_hdr_new = (struct icmphdr *)(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
					memcpy(icmp_hdr_new, icmp_hdr, sizeof(struct icmphdr));
					icmp_hdr_new->type = 0; // for reply
					icmp_hdr_new->checksum = 0;
					// memcpy(icmp_hdr_new + 8, ip_hdr, sizeof(struct iphdr));
					// memcpy(icmp_hdr_new + 8 + sizeof(struct iphdr), first_64, 8);
					icmp_hdr_new->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
					memcpy(((char *)icmp_hdr_new) + sizeof(struct icmphdr), (char *)ip_hdr + sizeof(struct iphdr) + sizeof(struct icmphdr), len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr));

					send_to_link(interface, icmp_packet, len);
					printf("sent icmp reply\n");

					free(ip);
					continue;
				}
				free(ip);
			}
		}

		/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */
		struct route_table_entry *next = get_best_route(ip_hdr->daddr);
		if (!next) {
			printf("Ignored packet; route not found\n");
			char *icmp_packet = malloc(MAX_PACKET_LEN);
			memset(icmp_packet, 0, MAX_PACKET_LEN);

			struct ether_header *eth_icmp = (struct ether_header*)icmp_packet;
			struct iphdr *ip_hdr_icmp = (struct iphdr *)(icmp_packet + sizeof(struct ether_header));

			memcpy(eth_icmp->ether_dhost, eth_hdr->ether_shost, 6);
			get_interface_mac(interface, eth_icmp->ether_shost);
			eth_icmp->ether_type = htons(0x0800);

			memcpy(ip_hdr_icmp, ip_hdr, sizeof(struct iphdr));
			ip_hdr_icmp->protocol = 1; // for icmp
			ip_hdr_icmp->ttl = 64;
			ip_hdr_icmp->tot_len = 16 + 2 * sizeof(struct iphdr);
			ip_hdr_icmp->daddr = ip_hdr->saddr;


			char *first_64 = malloc(8); // 8 bytes is 64 bits
			memcpy(first_64, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

			struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
			icmp_hdr->type = 3;
			icmp_hdr->code = 0;
			memcpy(icmp_hdr + 8, ip_hdr, sizeof(struct iphdr));
			memcpy(icmp_hdr + 8 + sizeof(struct iphdr), first_64, 8);
			icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, 16 + sizeof(struct iphdr)));
			send_to_link(interface, icmp_packet, sizeof(struct ether_header) + sizeof(struct iphdr) + 16 + sizeof(struct iphdr));
			printf("sent icmp\n");
			continue;
		}

		/* TODO 2.3: Check TTL >= 1. Update TLL. Update checksum  */
		if (ip_hdr->ttl > 1) {
			ip_hdr->ttl--;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		} else {
			printf("Ignored packet; no more ttl\n");
			char *icmp_packet = malloc(MAX_PACKET_LEN);
			memset(icmp_packet, 0, MAX_PACKET_LEN);

			struct ether_header *eth_icmp = (struct ether_header*)icmp_packet;
			struct iphdr *ip_hdr_icmp = (struct iphdr *)(icmp_packet + sizeof(struct ether_header));

			memcpy(eth_icmp->ether_dhost, eth_hdr->ether_shost, 6);
			get_interface_mac(interface, eth_icmp->ether_shost);
			eth_icmp->ether_type = htons(0x0800);

			memcpy(ip_hdr_icmp, ip_hdr, sizeof(struct iphdr));
			ip_hdr_icmp->protocol = 1; // for icmp
			ip_hdr_icmp->ttl = 64;
			ip_hdr_icmp->tot_len = 16 + 2 * sizeof(struct iphdr);
			ip_hdr_icmp->daddr = ip_hdr->saddr;


			char *first_64 = malloc(8); // 8 bytes is 64 bits
			memcpy(first_64, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

			struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
			icmp_hdr->type = 11;
			icmp_hdr->code = 0;
			memcpy(icmp_hdr + 8, ip_hdr, sizeof(struct iphdr));
			memcpy(icmp_hdr + 8 + sizeof(struct iphdr), first_64, 8);
			icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, 16 + sizeof(struct iphdr)));
			send_to_link(interface, icmp_packet, sizeof(struct ether_header) + sizeof(struct iphdr) + 16 + sizeof(struct iphdr));
			printf("sent icmp\n");
			continue;
		}

		/* TODO 2.4: Update the ethernet addresses. Use get_mac_entry to find the destination MAC
		 * address. Use get_interface_mac(m.interface, uint8_t *mac) to
		 * find the mac address of our interface. */
		
		uint8_t mac[6];
		get_interface_mac(next->interface, mac);
		memcpy(eth_hdr->ether_shost, mac, 6);
		printf("interface: %d\n", next->interface);

		struct arp_table_entry *next_mac = get_mac_entry(next->next_hop);
		if (!next_mac) {
			printf("sending arp request\n");

			void *packet = malloc(MAX_PACKET_LEN * sizeof(char));
			memcpy(packet, buf, len);
			queue_enq(q, packet);
			int *packet_len = malloc(sizeof(int));
			*packet_len = len;
			queue_enq(q, packet_len);

			void *arp_packet = malloc(MAX_PACKET_LEN * sizeof(char));
			struct ether_header *eth_arp_hdr = (struct ether_header *)arp_packet;
			memset(eth_arp_hdr->ether_dhost, 0xff, 6);
			memcpy(eth_arp_hdr->ether_shost, mac, 6);
			eth_arp_hdr->ether_type = htons(0x0806);

			struct arp_header *arp_hdr = (struct arp_header*) (arp_packet + sizeof(struct ether_header));
			arp_hdr->htype = htons(1); // ethernet
			arp_hdr->ptype = htons(0x0800);
			arp_hdr->hlen = 6;
			arp_hdr->plen = 4;
			arp_hdr->op = htons(1); // request
			memcpy(arp_hdr->sha, mac, 6);

			uint32_t *ip = malloc(sizeof(u_int32_t));
			get_parsed_ip_interface(interface, ip);

			arp_hdr->spa = *((int *) ip);
			printf("%u\n", htonl(*(int *)ip));
			arp_hdr->tpa = next->next_hop;

			((char *)arp_packet)[sizeof(struct ether_header) + sizeof(struct arp_header)] = 0;

			send_to_link(next->interface, (char *)arp_packet, sizeof(struct ether_header) + sizeof(struct arp_header));

			free(ip);

			continue;
		}
		memcpy(eth_hdr->ether_dhost, next_mac->mac, 6);

		send_to_link(next->interface, buf, len);
	}
}
