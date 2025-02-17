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

/* Queue of packets for which we wait arp reply. */
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
 	Returns a pointer to the best matching route, or NULL if  there is no
	matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	int index = search(root, ip_dest);
	printf("index found: %d\n", index);
	if (index == -1)
		return NULL;
	return &rtable[index];
}

/* 
	Iterates through the MAC table and searches for an entry that matches given_ip. Returns NULL if not found.
 */
struct arp_table_entry *get_mac_entry(uint32_t given_ip)
{
	for (int i = 0; i < mac_table_len; i++)
		if (mac_table[i].ip == given_ip)
			return &mac_table[i];

	return NULL;
}

/*
	Iterates through addresses and calls insert function for each of them.
*/
void insert_addresses(void)
{
	for (int i = 0; i < rtable_len; i++)
		insert_address(root, rtable[i], i);
}

/*
	Updates arp table after arp reply received. Takes information from 
	arp header.
*/
void update_arp_table(struct arp_header* arp_hdr)
{
	mac_table_len++;
	mac_table = realloc(mac_table, mac_table_len * sizeof (struct arp_table_entry));
	DIE(!mac_table, "realloc");

	memcpy(mac_table[mac_table_len - 1].mac, arp_hdr->sha, 6);
	mac_table[mac_table_len - 1].ip = arp_hdr->spa;
}

/*
	Checks if given mac is broadcast address.
*/
int check_broadcast(uint8_t mac[6])
{
	int i;
	for (i = 0; i < 6; i++)
		if (mac[i] != 0xff)
			break;
	return (i == 6);
}

/*
	Sends packets for which arp reply was received.
*/
void update_queue()
{
	while (!queue_empty(q)) {
		void *packet = queue_deq(q);
		int *packet_len = queue_deq(q);
					
		struct iphdr *ip_hdr_packet = (struct iphdr*) (packet + sizeof(struct ether_header));

		struct route_table_entry *next = get_best_route(ip_hdr_packet->daddr);

		struct arp_table_entry *table_entry_packet = get_mac_entry(next->next_hop);

		// still didn't receive mac address, we enque packet again
		if (!table_entry_packet) {
			queue_enq(q, packet);
			queue_enq(q, packet_len);
			break;
		}

		// got mac address so we can send the packet
		struct ether_header *eth_hdr_packet = (struct ether_header *)packet;

		memcpy(eth_hdr_packet->ether_dhost, table_entry_packet->mac, 6);

		send_to_link(next->interface, packet, *packet_len);

		free(packet); // data was written to interface file descriptor
		free(packet_len);
	}
}

/*
	Sends icmp echo reply. Needs information from the echo request packet.
*/
void send_icmp_echo_reply(int interface, struct icmphdr *icmp_hdr, struct iphdr *ip_hdr, struct ether_header *eth_hdr, size_t len, uint32_t *ip)
{
	char *icmp_packet = malloc(MAX_PACKET_LEN);
	DIE(!icmp_packet, "malloc");
	memset(icmp_packet, 0, MAX_PACKET_LEN);

	struct ether_header *eth_icmp = (struct ether_header*)icmp_packet;
	struct iphdr *ip_hdr_icmp = (struct iphdr *)(icmp_packet + sizeof(struct ether_header));

	memcpy(eth_icmp->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_icmp->ether_shost);
	eth_icmp->ether_type = htons(0x0800);

	memcpy(ip_hdr_icmp, ip_hdr, sizeof(struct iphdr));
	ip_hdr_icmp->protocol = 1; // for icmp
	ip_hdr_icmp->ttl = 64;
	ip_hdr_icmp->tot_len = len;
	ip_hdr_icmp->daddr = ip_hdr->saddr;
	ip_hdr_icmp->saddr = *(uint32_t *)ip;
	ip_hdr_icmp->check = 0;
	ip_hdr_icmp->check = htons(checksum((uint16_t *) ip_hdr_icmp, sizeof(struct iphdr)));

	struct icmphdr *icmp_hdr_new = (struct icmphdr *)(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	memcpy(icmp_hdr_new, icmp_hdr, sizeof(struct icmphdr));
	icmp_hdr_new->type = 0; // for reply
	icmp_hdr_new->checksum = 0;
	icmp_hdr_new->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
	memcpy(((char *)icmp_hdr_new) + sizeof(struct icmphdr), (char *)ip_hdr + sizeof(struct iphdr) + sizeof(struct icmphdr), len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr));

	send_to_link(interface, icmp_packet, len);
	free(icmp_packet);
	free(ip);
}

/*
	Sends icmp host unreachable packet. Needs information from the original
	packet.
*/
void send_icmp_host_unreachable(int interface, void *buf, struct iphdr *ip_hdr, struct ether_header *eth_hdr)
{
	char *icmp_packet = malloc(MAX_PACKET_LEN);
	DIE(!icmp_packet, "malloc");
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

	uint32_t *ip = malloc(sizeof(uint32_t));
	DIE(!ip, "malloc");
	get_parsed_ip_interface(interface, ip);
	ip_hdr_icmp->saddr = *ip;
	free(ip);
	ip_hdr_icmp->check = 0;
	ip_hdr_icmp->check = htons(checksum((uint16_t *) ip_hdr_icmp, sizeof(struct iphdr)));

	char *first_64 = malloc(8); // 8 bytes is 64 bits
	DIE(!first_64, "malloc");
	memcpy(first_64, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

	struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = 3;
	icmp_hdr->code = 0;
	memcpy(icmp_hdr + 8, ip_hdr, sizeof(struct iphdr));
	memcpy(icmp_hdr + 8 + sizeof(struct iphdr), first_64, 8);
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, 16 + sizeof(struct iphdr)));

	send_to_link(interface, icmp_packet, sizeof(struct ether_header) + sizeof(struct iphdr) + 16 + sizeof(struct iphdr));
			
	free(icmp_packet);
	free(first_64);
}

/*
	Sends icmp no more time to live message. Needs information from the original
	packet.
*/
void send_icmp_no_more_ttl(int interface, void *buf, struct iphdr *ip_hdr, struct ether_header *eth_hdr)
{
	char *icmp_packet = malloc(MAX_PACKET_LEN);
	DIE(!icmp_packet, "malloc");
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
	uint32_t *ip = malloc(sizeof(uint32_t));
	DIE(!ip, "malloc");
	get_parsed_ip_interface(interface, ip);
	ip_hdr_icmp->saddr = *ip;
	free(ip);
	ip_hdr_icmp->check = 0;
	ip_hdr_icmp->check = htons(checksum((uint16_t *) ip_hdr_icmp, sizeof(struct iphdr)));

	char *first_64 = malloc(8); // 8 bytes is 64 bits
	DIE(!first_64, "malloc");
	memcpy(first_64, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

	struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = 11;
	icmp_hdr->code = 0;
	memcpy(icmp_hdr + 8, ip_hdr, sizeof(struct iphdr));
	memcpy(icmp_hdr + 8 + sizeof(struct iphdr), first_64, 8);
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, 16 + sizeof(struct iphdr)));

	send_to_link(interface, icmp_packet, sizeof(struct ether_header) + sizeof(struct iphdr) + 16 + sizeof(struct iphdr));
	free(icmp_packet);
	free(first_64);
}

/*
	Sends arp request and enques packet until reply is received.
*/
void send_arp_request(int interface, void *buf, size_t len, uint8_t *mac, struct route_table_entry *next)
{
	void *packet = malloc(MAX_PACKET_LEN * sizeof(char));
	DIE(!packet, "malloc");
	memcpy(packet, buf, len);
	queue_enq(q, packet);
	int *packet_len = malloc(sizeof(int));
	DIE(!packet_len, "malloc");
	*packet_len = len;
	queue_enq(q, packet_len);

	void *arp_packet = malloc(MAX_PACKET_LEN * sizeof(char));
	DIE(!arp_packet, "malloc");
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
	DIE(!ip, "malloc");
	get_parsed_ip_interface(interface, ip);

	arp_hdr->spa = *((int *) ip);
	arp_hdr->tpa = next->next_hop;

	send_to_link(next->interface, (char *)arp_packet, sizeof(struct ether_header) + sizeof(struct arp_header));

	free(ip);
	free(arp_packet);
}


int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);

	char buf[MAX_PACKET_LEN];

	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory rtable");
	
	// statically parsed rtable and dinamically constructed arp table
	rtable_len = read_rtable(argv[1], rtable);
	mac_table_len = 0;
	mac_table = NULL;

	q = queue_create();

	// creating trie
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

				update_arp_table(arp_hdr);
				update_queue();

				continue;
			}
			if (arp_hdr->op == ntohs(1)) { // we received an arp request
				printf("got arp request\n");

				int broadcast = check_broadcast(eth_hdr->ether_dhost);

				uint32_t *ip = malloc(sizeof(u_int32_t));
				DIE(!ip, "malloc");
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

		// checks if we got an IPv4 packet
		if (eth_hdr->ether_type != ntohs(0x0800)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		// checks checksum
		uint16_t recv_sum = ntohs(ip_hdr->check);
		ip_hdr->check = 0;
		int sum_ok = (checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)) == recv_sum);
		if (!sum_ok) {
			printf("Ignored packet; checksum failed\n");
			continue;
		}

		// check icmp
		if (ip_hdr->protocol == 1) {
			printf("got icmp packet\n");

			struct icmphdr *icmp_hdr = (struct icmphdr *)(((char *)ip_hdr) + sizeof(struct iphdr));
			if (icmp_hdr->type == 8) {				
				printf("got icmp echo\n");

				uint32_t *ip = malloc(sizeof(u_int32_t));
				DIE(!ip, "malloc");
				get_parsed_ip_interface(interface, ip);

				if (ip_hdr->daddr == *((uint32_t *)ip)) {
					printf("got icmp echo for us\n");

					send_icmp_echo_reply(interface, icmp_hdr, ip_hdr, eth_hdr, len, ip);
					
					printf("sent icmp reply\n");
					continue;
				}
				free(ip);
			}
		}

		// calls get_best_route to find the most specific route;
		// sending host unreachable if null 
		struct route_table_entry *next = get_best_route(ip_hdr->daddr);
		if (!next) {
			send_icmp_host_unreachable(interface, buf, ip_hdr, eth_hdr);
			printf("sent icmp host unreachable\n");
			continue;
		}

		// checks TTL > 1; updates TLL; updates checksum
		if (ip_hdr->ttl > 1) {
			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		} else {
			send_icmp_no_more_ttl(interface, buf, ip_hdr, eth_hdr);
			printf("sent icmp for ttl\n");
			continue;
		}

		// updates the ethernet addresses; sending arp request if we have no
		// value for dhost
		uint8_t mac[6];
		get_interface_mac(next->interface, mac);
		memcpy(eth_hdr->ether_shost, mac, 6);
		printf("interface: %d\n", next->interface);

		struct arp_table_entry *next_mac = get_mac_entry(next->next_hop);
		if (!next_mac) {
			printf("sending arp request\n");
			send_arp_request(interface, buf, len, mac, next);
			
			continue;
		}
		memcpy(eth_hdr->ether_dhost, next_mac->mac, 6);

		send_to_link(next->interface, buf, len);
	}
}
