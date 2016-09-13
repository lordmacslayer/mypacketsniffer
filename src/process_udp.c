#include <stdio.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#define UDP_MIN_LEN 8
void process_udp(const u_char *packet, struct ip *ip_packet, unsigned int ip_header_length)
{
//	struct udphdr *udp_header = (struct udphdr *) (ip_packet + ip_header_length);
	struct udphdr *udp_header = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
	unsigned int payload_length;
	unsigned char *payload_ptr = NULL;
	int insert_new_line;

	printf("\n%20s", "TRANSPORT LAYER");
	printf("\n%20s", "--------- -----");

	printf("\nUDP Source Port: %u", ntohs(udp_header->uh_sport));
	printf("\nUDP Destination Port: %u", ntohs(udp_header->uh_dport));
	printf("\nUDP Length (header + data): %u bytes", ntohs(udp_header->uh_ulen));
	printf("\nUDP Checksum: %u", ntohs(udp_header->uh_sum));

	// minimum length of the UDP packet has to be that of the header fields.
	// so the minimum length has to be 8 bytes
	payload_length = ntohs(udp_header->uh_ulen) - UDP_MIN_LEN;
	payload_ptr = (unsigned char *)(udp_header + sizeof(struct udphdr));
	printf("\nUDP Payload (length = %u bytes) :", payload_length);
	insert_new_line = 0;
	// TODO: check if the payload is being properly printed by comparing with wireshark
	while (payload_length > 0)
	{
		if (insert_new_line % 8 == 0)
		{
			printf("\n\t");
		}
		printf("%02X ", (unsigned char)*payload_ptr);
		payload_ptr++;
		payload_length--;
		insert_new_line = (insert_new_line + 1) % 8;
	}
}
