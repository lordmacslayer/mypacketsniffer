/**************************************************
*   FILE : process_udp.c
* AUTHOR : Siddharth Manoj Bhise
*   DATE : 14th-September-2016
* Signature inserted by "identity_inserter" 
**************************************************/
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
	unsigned char *dump_ascii = NULL;
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
	payload_ptr = (unsigned char *)(udp_header + 1);
	printf("\nDBG: Payload_ptr = %u\t\tudp_header = %u", (unsigned int *)payload_ptr, (unsigned char *)udp_header);
	printf("\nUDP Payload (length = %u bytes) :", payload_length);
	insert_new_line = 0;
	dump_ascii = payload_ptr;
	while (payload_length > 0)
	{
		if (insert_new_line % 8 == 0)
		{
			printf("\t\t");
			// dump the ascii equivalent of the printed characters
			while (dump_ascii != payload_ptr)
			{
				if (*dump_ascii >=32 && *dump_ascii <= 128)
					printf("%c", (unsigned char)*dump_ascii);
				else
					printf(".");
				dump_ascii++;
			}
			printf("\n\t");
		}
		printf("%02X ", (unsigned int)*payload_ptr);
		payload_ptr++;
		payload_length--;
		insert_new_line = (insert_new_line + 1) % 8;
	}
	// this while loop is to dump the ascii for the last line hex dump
	printf("%*c",23-insert_new_line-(insert_new_line - 1),' ');
	printf("\t\t");
	while (dump_ascii != payload_ptr)
	{
		if (*dump_ascii >=32 && *dump_ascii <= 128)
			printf("%c", (unsigned char)*dump_ascii);
		else
			printf(".");
		dump_ascii++;
	}
}
