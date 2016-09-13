/**************************************************
*   FILE : process_ipv4_ipv6.c
* AUTHOR : Siddharth Manoj Bhise
*   DATE : 8th-September-2016
* Signature inserted by "identity_inserter" 
**************************************************/
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

extern void process_tcp(const u_char *, struct ether_header *);
extern void process_udp(const u_char *, struct ip *, unsigned int);
void process_ip_4(const u_char *packet, struct ether_header *eth_header)
{
	char source_ip[256], dest_ip[256];
	struct ip *ip_packet = (struct ip *) (packet + sizeof(struct ether_header));
	printf("\n%20s", "NETWORK LAYER");
	printf("\n%20s", "------- -----");
	printf("\nIP Version: %u", ip_packet->ip_v);
	// ip_hl: RFC 791
	// Internet Header Length is the length of the internet header in 32
	// bit words, and thus points to the beginning of the data.  Note that
	// the minimum value for a correct header is 5.
	printf("\nIP Header Length: %u in header and total %u bytes", ip_packet->ip_hl, ip_packet->ip_hl*4);
	// ip_tos: RFC 791
	// The Type of Service provides an indication of the abstract
	// parameters of the quality of service desired.  These parameters are
	// to be used to guide the selection of the actual service parameters
	// when transmitting a datagram through a particular network.  Several
	// networks offer service precedence, which somehow treats high
	// precedence traffic as more important than other traffic (generally
	// by accepting only traffic above a certain precedence at time of high
	// load).  The major choice is a three way tradeoff between low-delay,
	// high-reliability, and high-throughput.
	printf("\nIP Type Of Service: %u", ip_packet->ip_tos);
	// ip_len: RFC 791
	// Total Length is the length of the datagram, measured in octets,
	// including internet header and data.
	printf("\nIP Total Length: %u", ip_packet->ip_len);
	// ip_id: RFC 791
	// An identifying value assigned by the sender to aid in assembling the
	// fragments of a datagram.
	printf("\nIP id: %u", ip_packet->ip_id);
	// ip_off: RFC 791
	// This field indicates where in the datagram this fragment belongs.
	printf("\nIP Fragment Offset: %u", ip_packet->ip_off);
	// ip_ttl: RFC 791
	// This field indicates the maximum time the datagram is allowed to
	// remain in the internet system.  If this field contains the value
	// zero, then the datagram must be destroyed.  This field is modified
	// in internet header processing.  The time is measured in units of
	// seconds, but since every module that processes a datagram must
	// decrease the TTL by at least one even if it process the datagram in
	// less than a second, the TTL must be thought of only as an upper
	// bound on the time a datagram may exist.  The intention is to cause
	// undeliverable datagrams to be discarded, and to bound the maximum
	// datagram lifetime.
	printf("\nIP TTL: %u", ip_packet->ip_ttl);
	// ip_p: RFC 791
	// This field indicates the next level protocol used in the data
	// portion of the internet datagram.  The values for various protocols
	// are specified in "Assigned Numbers" RFC 790. 6 is TCP, 17 is UDP etc.
	printf("\nIP Next Level Protocol: %u", ip_packet->ip_p);
	// ip_sum: RFC 791
	// A checksum on the header only.  Since some header fields change
	// (e.g., time to live), this is recomputed and verified at each point
	// that the internet header is processed.
	printf("\nIP Source: %s\tDest: %s", inet_ntop(AF_INET, &ip_packet->ip_src, source_ip, 256), inet_ntop(AF_INET, &ip_packet->ip_dst, dest_ip, 256));

	// NOTE ON CHECKSUM ALGORITHM
	/*
		 The checksum algorithm is:

		 The checksum field is the 16 bit one's complement of the one's
		 complement sum of all 16 bit words in the header.  For purposes of
		 computing the checksum, the value of the checksum field is zero.

		 This is a simple to compute checksum and experimental evidence
		 indicates it is adequate, but it is provisional and may be replaced
		 by a CRC procedure, depending on further experience.
	 */

	// Now we are ready to parse the next level protocol structure
	switch (ip_packet->ip_p)
	{
		case 6:  // TCP
	//		process_tcp(packet, eth_header);
			break;
		case 17: // UDP
			process_udp(packet, ip_packet, ip_packet->ip_hl*4);
			break;
	}
}
