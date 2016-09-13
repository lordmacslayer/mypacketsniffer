/**************************************************
*   FILE : process_tcp.c
* AUTHOR : Siddharth Manoj Bhise
*   DATE : 10th-September-2016
* Signature inserted by "identity_inserter" 
**************************************************/
#include <stdio.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

// TODO:
//			Handle everything related to TCP correctly!!!! Leaving this unhandled currently since I now want to move on to UDP
void process_tcp(const u_char *packet, struct ether_header *eth_header)
{
	struct tcphdr *tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));

	printf("\n%20s", "TRANSPORT LAYER");
	printf("\n%20s", "--------- -----");

	// th_sport: source port number
	printf("\nTCP Source Port: %u", ntohs(tcp_header->th_sport));
	// th_dport: destination port number
	printf("\nTCP Destination Port: %u", ntohs(tcp_header->th_dport));
	// th_seq: RFC 793
	// The sequence number of the first data octet in this segment (except
	// when SYN is present). If SYN is present the sequence number is the
	// initial sequence number (ISN) and the first data octet is ISN+1.
	// SYN is the first sent frame in TCP handshaking. ISN need not be 0.
	printf("\nTCP Seq Number: %u", ntohl(tcp_header->th_seq));
	// th_ack: RFC 793
	// If the ACK control bit is set this field contains the value of the
	// next sequence number the sender of the segment is expecting to
	// receive.  Once a connection is established this is always sent.
	printf("\nTCP Ack Number: %u", ntohl(tcp_header->th_ack));
	// th_off: RFC 793
	// The number of 32 bit words in the TCP Header.  This indicates where
	// the data begins.  The TCP header (even one including options) is an
	// integral number of 32 bits long.
	printf("\nTCP Header Length (or Data Offset): %u", (unsigned int)tcp_header->th_off*4);
	// th_flags: RFC 793
	printf("\nTCP Flags: 0x%x", tcp_header->th_flags);
	switch (tcp_header->th_flags)
	{
		case TH_FIN:	// 0x01
			printf(" FIN");
			break;
		case TH_SYN:	//0x02
			printf(" SYN");
			break;
		case TH_RST: // 0x04
			printf(" RST");
			break;
		case TH_PUSH:	// 0x08
			printf(" PUSH");
		case TH_ACK: // 0x10
			printf(" ACK");
			break;
		case TH_URG:	// 0x20
			printf(" URG");
			break;
		case TH_ECE:	// 0x40
			printf(" ECE");
			break;
		case TH_CWR:	// 0x80
			printf(" CWR");
			break;
		case TH_FLAGS:	// (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
			printf(" FIN SYN RST ACK URG ECE CWR");
			break;
	}
	// th_win: RFC 793
	// The number of data octets beginning with the one indicated in the
	// acknowledgment field which the sender of this segment is willing to
	// accept.
	printf("\nTCP Window: %u", ntohs(tcp_header->th_win));

}
