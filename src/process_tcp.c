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
	printf("\nTCP Seq Number: %u", ntohs(tcp_header->th_seq));
	// th_ack: RFC 793
	// If the ACK control bit is set this field contains the value of the
	// next sequence number the sender of the segment is expecting to
	// receive.  Once a connection is established this is always sent.
	printf("\nTCP Ack Number: %u", ntohs(tcp_header->th_ack));
	// th_off: RFC 793
	// The number of 32 bit words in the TCP Header.  This indicates where
	// the data begins.  The TCP header (even one including options) is an
	// integral number of 32 bits long.
	printf("\nTCP Data Offset: %u", ntohs(tcp_header->th_off));
	// TODO: print the remaining members from tcp.h later
}
