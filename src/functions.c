/**************************************************
*   FILE : src/functions.c
* AUTHOR : Siddharth Manoj Bhise
*   DATE : 7th-September-2016
* Signature inserted by "identity_inserter" 
**************************************************/
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>	// for functions like ntohs etc.
#include <net/ethernet.h>
#include <pthread.h>
#include <stdlib.h>

#ifndef __APPLE__ && __MACH__		// malloc function on Mac OS X is declared in the file stdlib.h and not in malloc.h
#include <malloc.h>
#endif

#include "mps.h"

pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
void parse_packets(void *p)
{
	// Use the ETHER_IS_VALID_LEN in net/ethernet.h to validate length of the ethernet packet
	struct ether_header *eth_header = NULL;
	PACKET_THREAD *pt = (PACKET_THREAD *) p;
	u_char *user = pt->user;
	const struct pcap_pkthdr *h = pt->h;
	const u_char *packet = pt->packet;
	pthread_t my_thread_id = pt->thread_id;
	unsigned int packet_no = pt->packet_no;

	// acquire lock
	pthread_mutex_lock(&print_mutex);
	printf("\n#####################################################################################################");
		printf("\n%20s", "FRAME");
		printf("\n%20s", "-----");
		printf("\nSrno: %d\nFrame Cap Length: %3d\nFrame Length (Off Wire): %3d", packet_no, h->caplen,h->len);

	eth_header = (struct ether_header *) packet;
	printf("\n%20s", "ETHERNET");
	printf("\n%20s", "--------");
	printf("\nETHERNET ether_type = 0x%X", ntohs(eth_header->ether_type));
	switch (ntohs(eth_header->ether_type))
	{
		case ETHERTYPE_PUP: // 0x0200
			break;
		case ETHERTYPE_IP: // 0x0800
			process_ip_4(packet, eth_header);
			break;
		case ETHERTYPE_ARP: // 0x0806
			break;
		case ETHERTYPE_REVARP: // 0x8036
			break;
		case ETHERTYPE_VLAN: // 0x8100
			break;
		case ETHERTYPE_IPV6: // 0x86dd
			break;
#ifdef __APPLE__ && __MACH__
		case ETHERTYPE_PAE: // 0x888e
			break;
		case ETHERTYPE_RSN_PREAUTH: // 0x88c7
			break;
		case 0x4006:	// don't know why but on Mac, lo0 interface, this is what I receive
		case 0x4003: // not sure how to handle this. Will have to read more.
			break;
#endif
		case ETHERTYPE_LOOPBACK: // 0x9000
			break;
		default:
			// yet to handle
			break;
	}
	printf("\n#####################################################################################################\n");
	// release lock
	pthread_mutex_unlock(&print_mutex);
	free (p);
}


// Prints the list of the devices found with
// pcap_findalldevs()
void print_all_devs(pcap_if_t *ptr)
{
	if (ptr == NULL)
		printf("\nNo devices found");
	else
	{
		printf("\n\t\t%-15s%10c%-10s","NAME", ' ', "DESCRIPTION");
		printf("\n\t\t%-15s%10c%-10s","----", ' ', "-----------");
		do 
		{	// TBD: format this printf later for better view
			printf("\n\t\t%-15s%10c%-10s", ptr->name,' ', ptr->description);
			ptr = ptr->next;
		} while (ptr != NULL);
	}
	printf("\n");
}

void mypcapcallback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{
	static int i;
	pthread_t thread_id;
	PACKET_THREAD *packet_holder = NULL;
	if (h->caplen < ETHER_MIN_LEN)
	{
		// caplen is the captured length.
		// len is the total length.
	//	printf("\nFrame too short to process. Captured length = %d, min = %d", h->caplen, ETHER_MIN_LEN);
		return;
	}
	packet_holder = (PACKET_THREAD *) malloc(sizeof(PACKET_THREAD));
	if (packet_holder == NULL)
	{
		fprintf(stderr, "\nFailed to allocate memory for packet holder\n");
		exit(1);
	}

	packet_holder->user = user;
	packet_holder->h = h;
	packet_holder->packet = packet;
	packet_holder->thread_id = thread_id;
	packet_holder->packet_no = ++i;

	pthread_create(&thread_id, NULL, (void *) parse_packets, (void *) packet_holder);
}

