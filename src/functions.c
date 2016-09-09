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

// this is just a temporary function for studying how to analyze/parse the captured packets

void parse_packets(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{
	struct ether_header *eth_header = NULL;

	eth_header = (struct ether_header *) packet;
//	printf("\nEthernet header type = %x", ntohs(eth_header->ether_type));
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
#endif
		case ETHERTYPE_LOOPBACK: // 0x9000
			break;
		default:
			printf("\nEthernet header type = N/A");
			break;
	}
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
//	printf("\n%*c", 50, '#');
//	printf("\n%s%10c%5s%10c%5s%10c%10s", "SRNO", ' ', "CAPLEN", ' ', "LEN", ' ', "PAYLOAD");
//	printf("\n%4d%10c%5d%10c%5d%10c%10s", ++i, ' ', h->caplen, ' ',h->len, ' ', packet);
//	printf("\n%*c", 50, '#');
	printf("\n#####################################################################################################");
	printf("\n%20s", "ETHERNET");
	printf("\n%20s", "--------");
	printf("\nSRNO: %d\nPACKET CAP LENGTH: %3d\nPACKET LENGTH (OFF WIRE): %3d", ++i, h->caplen,h->len);
	parse_packets(user, h, packet);
	printf("\n#####################################################################################################\n");
//	printf("%X %X ", h->caplen, h->len);
}
