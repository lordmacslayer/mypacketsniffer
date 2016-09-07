#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>	// for functions like ntohs etc.
#include <net/ethernet.h>

// this is just a temporary function for studying how to analyze/parse the captured packets

void parse_packets(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{
	struct ether_header *eth_header = NULL;

	eth_header = (struct ether_header *) packet;
	printf("\nEthernet header type = %x", ntohs(eth_header->ether_type));
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
	printf("\nSRNO: %d\nPACKET CAP LENGTH: %3d\nPACKET LENGTH (OFF WIRE): %3d\nPACKET PAYLOAD: %3s", ++i, h->caplen,h->len, packet);
	parse_packets(user, h, packet);
	printf("\n#####################################################################################################\n");
//	printf("%X %X ", h->caplen, h->len);
}
