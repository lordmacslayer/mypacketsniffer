#include <pcap.h>
#include <stdio.h>

int main(void)
{
	char errbuf[256];
	char *network_interface = pcap_lookupdev(errbuf);
	if (network_interface != NULL)
	{
		printf("\nNETWORK INTERFACE NAME: %s", network_interface);
	}
	else
	{
		printf("\n[ERR] pcap_lookupdev failed: error: %s", errbuf);
	}
	printf("\n");
	return 0;
}
