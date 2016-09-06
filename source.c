#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

extern void mypcapcallback(u_char *, const struct pcap_pkthdr, const u_char *);
extern void print_all_devs(pcap_if_t *);
int main(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *pcap_ift_ptr = NULL;
	pcap_t *pcap_t_ptr = NULL;
	char dev_name[256];
	int ret = pcap_findalldevs(&pcap_ift_ptr, errbuf);
	system("clear");
	if (ret == -1)
	{
		printf("\n[ERROR] pcap_findalldevs failed: %s\n", errbuf);
		return 1;
	}
	else if (ret == 0)	// 0 devices found, unlikely case. Same case for success also.
		print_all_devs(pcap_ift_ptr);
	
	if (pcap_ift_ptr != NULL)
	{
		memset(errbuf, 0, PCAP_ERRBUF_SIZE);
		memset(dev_name, 0, 256);
		// ask the user for the name of the interface
		printf("\nEnter the name of the device you wish to capture for packets (with correct spelling): ");
		scanf("%s", dev_name);
		
		// opening in promiscuous mode
		pcap_t_ptr = pcap_open_live(dev_name, 65535, 1, 1000, errbuf);	// 1000 --> time out in ms
		
		if (pcap_t_ptr == NULL)
		{
			printf("\n[ERROR] pcap_open_live failed to open %s: %s\n", dev_name, errbuf);
			return 1;
		}
		system("clear");
		printf("%20s: %10s\n\n","OPENING DEVICE FOR CAPTURE", dev_name);
		while (1)
		{
			ret = pcap_dispatch(pcap_t_ptr, -1, mypcapcallback, NULL);		
			switch (ret)
			{
				case 0:
					// cnt exhausted or
					// device in non block mode hence did not read any packet or
					// time out interval expired
					// no more packets are available in '`savefile''
					break;
				case -1:
					// error occurred
					printf("[ERROR] pcap_dispatch: %s", pcap_geterr(pcap_t_ptr));
					ret = -10;
					break;
				case -2:
					// call to pcap_breakloop()
					ret = -20;
					break;
			}

			if (ret == -10 || ret == -20)
				break;
		}		
	}
	printf("\n");
	return 0;
}
