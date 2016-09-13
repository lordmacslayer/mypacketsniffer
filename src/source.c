/**************************************************
*   FILE : src/source.c
* AUTHOR : Siddharth Manoj Bhise
*   DATE : 7th-September-2016
* Signature inserted by "identity_inserter" 
**************************************************/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PREP_TCP_UDP_FILTER(FILTER_STR, BPF_INT32_HOST) sprintf(FILTER_STR, "tcp udp host %d", BPF_INT32_HOST)
#define TCP_UDP_FILTER "tcp || udp"
#define UDP_FILTER "udp"

extern void mypcapcallback(u_char *, const struct pcap_pkthdr, const u_char *);
extern void print_all_devs(pcap_if_t *);
int main(void)
{
	// Declarations 
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *pcap_ift_ptr = NULL;
	pcap_t *pcap_t_ptr = NULL;
	char dev_name[256];
	bpf_u_int32 ipaddr, netmaskaddr;
	unsigned char *u_char_print_ip, *u_char_print_netmask;
	/* filter specific declarations */
	struct bpf_program bpf_prog_fp;
	// end of Declarations


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
		memset(errbuf, 0, PCAP_ERRBUF_SIZE);
		// finding the ipv4 and the netmask of the chosen device
		ret = pcap_lookupnet(dev_name, &ipaddr, &netmaskaddr, errbuf);
		if (ret == -1)
		{
			printf("\n[ERROR] pcap_lookupnet: %s\n", errbuf);
			return 1;
		}
		u_char_print_ip = (unsigned char *) &ipaddr;
		u_char_print_netmask = (unsigned char *) &netmaskaddr;


		system("clear");
		printf("%20s: %10s (ipv4: %d.%d.%d.%d\tnetmaskaddr: %d.%d.%d.%d)\n\n","OPENING DEVICE FOR CAPTURE", dev_name, *u_char_print_ip, *(u_char_print_ip+1), *(u_char_print_ip+2), *(u_char_print_ip+3), *u_char_print_netmask, *(u_char_print_netmask+1), *(u_char_print_netmask+2), *(u_char_print_netmask+3));

		memset(errbuf, 0, PCAP_ERRBUF_SIZE);
		// set up the filter to capture, say tcp and udp traffic arriving at and going from this host Siddharths-Mac-mini.local
	//	if (pcap_compile(pcap_t_ptr, &bpf_prog_fp, TCP_UDP_FILTER, 0, netmaskaddr) == -1)
		if (pcap_compile(pcap_t_ptr, &bpf_prog_fp, UDP_FILTER, 0, netmaskaddr) == -1)
		{
			printf("\n[ERROR] pacp_compile: %s\n", pcap_geterr(pcap_t_ptr));
			return 1;
		}
		// we now set the compiled filter
		if (pcap_setfilter(pcap_t_ptr, &bpf_prog_fp) == -1)
		{
			printf("\n[ERROR] pcap_setfilter: %s\n", pcap_geterr(pcap_t_ptr));
			return 1;
		}

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
