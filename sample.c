#include <pcap.h>
#include <stdio.h>

int main(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *pcap_ift_ptr = NULL;
	int ret = pcap_findalldevs(&pcap_ift_ptr, errbuf);
	if (ret == -1)
	{
		printf("\n[ERROR] pcap_findalldevs failed: %s\n", errbuf);
		return 1;
	}
	else if (ret == 0)	// 0 devices found, unlikely case, and success also. Same case
		print_all_devs(pcap_ift_ptr);
	printf("\n");
	return 0;
}
