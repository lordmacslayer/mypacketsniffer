#include <stdio.h>
#include <pcap.h>

// Prints the list of the devices found with
// pcap_findalldevs()
void print_all_devs(pcap_if_t *ptr)
{
	if (ptr == NULL)
		printf("\nNo devices found ");
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
