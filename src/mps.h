/**************************************************
*   FILE : mps.h
* AUTHOR : Siddharth Manoj Bhise
*   DATE : 17th-September-2016
* Signature inserted by "identity_inserter" 
**************************************************/
#include <pcap.h>
#include <pthread.h>

// this file will have the declarations of structures and list funcitons 

#ifndef _MPS_H_
#define _MPS_H_

typedef struct _packet_thread
{
	u_char *user;	// user-defined args
	struct pcap_pkthdr *h;
	u_char *packet;
	// extra info
	pthread_t thread_id;
	unsigned int packet_no;
}PACKET_THREAD;

#endif
