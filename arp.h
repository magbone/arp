#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <arpa/inet.h>  
#include <ifaddrs.h>       
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pcap/pcap.h>

#ifndef _ARP_H_
#define _ARP_H_

#ifndef _IPv4
#define _IPv4 0x0800
#endif // !_IPv4

#ifndef _ARP
#define _ARP 0x0806
#endif // !_ARP

#define IS_EMPTY_MAC(mac) (mac[0] == mac[1] == mac[2] == mac[3] == mac[4] == mac[5] == 0)
#define IS_EMPTY_IP(ip) (ip[0] == ip[1] == ip[2] == ip[3] == 0)

#define FRAME_SIZE ( sizeof( struct ether_header ) + sizeof( struct ether_arp ) )
// static const char *err_msg [] = {
//       NULL,
//       "Invalid name value",
//       "Null pointer",
//       NULL
// };

void arp_pcap_handler ( u_char *user, const struct pcap_pkthdr *h, const u_char *bytes );

struct ether_header *ether_header_new( const u_char *src_mac );
struct ether_arp *ether_arp_new( const u_char *src_mac, const u_char *src_ip, const u_char * dst_ip );
int get_locator_address( const char *if_name, u_char *local_mac, u_char *local_ip );
int send_frame_and_capture( char *if_name, u_char *buffer, u_int size, char *dst_ip );
void pcap_capture_callback( u_char *user, const struct pcap_pkthdr *h, const u_char *bytes );
int parse_ip_to_array( const char *ip, u_char *ipp );
void uint32_to_array( uint32_t u, u_char * a);
int arp_run( const char *if_name, const char *dst_ip );


#endif // !_ARP_H_