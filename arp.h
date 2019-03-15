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
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>  
#include <ifaddrs.h>       
#include <errno.h>
#include <unistd.h>

#define ETHNAME "ens33"

#define BUFFER_SIZE 1024

#define ARR_CPY(des, src, len) \
      do{   \
         for(int i = 0; i < len; i++)   \
            des[i] = src[i];\
      }while(0)

#define MALLOC(pptr, structs, size) \
      do{ \
          *pptr = (structs *)malloc(size);  \
          if((*pptr) == NULL)\
          { printf("Error: Init failed.\n"); exit(1);}\
      }while(0)

#define FREE(s) \
      do{   \
         if(NULL != s) \
            free(s); \
      }while(0)



typedef struct _arp_ethernet_transmission_layer
{
      u_int8_t destination[6];
      u_int8_t sender[6];
      u_int16_t type;
} arp_ethernet_transmission_layer;


typedef struct _arp_ethernet_packet_data
{
      arp_ethernet_transmission_layer layer;
      u_int16_t ar_hdr;
      u_int16_t ar_pro;
      u_int8_t ar_hln;
      u_int8_t ar_pln;
      u_int16_t ar_op;
      u_int8_t *ar_sha;
      u_int8_t *ar_spa;
      u_int8_t *ar_tha;
      u_int8_t *ar_tpa;

} arp_ethernet_packet_data;


void arp_ethernet_transmission_layer_create(arp_ethernet_transmission_layer **lpp, u_int8_t **ip_address);

void arp_get_locator_mac(u_int8_t **mac, u_int8_t **ip_address);

void arp_ethernet_packet_data_create(arp_ethernet_transmission_layer *lp, arp_ethernet_packet_data **dpp, u_int8_t *src_ip, u_int8_t *dest_ip);

int arp_packet_create(arp_ethernet_packet_data *lp, char **buffer);

void arp_run(arp_ethernet_packet_data *data);

void arp_packet_unpacked(arp_ethernet_packet_data **data, char *buffer, int buffer_size);

