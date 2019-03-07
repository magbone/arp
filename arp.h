#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <arpa/inet.h>  
#include <ifaddrs.h>       
#include <errno.h>
#include <unistd.h>

#define ETHNAME "en0"
#define ARR_CPY(des, src, len) \
      do{   \
         for(int i = 0; i < len; i++)   \
            des[i] = src[i];\
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


void arp_ethernet_transmission_layer_create(arp_ethernet_transmission_layer **lpp);

void arp_get_locator_mac(u_int8_t **mac);