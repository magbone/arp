#include "arp.h"

void arp_ethernet_transmission_layer_create(arp_ethernet_transmission_layer **lpp)
{
      *lpp = (arp_ethernet_transmission_layer *) malloc(sizeof(arp_ethernet_transmission_layer));
      if((*lpp) == NULL)
      {
            printf("Error: Init failed.\n");
            exit(1);
      }
      u_int8_t det[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
      ARR_CPY((*lpp)->destination, det, 6);
      u_int8_t *local_mac;
      arp_get_locator_mac(&local_mac);
      ARR_CPY((*lpp)->sender, local_mac, 6);

      (*lpp)->type = 0x0806;
}

void arp_get_locator_mac(u_int8_t **mac)
{
      *mac = (u_int8_t *)malloc(sizeof(u_int8_t) * 6);
      if((*mac) == NULL)
      {
            printf("Error: Init failed.\n");
            exit(1);
      }

      struct sockaddr_in *addr;
      struct ifaddrs *ifadr, *if_list;
      u_int8_t *up;

      if(getifaddrs(&if_list) < 0)
      {
            perror("getifaddrs");
            exit(1);
      } 

      for(ifadr = if_list; ifadr != NULL; ifadr = ifadr->ifa_next)
      {
            if(ifadr->ifa_addr->sa_family == AF_LINK)
            {
                  if(strcmp(ETHNAME,ifadr->ifa_name) == 0)
                  {
                        up = (u_int8_t *)LLADDR((struct sockaddr_dl *)(ifadr->ifa_addr));
                        ARR_CPY((*mac), up, 6);
                        break;
                  }
            }
      }
      freeifaddrs(if_list);
      //FREE(addr);
}