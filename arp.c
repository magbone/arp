#include "arp.h"

void arp_ethernet_transmission_layer_create(arp_ethernet_transmission_layer **lpp, u_int8_t **ip_address)
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
      arp_get_locator_mac(&local_mac, ip_address);
      ARR_CPY((*lpp)->sender, local_mac, 6);
      (*lpp)->type = 0x0806;
}

void arp_get_locator_mac(u_int8_t **mac, u_int8_t **ip_address)
{
      *mac = (u_int8_t *)malloc(sizeof(u_int8_t) * 6);
      if((*mac) == NULL)
      {
            printf("Error: Init failed.\n");
            exit(1);
      }

      MALLOC(ip_address, u_int8_t, sizeof(uint8_t) * 4);
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
            if(ifadr->ifa_addr->sa_family == AF_INET)
            {
                  if(strcmp(ETHNAME,ifadr->ifa_name) == 0)
                  {
                        addr = (struct sockaddr_in *)ifadr->ifa_addr;
                        u_int8_t *ip = *ip_address;
                        ip[0] = ((addr->sin_addr.s_addr << 24) >> 24);
                        ip[1] = ((addr->sin_addr.s_addr << 16) >> 24);
                        ip[2] = ((addr->sin_addr.s_addr << 8) >> 24);
                        ip[3] = (addr->sin_addr.s_addr >> 24); 
                        up = (u_int8_t *)LLADDR((struct sockaddr_dl *)(ifadr->ifa_addr));
                        ARR_CPY((*mac), up, 6);
                        break;
                  }
            }
      }
      freeifaddrs(if_list);
}

void arp_ethernet_packet_data_create(arp_ethernet_transmission_layer *lp, arp_ethernet_packet_data **dpp, u_int8_t *src_ip, u_int8_t *dest_ip)
{
      *dpp = (arp_ethernet_packet_data *) malloc(sizeof(arp_ethernet_packet_data));
      if((*dpp) == NULL)
      {
            printf("Error: Init failed.\n");
            exit(1);
      }

      (*dpp)->layer = *lp;
      (*dpp)->ar_hdr = 0x0001; // Ethernet
      (*dpp)->ar_pro = 0x0800; // IPv4
      (*dpp)->ar_hln = 0x06;
      (*dpp)->ar_pln = 0x04;
      (*dpp)->ar_op = 0x0001; //request | reply
      if(src_ip == NULL)
      {
            printf("Error: Init failed.\n");
            exit(1);
      }
      MALLOC(&((*dpp)->ar_sha), u_int8_t, sizeof(u_int8_t) * (*dpp)->ar_hln);
      ARR_CPY((*dpp)->ar_sha, lp->sender, (*dpp)->ar_hln);

      MALLOC(&((*dpp)->ar_spa), u_int8_t, sizeof(u_int8_t) * (*dpp)->ar_pln);
      ARR_CPY((*dpp)->ar_spa, src_ip, (*dpp)->ar_pln);
      if(dest_ip == NULL)
      {
            printf("Error: Init failed.\n");
            exit(1);
      }
      memset(&((*dpp)->ar_tha), 0, (*dpp)->ar_hln);

      MALLOC(&((*dpp)->ar_tpa), u_int8_t, sizeof(u_int8_t) * (*dpp)->ar_pln);
      ARR_CPY((*dpp)->ar_tpa, dest_ip, (*dpp)->ar_pln);
}

void arp_run(arp_ethernet_packet_data *data)
{
      if(data == NULL) return;

      int sockfd;

      struct sockaddr_in addr;

      if ((sockfd = socket(PF_INET, SOCK_RAW, 0)) < 0) {
            perror("Error");
            return;
      }
      
}