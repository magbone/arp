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
      MALLOC(mac, u_int8_t, sizeof(u_int8_t) * 6);
      MALLOC(ip_address, u_int8_t, sizeof(u_int8_t) * 4);
      struct sockaddr_in *addr;
      struct ifaddrs *ifadr, *if_list;

      if(getifaddrs(&if_list) < 0)
      {
            perror("Error");
            exit(1);
      }

      for(ifadr = if_list; ifadr != NULL; ifadr = ifadr->ifa_next)
      {
            if(ifadr->ifa_addr->sa_family == AF_INET)
            {
                  if(strcmp(ETHNAME, ifadr->ifa_name) == 0)
                  {
                        addr = (struct sockaddr_in *) ifadr->ifa_addr;
                        **ip_address = (addr->sin_addr.s_addr << 24) >> 24;
                        *(*ip_address + 1) = (addr->sin_addr.s_addr << 16) >> 24;
                        *(*ip_address + 2) = (addr->sin_addr.s_addr << 8) >> 24;
                        *(*ip_address + 3) = (addr->sin_addr.s_addr) >> 24;

                  }
            }

            if(ifadr->ifa_addr->sa_family == AF_PACKET)
            {
                  struct sockaddr_ll *s = (struct sockaddr_ll *)(ifadr->ifa_addr);
                  for(int i = 0; i < 6; i++)
                  {
                        *(*mac + i) = s->sll_addr[i];
                  }
            }
      }
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
      MALLOC(&((*dpp)->ar_tha), u_int8_t, sizeof(u_int8_t) * (*dpp)->ar_hln);
      ARR_CPY((*dpp)->ar_tha, (*dpp)->layer.destination, (*dpp)->ar_hln);

      MALLOC(&((*dpp)->ar_tpa), u_int8_t, sizeof(u_int8_t) * (*dpp)->ar_pln);
      ARR_CPY((*dpp)->ar_tpa, dest_ip, (*dpp)->ar_pln);
}

void arp_run(arp_ethernet_packet_data *data)
{
      if(data == NULL) return;

      int sockfd, sockld;

      if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
            perror("Error");
            return;
      }
      
      if((sockld = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
      {
            perror("Error");
            return;
      }
      struct sockaddr_ll addr_ll;
      memset(&addr_ll, 0, sizeof(addr_ll));

      addr_ll.sll_family = AF_PACKET;
      addr_ll.sll_protocol = data->layer.type;
      addr_ll.sll_ifindex = if_nametoindex(ETHNAME);
      memcpy(addr_ll.sll_addr, data->layer.destination, 6);
      
      char *send_buffer;
      int send_len = arp_packet_create(data, &send_buffer);


      char recv_buffer[BUFFER_SIZE];
      memset(recv_buffer, 0,  BUFFER_SIZE);
      int recv_len;
      if(sendto(sockfd, send_buffer, send_len, 0, (struct sockaddr*) &addr_ll, sizeof(addr_ll)) < 0)
      {
            perror("Error");
      }

      if((recv_len = recv(sockld, recv_buffer, BUFFER_SIZE, 0)) < 0)
      {
            perror("Error");
      }
      
      printf("%d\n", recv_len);
      close(sockfd);
}

int arp_packet_create(arp_ethernet_packet_data *lp, char **buffer)
{
      int app_len = 2 * (sizeof(lp->ar_hdr) + sizeof(lp->ar_hln) + lp->ar_hln + lp->ar_pln + sizeof(lp->layer.sender)) + sizeof(lp->ar_op) + sizeof(lp->layer.type);
      MALLOC(buffer, char, app_len * sizeof(char));
      int index = 0;
      char *buffer_arr = *buffer;
      
      for(int i = 0; i < sizeof(lp->layer.destination); i++)
            buffer_arr[index++] = lp->layer.destination[i];

      for(int i = 0; i < sizeof(lp->layer.sender); i++)
            buffer_arr[index++] = lp->layer.sender[i];

      buffer_arr[index++] = (lp->layer.type >> 8) &0xff;
      buffer_arr[index++] = lp->layer.type & 0xff;
      buffer_arr[index++] = (lp->ar_hdr >> 8) & 0xff;
      buffer_arr[index++] = lp->ar_hdr & 0xff;
      buffer_arr[index++] = (lp->ar_pro >> 8) & 0xff;
      buffer_arr[index++] = lp->ar_pro & 0xff;
      buffer_arr[index++] = lp->ar_hln;
      buffer_arr[index++] = lp->ar_pln;
      buffer_arr[index++] = (lp->ar_op >> 8) & 0xff;
      buffer_arr[index++] = lp->ar_op && 0xff;

      for(int i = 0; i < 6; i++)
            buffer_arr[index++] = lp->ar_sha[i];

      for(int i = 0; i < 4; i++)
            buffer_arr[index++] = lp->ar_spa[i];

      for(int i = 0; i < 6; i++) 
            buffer_arr[index++] = lp->ar_tha[i];

      for(int i = 0; i < 4; i++)  
            buffer_arr[index++] = lp->ar_tpa[i];

      return index;
}