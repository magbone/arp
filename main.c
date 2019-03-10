#include "arp.h"

int main(int argc, char** argv)
{
      arp_ethernet_transmission_layer *lp;
      u_int8_t *ip_address;
      arp_ethernet_transmission_layer_create(&lp, &ip_address);
      u_int8_t dest_addr[4] = {192, 168, 31, 138};
      arp_ethernet_packet_data *data;
      arp_ethernet_packet_data_create(lp, &data, ip_address, dest_addr);
      arp_run(data);
      return 0;
}