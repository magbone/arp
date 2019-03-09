#include "arp.h"

int main(int argc, char** argv)
{
      arp_ethernet_transmission_layer *lp;
      u_int8_t *ip_address;
      arp_ethernet_transmission_layer_create(&lp, &ip_address);
      return 0;
}