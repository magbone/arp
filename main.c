#include "arp.h"

int main(int argc, char** argv)
{
      arp_ethernet_transmission_layer *lp;
      arp_ethernet_transmission_layer_create(&lp);
      return 0;
}