# arp
This is a very simple implementation written in C for learning arp protocol and pcap programming. 
Manually filled in arp broadcast datagram and inject into the interface by pcap. 
To receive reply packet from somewhat sent to, 
this program would use pcap to capture or return an error if no repose yet when the timeout occurs. 
Finally, process the packet and extract the targeting host‘s MAC address.

## Usage
```shell
arp [interface] [dest ip]
```

## Installation
Before installing, make sure the pcap has been installed in your system. Please view the pcap official website for more details.
```shell
gcc[clang] arp.c -o arp
```
