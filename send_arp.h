#ifndef SEND_ARP_H
#define SEND_ARP_H

#include <algorithm>
#include <arpa/inet.h>
#include <iostream>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "./include/libnet/libnet-macros.h"
#include "./include/libnet/libnet-headers.h"

#define MAC_SIZE 6
#define IP_SIZE 4

struct my_packet {
    struct libnet_ethernet_hdr e;
    struct libnet_arp_hdr a;

    u_char s_mac[MAC_SIZE];
    u_char s_ip[IP_SIZE];
    u_char t_mac[MAC_SIZE];
    u_char t_ip[IP_SIZE];

    uint8_t padding[18];    // 60-sz
};

void usage();
int GetSvrMacAddress(u_char* dst);
void make_arp_packet(my_packet* dst, u_char* s_mac, u_char* s_ip, u_char* t_mac, u_char* t_ip);
int is_arp_packet(const u_char* packet);
int is_same_ip(u_char* ip1, u_char* ip2);
void copy_mac(u_char* dst, const u_char* p);
void copy_ip(u_char* dst, const u_char* p);
my_packet* get_packet();

#endif // SEND_ARP_H
