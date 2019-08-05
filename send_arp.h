#ifndef SEND_ARP_H
#define SEND_ARP_H

#include <arpa/inet.h>
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

struct arp_packet
{
    struct libnet_ethernet_hdr e;
    struct libnet_arp_hdr a;

    u_char sdr_mac[MAC_SIZE];
    u_char sdr_ip[IP_SIZE];
    u_char tgt_mac[MAC_SIZE];
    u_char tgt_ip[IP_SIZE];
};

void usage();
int GetSvrMacAddress(const u_char* dst);

int is_same_mac(const u_char* mac1, const u_char* mac2);
int is_same_ip(u_char* ip1, u_char* ip2);
int is_reply_arp_packet(const u_char* packet);
int is_arp_packet(const u_char* p);

void ip_from_str(u_char* dst, char* str);

void print_mac(u_char* mac);

#endif // SEND_ARP_H
