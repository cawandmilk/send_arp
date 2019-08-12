#ifndef SEND_ARP_H
#define SEND_ARP_H

#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "./include/libnet/libnet-macros.h"
#include "./include/libnet/libnet-headers.h"

#define MAC_SIZE 6
#define IP_SIZE 4

#pragma pack(push, 1) // struture padding terminate
struct arp_packet
{
    struct libnet_ethernet_hdr e;
    struct libnet_arp_hdr a;

    uint8_t  sdr_mac[MAC_SIZE];
    uint32_t sdr_ip;
    uint8_t  tgt_mac[MAC_SIZE];
    uint32_t tgt_ip;
};
#pragma pack(pop)

void usage();
void dump(const uint8_t* packet, size_t size);
int GetSvrMacAddress(const uint8_t* dst);

int is_reply_arp_packet(const uint8_t* packet);
int is_arp_packet(const uint8_t* p);
void print_mac(const uint8_t* mac);

#endif // SEND_ARP_H
