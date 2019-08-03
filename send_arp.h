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

void usage();
int GetSvrMacAddress(const u_char* dst);

int is_arp_packet(const u_char* packet);
int is_ip_packet(const u_char* packet);

int is_same_mac(const u_char* mac1, const u_char* mac2);
int is_same_ip(u_char* ip1, u_char* ip2);

void ip_from_str(u_char* ip, char* str);
void ip_from_arp_packet(u_char* dst, const u_char* packet);
void ip_from_ip_packet(u_char* dst, const u_char* packet);

int is_reply_arp_packet(const u_char* packet);

#endif // SEND_ARP_H
