#include <pcap.h>
#include <stdio.h>
#include "send_arp.h"

int main(int argc, char* argv[])
{
    // send_arp <interface> <sender ip> <target ip>
    if (argc != 4)
    {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    const u_char s_mac[6] = {0, };
    u_char s_ip[4] = {0, };
    const u_char d_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    u_char d_ip[4] = {0, };

    const u_char arp_packet[LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H] = {0, };
    struct libnet_ethernet_hdr* e = (libnet_ethernet_hdr*)&arp_packet[0];
    struct libnet_arp_hdr* a = (libnet_arp_hdr*)&arp_packet[LIBNET_ETH_H];

    GetSvrMacAddress(s_mac);
    ip_from_str(d_ip, argv[2]);

    // Get my IP address
    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        const u_char tmp_mac[6] = {0, };    // dest mac
        memcpy((void*)tmp_mac, packet, sizeof(tmp_mac));

        if( is_same_mac(tmp_mac, s_mac) && is_arp_packet(packet) )
        {
            memcpy(s_ip, &packet[LIBNET_ETH_H + LIBNET_ARP_H + 16], sizeof(s_ip));
            break;
        }
        if( is_same_mac(tmp_mac, s_mac) && is_ip_packet(packet) )
        {
            memcpy(s_ip, &packet[LIBNET_ETH_H + 16], sizeof(s_ip));
            break;
        }
    }

    memcpy(&e->ether_dhost, d_mac, sizeof(d_mac));
    memcpy(&e->ether_shost, s_mac, sizeof(s_mac));
    e->ether_type = htons(ETHERTYPE_ARP);

    a->ar_hrd = htons(ARPHRD_ETHER);
    a->ar_pro = htons(ETHERTYPE_IP);
    a->ar_hln = MAC_SIZE;
    a->ar_pln = IP_SIZE;
    a->ar_op  = htons(ARPOP_REQUEST);

    memcpy((void*)&arp_packet[LIBNET_ETH_H + LIBNET_ARP_H     ], s_mac, sizeof(s_mac));
    memcpy((void*)&arp_packet[LIBNET_ETH_H + LIBNET_ARP_H + 6 ], s_ip , sizeof(s_ip ));
    memcpy((void*)&arp_packet[LIBNET_ETH_H + LIBNET_ARP_H + 10], d_mac, sizeof(d_mac));
    memcpy((void*)&arp_packet[LIBNET_ETH_H + LIBNET_ARP_H + 16], d_ip , sizeof(d_ip ));

    for(int i=0; i<LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H; i++)
    {
        printf("%.2X ", arp_packet[i]);
        if(i%16 == 15) printf("\n");
    }
    printf("\n\n");

    // Who has s_ip[] ip??
    // pcap_sendpacket(handle, packet, sizeof(packet));

    // Get sender's mac address
    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        const u_char tmp_mac[6] = {0, };    // dest mac
        memcpy((void*)tmp_mac, packet, sizeof(tmp_mac));

        printf("%d %d %d\n", is_same_mac(tmp_mac, s_mac), is_reply_arp_packet(packet),
               is_same_ip(s_ip, (u_char*)&packet[LIBNET_ETH_H + LIBNET_ARP_H + 16]));

        if( is_same_mac(tmp_mac, s_mac) && is_reply_arp_packet(packet)
                && is_same_ip(s_ip, (u_char*)&packet[LIBNET_ETH_H + LIBNET_ARP_H + 16]))
        {
            memcpy((void*)d_mac, &packet[LIBNET_ETH_H + LIBNET_ARP_H + 10], sizeof(d_mac));
            break;
        }
    }

    // Save d_mac
    memcpy(&e->ether_dhost, d_mac, sizeof(d_mac));
    memcpy((void*)&arp_packet[LIBNET_ETH_H + LIBNET_ARP_H + 10], d_mac, sizeof(d_mac));

    for(int i=0; i<6; i++)
    {
        printf("%.2X ", d_mac[i]);
    }
    printf("\n");

    // Save target's IP address
    ip_from_str(s_ip, argv[3]); // argv[3]: target ip

    for(int i=0; i<LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H; i++)
    {
        printf("%.2X ", arp_packet[i]);
        if(i%16 == 15) printf("\n");
    }
    printf("\n");

    // pcap_sendpacket(handle, packet, sizeof(packet));

    pcap_close(handle);
    return 0;
}
