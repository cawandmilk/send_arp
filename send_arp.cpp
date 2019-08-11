#include "send_arp.h"

void usage()
{
    printf("./send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: ./send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

void dump(uint8_t* packet, size_t size)
{
    // Input: the packet what you want to print the data and the size of your packet
    // output: -

    for(uint32_t i = 0; i < size; i++)
    {
        printf("%.2X ", packet[i]);
        if(i % 16 == 15)
        {
            printf("\n");
        }
    }
    printf("\n\n");
}

int GetSvrMacAddress(const uint8_t* dst)
{
    // Reference: http://egloos.zum.com/kangfeel38/v/4273426
    // Input: Array space to store my Mac address
    // output: return 1 if it terminated well else 0

    int nSD; // Socket descriptor
    struct ifreq *ifr; // Interface request
    struct ifconf ifc;
    int i, numif;

    memset(&ifc, 0, sizeof(ifc));
    ifc.ifc_ifcu.ifcu_req = nullptr;
    ifc.ifc_len = 0;

    // Create a socket that we can use for all of our ioctls
    nSD = socket(PF_INET, SOCK_DGRAM, 0);
    if(nSD < 0)  return 0;
    if(ioctl(nSD, SIOCGIFCONF, &ifc) < 0) return 0;
    if((ifr = (ifreq*)malloc(ifc.ifc_len)) == nullptr)
    {
        return 0;
    }
    else
    {
        ifc.ifc_ifcu.ifcu_req = ifr;
        if (ioctl(nSD, SIOCGIFCONF, &ifc) < 0)
        {
            return 0;
        }
        numif = ifc.ifc_len / sizeof(struct ifreq);
        for (i = 0; i < numif; i++)
        {
            struct ifreq *r = &ifr[i];
            if (!strcmp(r->ifr_name, "lo"))
            {
                continue; // skip loopback interface
            }
            if(ioctl(nSD, SIOCGIFHWADDR, r) < 0)
            {
                return 0;
            }

            memcpy((void*)dst, (uint8_t*)r->ifr_hwaddr.sa_data, MAC_SIZE);
        }
    }
    close(nSD);
    free(ifr);
    return(1);
}

int is_arp_packet(const uint8_t* p)
{
    // Input: A packet which we want to check if the packet is arp or not
    // output: return 1 if p's L3 protocol is arp else 0

    struct libnet_ethernet_hdr e;
    memcpy(&e, &p[0], sizeof(e));

    return ntohs(e.ether_type) == ETHERTYPE_ARP;
}


int is_reply_arp_packet(const uint8_t* p)
{
    // Input: A packet which we want if that was reply arp packet or not
    // output: return 1 if that packet was reply arp packet else 0

    if( !is_arp_packet(p) )
    {
        return 0;
    }
    struct libnet_arp_hdr a;
    memcpy(&a, &p[LIBNET_ETH_H], sizeof(a));

    return ntohs(a.ar_op) == ARPOP_REPLY;
}

void print_mac(uint8_t* mac)
{
    // Input: A mac address what we want to print
    // output: -

    printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
