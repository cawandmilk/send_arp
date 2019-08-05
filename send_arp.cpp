#include "send_arp.h"

void usage()
{
  printf("./send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: ./send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int GetSvrMacAddress(const u_char* dst)
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

            memcpy((void*)dst, (u_char*)r->ifr_hwaddr.sa_data, MAC_SIZE);
        }
    }
    close(nSD);
    free(ifr);
    return(1);
}

int is_arp_packet(const u_char* p)
{
    // Input: A packet which we want to check if the packet is arp or not
    // output: return 1 if p's L3 protocol is arp else 0

    struct libnet_ethernet_hdr e;
    memcpy(&e, p, sizeof(e));

    return ntohs(e.ether_type) == ETHERTYPE_ARP;
}

int is_same_mac(const u_char* mac1, const u_char* mac2)
{
    // Input: Two mac address which we want to compare
    // output: return 1 if two mac address were same else 0

    for(int i = 0; i < MAC_SIZE; i++)
    {
        if(mac1[i] != mac2[i])
        {
            return 0;
        }
    }
    return 1;
}

int is_same_ip(u_char* ip1, u_char* ip2)
{
    // Input: Two ip address which we want to compare
    // output: return 1 if two ip address were same else 0

    for(int i = 0; i < IP_SIZE; i++)
    {
        if(ip1[i] != ip2[i])
        {
            return 0;
        }
    }
    return 1;
}

int is_reply_arp_packet(const u_char* packet)
{
    // Input: A packet which we want if that was reply arp packet or not
    // output: return 1 if that packet was reply arp packet else 0

    if( !is_arp_packet(packet) )
    {
        return 0;
    }
    struct libnet_arp_hdr a;
    memcpy(&a, &packet[LIBNET_ETH_H], sizeof(a));

    return ntohs(a.ar_op) == ARPOP_REPLY;
}

void ip_from_str(u_char* dst, char* str)
{
    // Input: A string we want to convert and an array we want to store that converted ip.
    // output: -

    for(uint32_t i = 0, cnt = 0; i < strlen(str); i++)
    {
        if(str[i] == '.')
        {
            cnt++;
        }
        else
        {
            dst[cnt] = dst[cnt] * 10 + (u_char)(str[i] - '0');
        }
    }
    printf("\n");
}

void print_mac(u_char* mac)
{
    // Input: A mac address what we want to print
    // output: -

    printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
