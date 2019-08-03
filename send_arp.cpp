#include "send_arp.h"

using namespace std;

void usage()
{
  printf("./send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: ./send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int GetSvrMacAddress(const u_char* dst)
{
    // Reference: http://egloos.zum.com/kangfeel38/v/4273426

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
            struct sockaddr_in *sin = (struct sockaddr_in *)&r->ifr_addr;
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
    struct libnet_ethernet_hdr e;
    memcpy(&e, p, sizeof(e));

    return ntohs(e.ether_type) == ETHERTYPE_ARP;
}

int is_ip_packet(const u_char* p)
{
    struct libnet_ethernet_hdr e;
    memcpy(&e, p, sizeof(e));

    return ntohs(e.ether_type) == ETHERTYPE_IP;
}

int is_same_mac(const u_char* mac1, const u_char* mac2)
{
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
    for(int i = 0; i < IP_SIZE; i++)
    {
        if( ip1[i] != ip2[i])
        {
            return 0;
        }
    }
    return 1;
}

int is_reply_arp_packet(const u_char* packet)
{
    if( !is_arp_packet(packet) )
    {
        return 0;
    }
    struct libnet_arp_hdr* a = (libnet_arp_hdr*)&packet[LIBNET_ETH_H];

    return ntohs(a->ar_op) == ARPOP_REPLY;
}

void ip_from_str(u_char* ip, char* str)
{
    for(uint32_t i = 0, cnt = 0; i < strlen(str); i++)
    {
        if(str[i] == '.')
        {
            cnt++;
        }
        else
        {
            ip[cnt] = ip[cnt] * 10 + (u_char)(str[i] - '0');
        }
    }
    printf("\n");
}
