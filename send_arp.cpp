#include "send_arp.h"

void usage()
{
    printf("./send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: ./send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

void dump(const uint8_t* packet, size_t size)
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

void GetSvrMACAddress(uint8_t* dst)
{
    FILE* fp = popen("/sbin/ifconfig | grep 'ether' | tr -s ' ' | cut -d ' ' -f3", "r");
    char hostMAC_str[20] = {0, }, *result;

    if( (result = fgets(hostMAC_str, 20, fp)) != nullptr )
    {
        for(int i = 0; i < MAC_SIZE; i++)
        {
            dst[i] += hostMAC_str[3*i] >= 'A' ? hostMAC_str[3*i] - 'A' + 10 : hostMAC_str[3*i] - '0';
            dst[i] *= 16;
            dst[i] += hostMAC_str[3*i+1] >= 'A' ? hostMAC_str[3*i+1] - 'A' + 10 : hostMAC_str[3*i+1] - '0';
        }
    }
    else
    {
        printf("MAC assignming error!\n");
    }

    pclose(fp);
}

void GetSvrIPAddress(uint32_t* dst)
{
    FILE* fp = popen("hostname -I", "r");
    char hostIP_str[20] = {0, }, *result;

    if( (result = fgets(hostIP_str, 20, fp)) != nullptr )
    {
        *dst = inet_addr(hostIP_str);
    }
    else
    {
        printf("IP assigning error!\n");
    }

    pclose(fp);
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

void print_mac(const uint8_t* mac)
{
    // Input: A mac address what we want to print
    // output: -

    printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
