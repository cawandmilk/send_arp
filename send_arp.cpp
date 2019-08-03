#include "send_arp.h"

using namespace std;

void usage()
{
  printf("./send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: ./send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int GetSvrMacAddress(u_char* dst)
{
    // http://egloos.zum.com/kangfeel38/v/4273426

    int nSD; // Socket descriptor
    struct ifreq *ifr; // Interface request
    struct ifconf ifc;
    int i, numif;

    memset(&ifc, 0, sizeof(ifc));
    ifc.ifc_ifcu.ifcu_req = NULL;
    ifc.ifc_len = 0;

    // Create a socket that we can use for all of our ioctls
    nSD = socket( PF_INET, SOCK_DGRAM, 0 );
    if ( nSD < 0 )  return 0;
    if(ioctl(nSD, SIOCGIFCONF, &ifc) < 0) return 0;
    if ((ifr = (ifreq*)  malloc(ifc.ifc_len)) == NULL)
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
                continue; // skip loopback interface

            if(ioctl(nSD, SIOCGIFHWADDR, r) < 0)
                return 0;

            memcpy(dst, (u_char*)r->ifr_hwaddr.sa_data, sizeof(dst));
            return 0;
        }
    }
    close(nSD);
    free(ifr);
    return(1);
}

void make_arp_packet(my_packet* p, u_char* s_mac, u_char* s_ip, u_char* t_mac, u_char* t_ip)
{
    memcpy(&p->e.ether_dhost, t_mac, sizeof(p->e.ether_dhost));
    memcpy(&p->e.ether_shost, s_mac, sizeof(p->e.ether_shost));
    p->e.ether_type = ETHERTYPE_ARP;

    p->a.ar_hrd = ARPHRD_ETHER;
    p->a.ar_pro = htons(ETHERTYPE_IP);
    p->a.ar_hln = MAC_SIZE;
    p->a.ar_pln = IP_SIZE;
    p->a.ar_op = htons(ARPOP_REPLY);

    memcpy(&p->s_mac, s_mac, sizeof(p->s_mac));
    memcpy(&p->s_ip, s_ip, sizeof(p->s_ip));
    memcpy(&p->t_mac, t_mac, sizeof(p->t_mac));
    memcpy(&p->t_ip, t_ip, sizeof(p->t_ip));

    memset(p->padding, 0, sizeof(p->padding));
}

int is_arp_packet(const u_char* p)
{
    struct libnet_ethernet_hdr e;
    memcpy(&e, p, sizeof(e));

    return e.ether_type == ETHERTYPE_ARP;
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

void copy_mac(u_char* dst, const u_char* p)
{
    struct libnet_ethernet_hdr e;
    memcpy(&e, p, sizeof(e));
    memcpy(dst, &e.ether_shost, sizeof(*dst));

}

void copy_ip(u_char* dst, const u_char* p)
{
    struct libnet_ipv4_hdr i;
    memcpy(&i, &p[LIBNET_ETH_H], sizeof(i));
    memcpy(dst, &i, sizeof(dst));
}

my_packet* get_packet(void)
{
    my_packet* new_packet = (my_packet*)malloc(sizeof(my_packet));
    return new_packet;
}

void put_packet(my_packet* p)
{
    free(p);
}
