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

    my_packet* bp = get_packet();
    u_char my_mac[6] = {0, };
    u_char my_ip[4] = {127, 0, 0, 1};
    u_char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    GetSvrMacAddress(my_mac);

    make_arp_packet(bp, my_mac, my_ip, broadcast_mac, (u_char*)argv[3]);

    pcap_sendpacket(handle, (const u_char*)broadcast_packet, sizeof(broadcast_packet));

    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        if( is_arp_packet(packet) )
        {
            // u_char ip[4];
            //struct sockaddr_in tmp;


            // if(is_same_ip(inet_aton(argv[2], &tmp.sin_addr), copy_ip(ip, packet)));
            // inet_aton();
            // struct sockaddr_in a;
        }
    }

    pcap_close(handle);
    return 0;
}
