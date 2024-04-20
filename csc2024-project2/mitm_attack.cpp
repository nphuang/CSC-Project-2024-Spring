#include <iostream>
#include <iomanip>
#include <map>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <memory>
#include <array>
#include <linux/if_ether.h> // Include the header file that defines "ETH_P_ARP"
#include <net/if_arp.h>       // for ARPHRD_ETHER and ARPOP_REQUEST
#include <netinet/ether.h>
#include <linux/if_packet.h> // Include the header file that defines "struct sockaddr_ll"
#include <net/ethernet.h>
#include <thread>
using namespace std;


struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};
// struct arp_packet {
//     struct ethhdr eth;
//     struct arp_header arp;
// };
#define ETHER_HEADER_LEN sizeof(struct ether_header)
#define ETHER_ARP_LEN sizeof(struct ether_arp)
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN
#define IP_ADDR_LEN 4
#define BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

struct ether_arp *fill_arp_packet(const unsigned char *src_mac_addr, const char *src_ip, const char *dst_ip)
{
    struct ether_arp *arp_packet;
    struct in_addr src_in_addr, dst_in_addr;
    unsigned char dst_mac_addr[ETH_ALEN] = BROADCAST_ADDR;
    // ip address translation
    inet_pton(AF_INET, src_ip, &src_in_addr);
    inet_pton(AF_INET, dst_ip, &dst_in_addr);

    // fill the arp packet
    arp_packet = (struct ether_arp *)malloc(ETHER_ARP_LEN);
    arp_packet->arp_hrd = htons(ARPHRD_ETHER);
    arp_packet->arp_pro = htons(ETHERTYPE_IP);
    arp_packet->arp_hln = ETH_ALEN;
    arp_packet->arp_pln = IP_ADDR_LEN;
    arp_packet->arp_op = htons(ARPOP_REQUEST);
    memcpy(arp_packet->arp_sha, src_mac_addr, ETH_ALEN);
    memcpy(arp_packet->arp_tha, dst_mac_addr, ETH_ALEN);
    memcpy(arp_packet->arp_spa, &src_in_addr, IP_ADDR_LEN);
    memcpy(arp_packet->arp_tpa, &dst_in_addr, IP_ADDR_LEN);

    return arp_packet;
}

map<string, string> devices;
string exec(const char* cmd) {
    array<char, 128> buffer;
    string result;
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}
void arp_request(const char *if_name, const char *base_ip)
{
    struct sockaddr_ll saddr_ll;
    struct ether_header *eth_header;
    struct ether_arp *arp_packet;
    struct ifreq ifr;
    char buf[ETHER_ARP_PACKET_LEN];
    unsigned char src_mac_addr[ETH_ALEN];
    unsigned char dst_mac_addr[ETH_ALEN] = BROADCAST_ADDR;

    int sock_raw_fd, ret_len, i;

    if ((sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
    {
        cerr << "Error creating socket." << endl;
    }
    // cout << "Socket created: " << sock_raw_fd << endl;
    bzero(&saddr_ll, sizeof(struct sockaddr_ll));
    bzero(&ifr, sizeof(struct ifreq));
    memcpy(ifr.ifr_name, if_name, strlen(if_name));
    cout << "Interface name: " << if_name << endl;
    // ifindex
    if (ioctl(sock_raw_fd, SIOCGIFINDEX, &ifr) < 0) {
        cerr << "Error getting index." << endl;
    }
    saddr_ll.sll_ifindex = ifr.ifr_ifindex;
    saddr_ll.sll_family = PF_PACKET;
    cout << "Interface index: " << ifr.ifr_ifindex << endl;
    // local ip
    if (ioctl(sock_raw_fd, SIOCGIFADDR, &ifr) < 0) 
        cerr << "Error getting src ip." << endl;
    char *src_ip = inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
    cout << "local IP: " << src_ip << endl;

    // local mac
    if (ioctl(sock_raw_fd, SIOCGIFHWADDR, &ifr) < 0) {
        cerr << "Error getting MAC address." << endl;
    }
    memcpy(src_mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    cout << "local MAC: ";
    for (int i = 0; i < 6; i++) {
        cout << hex << setw(2) << setfill('0') << (int)src_mac_addr[i];
        if (i < 5) 
            cout << ":";
    }
    cout << endl;

    for (int i = 1; i < 255; i++) {
        string dst_ip = string(base_ip) + "." + to_string(i);
        // cout << "IP: " << dst_ip << endl;
        bzero(buf, ETHER_ARP_PACKET_LEN);
        // ethheader
        eth_header = (struct ether_header *)buf;
        memcpy(eth_header->ether_shost, src_mac_addr, ETH_ALEN);
        memcpy(eth_header->ether_dhost, dst_mac_addr, ETH_ALEN);
        eth_header->ether_type = htons(ETHERTYPE_ARP);
        // arp packet
        arp_packet = fill_arp_packet(src_mac_addr, src_ip, dst_ip.c_str());
        memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);

        // sendto
        ret_len = sendto(sock_raw_fd, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
        if ( ret_len < 0) {
            cerr << "Error sending packet." << endl;
        }
                
        // receive
        unsigned char buffer[ETHER_ARP_PACKET_LEN];
        ssize_t length = recvfrom(sock_raw_fd, buffer, ETHER_ARP_PACKET_LEN, 0, NULL, NULL);
        if (length == -1) {
            cerr << "Error receiving packet." << endl;
        } else {
            // 解析 ARP 回覆
            struct ether_arp *arp_resp = (struct ether_arp *)(buffer + ETHER_HEADER_LEN);
            if (ntohs(arp_resp->arp_op) == ARPOP_REPLY) {
                struct in_addr sender_ip;
                memcpy(&sender_ip, arp_resp->arp_spa, IP_ADDR_LEN);
                char sender_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sender_ip, sender_ip_str, INET_ADDRSTRLEN);

                struct ether_addr sender_mac;
                memcpy(&sender_mac, arp_resp->arp_sha, ETH_ALEN);
                char sender_mac_str[18];
                ether_ntoa_r(&sender_mac, sender_mac_str);

                // 將 IP 和 MAC 加入 devices 地圖
                devices[sender_ip_str] = sender_mac_str;

                cout << "ARP Reply Received: ";
                cout << "Sender IP: " << sender_ip_str << ", Sender MAC: " << sender_mac_str << endl;
            }
        }

    }
    // read the response
    //


    close(sock_raw_fd);

}


void get_devices(string interface, string gateway_ip, string source_ip, map<string, string>& devices) {
    // send ARP request to all devices in the network  
    // get the MAC address of the source IP address
    // struct ifreq ifr;
        
    string base_ip = gateway_ip.substr(0, gateway_ip.find_last_of("."));
    arp_request(interface.c_str(), base_ip.c_str());
    // bind the socket to the interface
    // int new_sockfd;
    // bind_socket(ifr.ifr_ifindex, &new_sockfd);

    // send to broadcast


}
void list_devices() {
    // list all devices' IP/MAC addresses in the Wi-Fi network(except the attacker and gateway)
    // get the interface name and gateway IP address
    string gateway_ip = exec("ip route | grep default | awk '{print $3}'");
    gateway_ip.erase(gateway_ip.end() - 1);
    string source_ip = exec("hostname -I");
    source_ip.erase(source_ip.end() - 1);
    string interface = exec("ip route | grep default | awk '{print $5}'");
    interface.erase(interface.end() - 1);
    // cout << "Gateway IP: " << gateway_ip << endl;
    // cout << "Interface: " << interface << endl;
    // uint32_t gateway_ip_int = inet_addr(gateway_ip.c_str());
    // uint32_t source_ip_int = inet_addr(source_ip.c_str());
    cout << "Available devices:\n";
    cout << "---------------------------------------\n";
    cout << "IP\t\tMAC\n";
    cout << "---------------------------------------\n";

    get_devices(interface, gateway_ip ,source_ip, devices);

}

int main() {
    // task 1
    list_devices();



    return 0;
}
