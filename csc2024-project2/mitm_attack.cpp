#include <iostream>
#include <iomanip>
#include <map>
#include <cstring>
#include <cstdlib>
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
struct arp_packet {
    struct ethhdr eth;
    struct arp_header arp;
};


map<string, string> devices;

int bind_socket(const char* interface) {
    // create socket
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        cerr << "Error creating socket." << endl;
        return -1;
    }

    // bind socket to interface
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    cout<<"Interface: "<<interface<<endl;
    cout<<"Interface index: "<<if_nametoindex(interface)<<endl;
    socket_address.sll_ifindex = if_nametoindex(interface);
    cout << "Interface index: " << socket_address.sll_ifindex << endl;
    if (bind(sockfd, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        cerr << "Error binding socket to interface." << endl;
        return -1;
    }

    return sockfd;
}

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
void list_devices() {
    // list all devices' IP/MAC addresses in the Wi-Fi network(except the attacker and gateway)
    // get the interface name and gateway IP address
    string gateway_ip = exec("ip route | grep default | awk '{print $3}'").c_str();
    string interface = exec("ip route | grep default | awk '{print $5}'").c_str();
    cout << "Gateway IP: " << gateway_ip << endl;
    cout << "Interface: " << interface << endl;
    uint32_t gateway_ip_int = inet_addr(gateway_ip.c_str());
    // cout<<"Gateway IP int: "<<gateway_ip_int<<endl;
    // uint32_t local;
    // int ifindex;
        
    if (bind_socket(interface.c_str()) < 0) {
        cerr << "Error binding socket to interface." << endl;
        return;
    }

    // // create socket
    // int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    // if (sockfd < 0) {
    //     cerr << "Error creating socket." << endl;
    //     return;
    // }

    // // construct ARP request packet
    // arp_packet packet;
    // memset(&packet, 0, sizeof(arp_packet));

    // // set Ethernet header
    // packet.eth.h_proto = htons(ETH_P_ARP);

    // // set ARP header
    // packet.arp.htype = htons(ARPHRD_ETHER);
    // packet.arp.ptype = htons(ETH_P_IP);
    // packet.arp.hlen = 6;
    // packet.arp.plen = 4;
    // packet.arp.opcode = htons(ARPOP_REQUEST);

    // // get source MAC address
    // struct ifreq ifr;
    // strcpy(ifr.ifr_name, interface.c_str());
    // ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    // memcpy(packet.eth.h_source, ifr.ifr_hwaddr.sa_data, 6);
    // cout << "Attacker MAC Address: " << ether_ntoa((struct ether_addr*)packet.eth.h_source) << endl;
    
    // // get source IP address
    // ioctl(sockfd, SIOCGIFADDR, &ifr);
    // struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
    // memcpy(packet.arp.sender_ip, &sin->sin_addr, 4);
    // cout << "Attacker IP Address: " << inet_ntoa(sin->sin_addr) << endl;

    // // set destination MAC address to broadcast
    // memset(packet.eth.h_dest, 0xff, 6);

    // set target IP address
    // uint8_t target_ip[4] = {192, 168, 1, 1};
    // memcpy(packet.arp.target_ip, target_ip, 4);

    // // send ARP request packet
    // struct sockaddr_ll socket_address;
    // memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    // socket_address.sll_ifindex = if_nametoindex(interface.c_str());
    // socket_address.sll_family = AF_PACKET;
    // socket_address.sll_protocol = htons(ETH_P_ARP);
    // sendto(sockfd, &packet, sizeof(arp_packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));

    // // receive ARP response packet
    // arp_packet recv_packet;
    // ssize_t recv_len = recv(sockfd, &recv_packet, sizeof(recv_packet), 0);
    // if (recv_len < 0) {
    //     cerr << "Error receiving ARP response." << endl;
    //     return;
    // }

    // // parse ARP response packet
    // uint8_t* mac = recv_packet.arp.sender_mac;
    // uint8_t* ip = recv_packet.arp.sender_ip;
    // char mac_str[18];
    // sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    // char ip_str[16];
    // sprintf(ip_str, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    // devices[ip_str] = mac_str;

    // // display device information
    // cout << "IP Address: " << ip_str << ", MAC Address: " << mac_str << endl;

    // close(sockfd);
}

int main() {
    // task 1
    list_devices();



    return 0;
}
