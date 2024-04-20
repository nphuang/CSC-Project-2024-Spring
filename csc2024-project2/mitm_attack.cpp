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
int send_arp (int sockfd, uint32_t source_ip, uint32_t target_ip, uint8_t* source_mac) {
    struct arp_packet packet;
    memset(&packet, 0, sizeof(packet));
    // fill the Ethernet header
    memset(&packet.eth.h_dest, 0xff, 6); // destination MAC address
    memcpy(&packet.eth.h_source, source_mac, 6); // source MAC address
    packet.eth.h_proto = htons(ETH_P_ARP); // protocol type
    // fill the ARP header
    packet.arp.htype = htons(ARPHRD_ETHER); // hardware type
    packet.arp.ptype = htons(ETH_P_IP); // protocol type
    packet.arp.hlen = 6; // hardware address length
    packet.arp.plen = 4; // protocol address length
    packet.arp.opcode = htons(ARPOP_REQUEST); // ARP operation

    memcpy(&packet.arp.sender_mac, source_mac, 6); // sender MAC address
    memcpy(&packet.arp.sender_ip, &source_ip, 4); // sender IP address
    // memcpy(&packet.arp.target_mac, target_mac, 6); // target MAC address
    memcpy(&packet.arp.target_ip, &target_ip, 4); // target IP address
    // send the ARP packet
    if (send(sockfd, &packet, sizeof(packet), 0) < 0) {
        cerr << "Error sending ARP packet." << endl;
        return -1;
    }
    return 0;
}
void bind_socket(int index, int* sockfd) {
    // create socket
    *sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    cout << "Socket: " << *sockfd << endl;
    if (*sockfd < 0) {
        cerr << "Error creating socket." << endl;
        // return -1; // Remove this line
    }

    // bind socket to interface
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_family = AF_PACKET;
    // socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = index;
    // cout << "Interface index: " << socket_address.sll_ifindex << endl;
    if (bind(*sockfd, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        cerr << "Error binding socket to interface." << endl;
        // return -1; // Remove this line
    }
    // return 0; // Remove this line
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
void get_devices(string interface, uint32_t gateway_ip, uint32_t source_ip, map<string, string>& devices) {
    // grep the index of the interface
    string temp = exec(("ip addr show " + interface).c_str());
    int i;
    for (i = 0; i < temp.size(); i++) {
        if (temp[i] == ':') {
            break;
        }
    }
    int index = stoi(temp.substr(0, i));
    cout << "Interface index: " << index << endl;
    int arp_sockfd;
    bind_socket(index, &arp_sockfd);
    // send ARP request to all devices in the network  
    // get the MAC address of the source IP address
    struct ifreq ifr;
    strcpy(ifr.ifr_name, interface.c_str());
    if (ioctl(arp_sockfd, SIOCGIFINDEX, &ifr) < 0) {
        cerr << "Error getting index." << endl;
    }
    cout << "Interface index: " << ifr.ifr_ifindex << endl;
    if (ioctl(arp_sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        cerr << "Error getting MAC address." << endl;
    }
    unsigned char source_mac[6];
    memcpy(source_mac, ifr.ifr_hwaddr.sa_data, 6);
    cout << "Source MAC: ";
    for (int i = 0; i < 6; i++) {
        cout << hex << setw(2) << setfill('0') << (int)source_mac[i];
        if (i < 5) {
            cout << ":";
        }
    }

    // for (int i = 0; i < 6; i++) {
    //     cout << hex << setw(2) << setfill('0') << (int)source_mac[i];
    //     if (i < 5) {
    //         cout << ":";
    //     }
    // }
    // cout << endl;
    // send ARP request to all devices in the network
    // for (auto& device : devices) {
    //     uint32_t target_ip = inet_addr(device.first.c_str());
    //     send_arp(arp_sockfd, source_ip, target_ip, source_mac);
    // }


}
void list_devices() {
    // list all devices' IP/MAC addresses in the Wi-Fi network(except the attacker and gateway)
    // get the interface name and gateway IP address
    string gateway_ip = exec("ip route | grep default | awk '{print $3}'").c_str();
    string source_ip = exec("hostname -I").c_str();
    string interface = exec("ip route | grep default | awk '{print $5}'").c_str();
    cout << "Gateway IP: " << gateway_ip;
    cout << "Interface: " << interface;
    uint32_t gateway_ip_int = inet_addr(gateway_ip.c_str());
    uint32_t source_ip_int = inet_addr(source_ip.c_str());
    get_devices(interface, gateway_ip_int ,source_ip_int, devices);

}

int main() {
    // task 1
    list_devices();



    return 0;
}
