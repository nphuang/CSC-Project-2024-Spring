#include <iostream>
#include <iomanip>
#include <map>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

using namespace std;

map<string, string> possible_victims;

void list_devices() {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in sin;
    char mac[18];

    // Create socket
    sockfd = socket(AF_INET, SOCK_RAW, htons(0x0806));
    if(sockfd < 0) {
        cerr << "Error: Unable to create socket" << endl;
        exit(1);
    }

    // Get list of network interfaces
    struct ifconf ifc;
    char buffer[1024];
    ifc.ifc_buf = buffer;
    ifc.ifc_len = sizeof(buffer);
    if(ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
        cerr << "Error: Unable to get network interfaces" << endl;
        close(sockfd);
        exit(1);
    }

    // Iterate over each network interface
    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);

        // Get interface flags
        if(ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
            cerr << "Error: Unable to get interface flags" << endl;
            continue;
        }

        // Skip interfaces that are not up or loopback
        if(!(ifr.ifr_flags & IFF_UP) || (ifr.ifr_flags & IFF_LOOPBACK)) {
            continue;
        }

        // Get interface address
        if(ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
            cerr << "Error: Unable to get interface address" << endl;
            continue;
        }

        // Convert IP address to string format
        sin = *(struct sockaddr_in*)&ifr.ifr_addr;
        char* interface_ip = inet_ntoa(sin.sin_addr);

        // Get interface CIDR
        if(ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
            cerr << "Error: Unable to get interface netmask" << endl;
            continue;
        }

        // Convert netmask to string format
        sin = *(struct sockaddr_in*)&ifr.ifr_addr;
        char* netmask = inet_ntoa(sin.sin_addr);

        // Generate CIDR format
        string cidr = string(interface_ip) + "/" + to_string(__builtin_popcount(*(uint32_t*)&sin.sin_addr.s_addr));

        // ARP ping to discover hosts on the local ethernet network
        // Implement this part according to your previous method

        cout << "Interface: " << ifr.ifr_name << ", CIDR: " << cidr << endl;
    }

    close(sockfd);
}

int main() {
    list_devices();
    return 0;
}
