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

void list_devices(const char* interface, const char* AP_ip, const char* cidr) {
}

int main() {
    // task 1: list all devices' IP/MAC addresses in the Wi-Fi network(except the attacker and gateway)
    // get the interface name and gateway IP address
    string gateway = exec("ip route | grep default | awk '{print $3}'").c_str();
    string interface = exec("ip route | grep default | awk '{print $5}'").c_str();
    string cidr = exec("ip route | grep default | awk '{print $1}'").c_str();
    cout << "Gateway IP: " << gateway << endl;
    cout << "Interface: " << interface << endl;
    cout << "CIDR: " << cidr << endl;
    return 0;
}
