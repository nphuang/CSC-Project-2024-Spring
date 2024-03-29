#include "session.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <span>
#include <utility>
extern bool running;

uint16_t checksum(const uint16_t* buffer, size_t size) {
  uint32_t sum = 0;
  while (size > 1) {
    sum += *buffer++;
    size -= 2;
  }
  if (size > 0) {
    sum += *reinterpret_cast<const uint8_t*>(buffer);
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  // sum = (sum >> 16) + (sum & 0xFFFF);
  // sum += (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

uint16_t tcp_checksum(const iphdr* iph, const tcphdr* tcph, const std::string& payload) {
  uint32_t sum = 0;

  auto buffer = reinterpret_cast<const uint16_t*>(iph);
  // summing the IP header
  for (int i = 2; i < 6; i++) {
      sum += ntohs(buffer[i]);
  }
  
  sum += IPPROTO_TCP; // Add IPPROTO_TCP
  sum += sizeof(tcphdr) + payload.size(); 
  buffer = reinterpret_cast<const uint16_t*>(tcph);
  // summung the tcp header
  for (int i = 0; i < 10; i++) {
      sum += ntohs(buffer[i]);
  }

  buffer = reinterpret_cast<const uint16_t*>(payload.data());
  int len;
  if((payload.size() & 1)) {
    len = payload.size() / 2 + 1;
  }
  else {
    len = payload.size() / 2;
  }

  for (int i = 0; i < len; i++) {
    sum += ntohs(buffer[i]);
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return htons(~sum);
  
}

Session::Session(const std::string& iface, ESPConfig&& cfg)
    // Fill struct sockaddr_ll addr which will be used to bind the socket
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  addr_ll.sll_family = AF_PACKET;
  addr_ll.sll_protocol = htons(ETH_P_ALL);
  addr_ll.sll_ifindex = if_nametoindex(iface.c_str());
  if (addr_ll.sll_ifindex == 0) {
    throw std::runtime_error("Failed to get interface index");
  }
  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
  std::cout << "Socket created and bound to interface " << iface << " (index "
            << addr_ll.sll_ifindex << ")\n";
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}

void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  std::string secret;
  std::cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        std::getline(std::cin, secret);
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) {
          // std::cout << "Sending ACK\n";  // debug
          encapsulate("");
        }
        if (!secret.empty() && state.recvPacket) {
        std:
          // std::cout << "Sending secret\n";  // debug
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  dissectIPv4(payload);
}

void Session::dissectIPv4(std::span<uint8_t> buffer) {
  // Extract IPv4 header and payload, and check if receiving packet from remote
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO:
  // Set `recvPacket = true` if we are receiving packet from remote
  state.recvPacket = false;
  if (hdr.saddr == inet_addr(config.remote.c_str())) state.recvPacket = true;
  // Track current IP id
  if(state.recvPacket == false){
    // state.ipId++
    state.ipId = hdr.id;
    state.ipId += htons(1);  
  }
  // Call dissectESP(payload) if next protocol is ESP
  //   auto payload = buffer.last(buffer.size() - headerLength);

  auto headerLength = hdr.ihl * 4;
  auto payload = buffer.last(buffer.size() - headerLength);
  if (hdr.protocol == IPPROTO_ESP) {
    // this part seems correct
    // std::cout << "ESP packet received\n";
    dissectESP(payload);
  }
  else if (hdr.protocol == IPPROTO_TCP) {
  //   std::cout << "TCP packet received\n";
  //   auto headerLength = hdr.ihl * 4;
  //   auto payload = buffer.last(buffer.size() - headerLength);
    dissectTCP(payload);
  }
}

void Session::dissectESP(std::span<uint8_t> buffer) {
  // Extract ESP header and payload, and track ESP sequence number
  // std::cout << "Dissecting ESP\n";
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  int hashLength = config.aalg->hashLength();
  
  // std::cout<<"Hash length: "<<hashLength<<std::endl; // 12
  // Strip hash

  // payload + esp_trailer
  buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength);
  std::vector<uint8_t> data;
  // Decrypt payload
  if (!config.ealg->empty()) {
    // std::cout << "Decrypting ESP packet\n";
    data = config.ealg->decrypt(buffer);
    buffer = std::span{data.data(), data.size()};
  }
  // ?
  int paddingLength = buffer.data()[buffer.size() - sizeof(ESPTrailer)];
  // std::cout << "Padding length: " << paddingLength << std::endl;
  int payloadLength = buffer.size() - paddingLength - sizeof(ESPTrailer);
  buffer = buffer.first(payloadLength);
  //
  // TODO:
  // Track ESP sequence number
  if (state.recvPacket == false) 
    state.espseq = ntohl(hdr.seq)+1;
  // std::cout<<"ESP sequence number: "<<state.espseq<<std::endl;
  // Call dissectTCP(payload) if next protocol is TCP
  // std::cout << "buffer size" << buffer.size() << std::endl;
  dissectTCP(buffer);
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  // Extract TCP header, and track TCP header parameters
  // std::cout << "Dissecting TCP\n";
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);
  // Track tcp parameters
  state.tcpseq = hdr.seq;
  state.tcpackseq = hdr.ack_seq;
  state.srcPort = hdr.source;
  // std::cout << "Source port: " << state.srcPort << std::endl;
  state.dstPort = hdr.dest;
  // std::cout << "Destination port: " << state.dstPort << std::endl;

  // Is ACK message?
  if (payload.empty()) return;
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
  }
}

void Session::encapsulate(const std::string& payload) {
  // std::cout << "Encapsulat Start\n";
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  // std::cout << "Encapsulating IPv4 packet\n";
  // Fill IPv4 header, and compute the checksum
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO: Fill IP header
  hdr.version = 4;
  hdr.ihl = 5;
  hdr.ttl = 64;
  hdr.id = state.ipId;
  hdr.protocol = IPPROTO_ESP;
  hdr.frag_off = htons(0);
  hdr.saddr = inet_addr(config.local.c_str());
  hdr.daddr = inet_addr(config.remote.c_str());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);

  hdr.tot_len = htons(payloadLength);
  // Compute checksum
  hdr.check = checksum(reinterpret_cast<uint16_t*>(buffer.data()), sizeof(iphdr));
  // std::cout << "IPv4Checksum: " << std::hex << hdr.check << std::endl;
  return payloadLength;
}


int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  // std::cout << "Encapsulating ESP packet" << std::endl;
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto hashbuf = buffer;
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  // TODO: Fill ESP header
  hdr.spi = config.spi;
  hdr.seq = htonl(state.espseq++);
  //state.espseq++;
  int payloadLength = encapsulateTCP(nextBuffer, payload);

  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);
  // TODO: Calculate padding size and do padding in `endBuffer`
  uint8_t padSize = (payloadLength + sizeof(ESPTrailer)) % 8 ? 8 - (payloadLength + sizeof(ESPTrailer)) % 8 : 0;
  //std::cout << "Padding size: " << (int)padSize << std::endl;
  payloadLength += padSize;
  for(int i = 0; i < padSize; i++)
    memset(&endBuffer[i], (uint8_t)(i+1), 1);

  // ESP trailer
  endBuffer[padSize] = padSize;
  endBuffer[padSize + 1] = IPPROTO_TCP;
  payloadLength += sizeof(ESPTrailer);
  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }
  payloadLength += sizeof(ESPHeader);
   
  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    auto result = config.aalg->hash(buffer.first(payloadLength));
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }

  return payloadLength;
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  // std::cout << "Encapsulating TCP\n";
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()) hdr.psh = 1;
  // TODO: Fill TCP header
  hdr.ack = 1;
  hdr.doff = 5;
  hdr.dest = state.srcPort;
  hdr.source = state.dstPort;
  hdr.ack_seq = state.tcpseq;
  hdr.seq = state.tcpackseq;
  hdr.window = htons(502);
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }
  // TODO: Update TCP sequence number
  state.tcpseq = hdr.seq;
  payloadLength += sizeof(tcphdr);
  iphdr* iph = reinterpret_cast<iphdr*>(buffer.data() - sizeof(iphdr));
  tcphdr* tcph = reinterpret_cast<tcphdr*>(buffer.data());
  // TODO: Compute checksum
  hdr.check =  tcp_checksum(iph, tcph, payload);

  return payloadLength;
}
