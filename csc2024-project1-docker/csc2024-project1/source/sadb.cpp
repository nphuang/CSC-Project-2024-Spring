#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>

std::optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  std::vector<uint8_t> message(65536);
  sadb_msg msg{};
  // Fill sadb_msg
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type = SADB_DUMP;
  msg.sadb_msg_satype = SADB_SATYPE_ESP;
  msg.sadb_msg_len = sizeof(sadb_msg) / sizeof(uint64_t);
  msg.sadb_msg_pid = getpid();

  // Create a PF_KEY_V2 socket and write msg to it
  int sock = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
  if (sock < 0) {
    std::cerr << "Failed to create PF_KEY_V2 socket." << std::endl;
    return std::nullopt;
  }
  // write msg to socket
  if (write(sock, &msg, sizeof(sadb_msg)) < 0) {
    std::cerr << "Failed to write to PF_KEY_V2 socket." << std::endl;
    return std::nullopt;
  }
  // Then read from socket to get SADB information
  uint8_t *key_data;
  sadb_key *key;
  // Read from socket
  int bytesRead = read(sock, message.data(), message.size());
  sadb_msg *sadb = (sadb_msg *)message.data();
  sadb_ext *ext = (sadb_ext *)(sadb + 1);
  sadb_sa *sa;
  uint32_t src, dst;
  bytesRead = read(sock, message.data(), message.size());
  // Parse SADB message
  sadb = (sadb_msg *)message.data();
  ext = (sadb_ext *)(sadb + 1);
  bytesRead -= sizeof(sadb_msg);
  while (bytesRead > 0) {
    // std::cout << "ext type: " << ext->sadb_ext_type << std::endl;
    if (ext->sadb_ext_type == SADB_EXT_SA) {
      sa = (sadb_sa *)ext;
    } else if (ext->sadb_ext_type == SADB_EXT_ADDRESS_SRC
               || ext->sadb_ext_type == SADB_EXT_ADDRESS_DST) {
      sadb_address *addr = reinterpret_cast<sadb_address *>(ext);
      // Assuming sockaddr_in is the correct type
      sockaddr_in *sockaddr = reinterpret_cast<sockaddr_in *>(addr + 1);
      uint32_t ip = sockaddr->sin_addr.s_addr;
      if (ext->sadb_ext_type == SADB_EXT_ADDRESS_SRC) {
        src = ip;
        std::cout << "src addr: " << ipToString(src) << std::endl;
      } else {
        dst = ip;
        std::cout << "dst addr: " << ipToString(dst) << std::endl;
      }
    } else if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH) {
      key = reinterpret_cast<sadb_key *>(ext);
      key_data = reinterpret_cast<uint8_t *>(key + 1);
      uint16_t key_len;
      memcpy(&key_len, &(key->sadb_key_len), sizeof(key_len));
    }
    bytesRead -= ext->sadb_ext_len << 3;
    ext = reinterpret_cast<sadb_ext *>(reinterpret_cast<char *>(ext) + (ext->sadb_ext_len << 3));
  }

  close(sock);
  // Set size to number of bytes in response message
  int size = bytesRead;

  // Has SADB entry
  if (size != sizeof(sadb_msg)) {
    // Parse SADB message
    ESPConfig config;
    config.spi = sa->sadb_sa_spi;
    config.aalg = std::make_unique<ESP_AALG>(sa->sadb_sa_auth,
                                             std::span<uint8_t>(key_data, key->sadb_key_bits / 8));
    if (sa->sadb_sa_encrypt != SADB_EALG_NONE) {
      config.ealg = std::make_unique<ESP_EALG>(
          sa->sadb_sa_encrypt, std::span<uint8_t>(key_data, key->sadb_key_bits / 8));
    } else {
      config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
    }
    config.local = ipToString(src);
    config.remote = ipToString(dst);
    return config;
  }
  std::cerr << "SADB entry not found." << std::endl;
  return std::nullopt;
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "------------------------------------------------------------";
  return os;
}
