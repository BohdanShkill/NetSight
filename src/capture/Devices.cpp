#include "netsight/capture/Devices.hpp"

#include <pcap.h>
#include <memory>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

namespace netsight {
    std::vector<NetworkInterface> list_interfaces(std::string& error_out) {
        error_out.clear();
        std::vector<NetworkInterface> result;
        
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t* alldevs = nullptr;

        if (pcap_findalldevs(&alldevs, errbuf) != 0) {
            error_out = errbuf;
            return{};
        }
        
        std::unique_ptr<pcap_if_t, decltype(&pcap_freealldevs)> dev_guard(alldevs, pcap_freealldevs);
        
        for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
            NetworkInterface iface;
            iface.name = dev->name ? dev->name : "";
            iface.description = dev->description ? dev->description : "";
            iface.is_loopback = (dev->flags & PCAP_IF_LOOPBACK) != 0;
        #ifdef PCAP_IF_UP
            iface.is_up = (dev->flags & PCAP_IF_UP) != 0;
        #endif
            
            for (pcap_addr_t* a = dev->addresses; a != nullptr; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    auto* sa = reinterpret_cast<struct sockaddr_in*>(a->addr);
                    char ip_str[INET_ADDRSTRLEN];
                    if(inet_ntop(AF_INET, &(sa->sin_addr), ip_str, sizeof(ip_str))) {
                        iface.ipv4_address = ip_str;
                        break;
                    }
                }
            }
            result.push_back(std::move(iface));
        }
        return result;
    }
}
