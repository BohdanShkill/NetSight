#include <iostream>
#include "netsight/capture/Devices.hpp"

#ifndef NETSIGHT_VERSION
#define NETSIGHT_VERSION "0.1.0"
#endif

int main(){
    std::string error_msg = "";
    const auto interfaces = netsight::list_interfaces(error_msg);

    std::cout << "NetSight v" << NETSIGHT_VERSION << " starting...\n";
    if (!error_msg.empty()) {
        std::cerr << "Error capture interfaces:" << error_msg << '\n';
        return 1;
    }

    if (interfaces.empty()) {
        std::cerr << "No network interfaces found.\n";
        return 1;
    }

    std::cout << "Interfaces found: " << interfaces.size() << '\n';

    for (std::size_t i = 0; i < interfaces.size(); ++i) {
        const auto& iface = interfaces[i];

        const std::string ip = iface.ipv4_address.empty() ? "-" : iface.ipv4_address;

        std::string flags;
        if (iface.is_loopback) {
            flags += "[loopback]";
        }
        if (!iface.is_up) {
            flags += "[down]";
        }
        if (flags.empty()) {
            flags = "[up]";
        }

        const std::string desc = iface.description.empty() ? "-" : iface.description;

        std::cout << "  ID:   " << i << '\n'
                  << "  Name: " << iface.name << '\n'
                  << "  IPv4: " << ip << '\n'
                  << "  Flag: " << flags << '\n'
                  << "  Description: " << desc << '\n';
    }
    
    return 0;
}