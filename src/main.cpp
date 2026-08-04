#include <iostream>
#include <pcap.h>

int main(){
    pcap_if_t* alldevs;
    char errbuff[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevs, errbuff) == -1){
        std::cerr << errbuff << std::endl;
        return 1;
    }
    for(pcap_if_t* d = alldevs; d != nullptr; d = d -> next){
        std::cout << d -> name << std::endl;
    }
    pcap_freealldevs(alldevs);
    std::cout << "NetSight v0.1 starting...\n";
    return 0;
}