#include "netsight/capture/PcapRuntime.hpp"

#include <pcap.h>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#include <mutex>
#endif

namespace netsight {

bool ensure_pcap_loaded(std::string& error) {
#ifndef _WIN32
    (void)error;
    return true;
#else
    static std::once_flag flag;
    static bool cached_ok = false;
    static std::string cached_err;

    std::call_once(flag, []() {
        wchar_t sysdir[MAX_PATH];
        UINT len = GetSystemDirectoryW(sysdir, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) {
            cached_ok = false;
            cached_err = "failed to get Windows system directory";
            return;
        }
        std::wstring npcap_dir = std::wstring(sysdir) + L"\\Npcap";
        SetDllDirectoryW(npcap_dir.c_str());
        HMODULE h = LoadLibraryW(L"wpcap.dll");
        if (!h) {
            cached_ok = false;
            cached_err = "Npcap is not installed (wpcap.dll not found). Install from https://npcap.com";
        } else {
            cached_ok = true;
        }
    });
    if (!cached_ok) {
        error = cached_err;
    }
    return cached_ok;
#endif
}

bool validate_bpf(
    const std::string& expr,
    LinkType link,
    std::uint32_t snaplen,
    std::string& error) 
{
    if (!ensure_pcap_loaded(error)) {
        return false;
    }
    if (expr.empty()) {
        return true;
    }
    if (link == LinkType::Unknown) {
        error = "cannot compile BPF for unknown link type";
        return false;
    }
    pcap_t* dead = pcap_open_dead(static_cast<int>(link), static_cast<int>(snaplen));
    if (!dead) {
        error = "failed to create dead pcap handle";
        return false;
    }
    std::unique_ptr<pcap_t, decltype(&pcap_close)> dead_guard(dead, pcap_close);
    struct bpf_program prog;
    if (pcap_compile(dead, &prog, expr.c_str(), 1 , PCAP_NETMASK_UNKNOWN) != 0) {
        error = "invalid BPF filter: " + std::string(pcap_geterr(dead));
        return false;
    }
    pcap_freecode(&prog);
    return true;
}

}