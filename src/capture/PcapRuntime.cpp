#include "netsight/capture/PcapRuntime.hpp"

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

}