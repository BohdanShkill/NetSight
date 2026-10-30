# NetSight

<p align="center">
<strong>A lightweight, multithreaded network packet analyzer and anomaly detector written in C++17.</strong>
</p>

<p align="center">
<a href="https://github.com/BohdanShkill/NetSight/actions/workflows/ci.yml"><img src="https://github.com/BohdanShkill/NetSight/actions/workflows/ci.yml/badge.svg" alt="NetSight CI"></a>
<img src="https://img.shields.io/badge/C%2B%2B-17-blue.svg?logo=c%2B%2B" alt="C++17">
<img src="https://img.shields.io/badge/CMake-3.20%2B-064F8C.svg?logo=cmake" alt="CMake 3.20+">
<img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg" alt="Platform: Linux | Windows">
<a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
</p>

---

> [!NOTE]
> **Project Status: Under Active Development**
> Core architectural abstractions, cross-platform build system, and automated CI pipelines are implemented. Packet capture engines and UB-free zero-copy header parsers are currently in progress.

---

## Overview

**NetSight** can replay live network traffic from OS-level interfaces, or can replay .pcap files, passes packets through a bounded thread-safe queue to worker threads, does live detection of network anomalies (SYN-flood attacks and port scans) in a sliding time window, and provides real-time statistics through an embedded REST API and CSV exporter.

### Key Engineering Decisions

* **Single Copy at Boundary:** All incoming packets are copied from driver buffers into contiguous (RawPacket) storage, and all protocol parsing is then done via non-owning memory views.
* **UB-Free Byte-Level Parsing:** Network headers are read using endian-agnostic bounds-checked readers instead of using unsafe reinterpret_cast casts with #pragma pack structs, which avoids unaligned memory accesses from crashing on non-x86 platforms.
* **Stable Packet Processing:** Packet processing will be done using a bounded queue with drop-newest backpressure to ensure packet processing stability under volumetric DDoS conditions.
* **Clean Layering:** Split into netsight_core (standard C++17 with no third party capture dependency) and netsight_capture (thin native OS wrapper for libpcap/Npcap).

---

## Quick Start

### Prerequisites

* **C++ Compiler:** GCC 9+, Clang 10+, or MSVC 2019+ (C++17 support required)
* **Build System:** CMake 3.20+
* **Packet Capture Library:**
* **Linux:** `sudo apt install libpcap-dev`
* **Windows:** [Npcap SDK](https://npcap.com/#download) (set `-DNPCAP_SDK_DIR=C:/path/to/sdk` if installed in a custom directory)

Third-party C++ libraries (**GoogleTest**, **nlohmann/json**, **cpp-httplib**) are fetched automatically during CMake configuration via `FetchContent`.

### Live Packet Capture Permissions

You need an OS raw socket for capturing live network traffic:

For Linux systems: Execute as `sudo`... or give the executable non-root privileges...
```bash
sudo setcap cap_net_raw,cap_net_admin=eip <path-to-binary>
```
To run privileged live integration tests:
```bash
sudo env NETSIGHT_REQUIRE_LIVE=1 ctest --test-dir build -C Debug -L integration --output-on-failure
```
Windows: Needs driver [Npcap](https://npcap.com/) to be installed. If Npcap has been installed with the option of "Restrict driver access to Administrators only" then run the executable or tests from an Administrator console. Binaries are still able to run safely (in offline .pcap analysis; via MSVC delay-load) when Npcap is not present.

### Building from Source

```bash
# 1. Clone repository
git clone https://github.com/BohdanShkill/NetSight.git
cd NetSight

# 2. Configure build directory
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug

# 3. Compile targets
cmake --build build --config Debug
```

### Running Tests

All unit and integration tests are managed via CTest and isolated from OS driver requirements:

```bash
ctest --test-dir build --output-on-failure -C Debug
```

---

## License

This project is open-source software licensed under the [MIT License](LICENSE).