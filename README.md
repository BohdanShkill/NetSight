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
> **Project Status: Under Active Development (Milestone 2)**  
> Core architectural abstractions, cross-platform build system, and automated CI pipelines are implemented. Packet capture engines and UB-free zero-copy header parsers are currently in progress.

---

## Overview

**NetSight** captures live network traffic directly from OS-level interfaces (or replays `.pcap` dumps), dispatches packets through a bounded thread-safe queue to worker threads, parses protocol headers (L2–L4), detects network anomalies (SYN-flood attacks and port scans) in a sliding time window, and exposes real-time statistics via an embedded REST API and CSV exporter.

### Key Engineering Decisions

* **Single Copy at Boundary, Zero-Allocation Parser:** Incoming packets are copied once from driver buffers into contiguous storage (`RawPacket`); all subsequent protocol parsing operates strictly via non-owning memory views.
* **UB-Free Byte-Level Parsing:** Network headers are decoded via bounds-checked endian-agnostic readers instead of dangerous `reinterpret_cast` casts over `#pragma pack` structs, preventing unaligned memory access crashes on non-x86 architectures.
* **Predictable Memory Footprint:** Packet processing uses a bounded queue with drop-newest backpressure to guarantee stability under volumetric DDoS conditions.
* **Clean Layering:** Decoupled into `netsight_core` (standard C++17, zero third-party capture dependencies) and `netsight_capture` (thin native OS wrapper for `libpcap`/`Npcap`).

---

## Quick Start

### Prerequisites

* **C++ Compiler:** GCC 9+, Clang 10+, or MSVC 2019+ (C++17 support required)
* **Build System:** CMake 3.20+
* **Packet Capture Library:**
  * **Linux:** `sudo apt install libpcap-dev`
  * **Windows:** [Npcap SDK](https://npcap.com/#download) (set `-DNPCAP_SDK_DIR=C:/path/to/sdk` if installed in a custom directory)

Third-party C++ libraries (**GoogleTest**, **nlohmann/json**, **cpp-httplib**) are fetched automatically during CMake configuration via `FetchContent`.

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
