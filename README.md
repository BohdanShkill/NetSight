# NetSight [WIP]

![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![CI](https://github.com/BohdanShkill/NetSight/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

> **Status:** Active development (Foundation & Architecture stage).

**NetSight** is a lightweight, multithreaded network traffic analyzer written in C++17.

## Features (Planned & In Progress)
* Live OS traffic capture (`libpcap` / `Npcap`) and offline `.pcap` file replay
* Multithreaded producer-consumer architecture with bounded queue backpressure
* Allocation-free parsing of L2–L4 headers (Ethernet, VLAN, IPv4/IPv6, TCP, UDP, ICMP)
* Real-time SYN flood and port scan anomaly detection
* Localhost REST API and CSV export for metrics and alerts

## Tech Stack
* **Language:** C++17
* **Build System:** CMake (≥ 3.20)
* **Dependencies:** libpcap / Npcap SDK, GoogleTest, nlohmann/json, cpp-httplib, CLI11

## Build & Test
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure