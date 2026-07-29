# NetSight [WIP]

![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Status](https://img.shields.io/badge/Status-Under%20Development-orange.svg)

> **Project Status: Work in Progress**  
> NetSight is currently under active development. The core architecture is being built.

**NetSight** ist ein ressourcenschonender, multithreaded Netzwerk-Traffic-Analysator, der in C++17 geschrieben wurde.

## Geplante Funktionen (Planned Features)
* Traffic-Erfassung auf Betriebssystemebene (`libpcap` / `Npcap`)
* Multithread-Architektur (Producer-Consumer)
* Low-Level-Parsing von Netzwerk-Headern (L2–L4) mittels *Zero-Copy*
* Erkennung von SYN-Flood-Angriffen und Port-Scans in Echtzeit
* REST-API zum Abrufen von Statistiken

##  Stack
* **C++17**
* **CMake**
* **libpcap / Npcap**
