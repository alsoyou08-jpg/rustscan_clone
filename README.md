# rustscan_clone
# RustScan Clone - Fast Port Scanner in C

[![License](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)
[![C](https://img.shields.io/badge/C-99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

## 🚀 Features

- ⚡ **Fast** - Scan ports in seconds with multi-threading
- 🎨 **Colored output** - Easy to read, color-coded results
- 📁 **Save results** - Export to file with `-o` option
- 🔗 **Nmap integration** - Auto-pipe results to Nmap for deep scanning
- 🌐 **CIDR support** - Scan whole networks (e.g., 192.168.1.0/24)
- 🔧 **Multi-threaded** - Configurable threads for speed
- 📝 **Service detection** - Identifies common services (HTTP, SSH, DNS, etc.)

## 📦 Installation
=========================================================
```bash
git clone https://github.com/alsoyou08-jpg/rustscan_clone.git
cd rustscan_clone
gcc -O3 -pthread -o rustscan rustscan_final.c
sudo cp rustscan /usr/local/bin/  # optional
=============================================
📊 Options
Option	Description
-a	Target IP, CIDR, or domain (required)
-p	Port range/comma list (e.g., 1-1000, 80,443)
-t	Timeout in milliseconds (default: 1000)
-T	Number of threads (default: 500, max: 2000)
-b	Batch size (default: 1000)
-o	Save results to file
-n	Pipe results to Nmap
-s	Run custom script after scan
-v	Verbose output
-h	Show help
=========================================
# Basic scan of common ports
./rustscan -a 192.168.1.1 -p 80,443,22,53

# Full range scan with output file
./rustscan -a 192.168.1.1 -p 1-1000 -o results.txt

# Scan entire network with Nmap integration
./rustscan -a 192.168.1.0/24 -p 80,443,22,53 -n

# Fast scan with custom timeout and threads
./rustscan -a google.com -p 1-10000 -t 500 -T 1000
=========================================
📈 Performance
Target	Ports	Time
localhost	1000	0.07s
192.168.1.1	1000	2.06s
google.com	1000	2.11s
Network /24	100	~15s
=======================
