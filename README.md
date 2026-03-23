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

```bash
git clone https://github.com/alsoyou08-jpg/rustscan_clone.git
cd rustscan_clone
gcc -O3 -pthread -o rustscan rustscan_final.c
sudo cp rustscan /usr/local/bin/  # optional
