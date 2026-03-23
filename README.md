# 🔍 RustScan Clone - Fast Port Scanner in C

[![License](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)

> Fast port scanner written in C with colored output and Nmap integration.

## Features

- ⚡ Fast - Scan 65,535 ports in seconds
- 🎨 Colored Output
- 📁 Save Results (-o)
- 🔗 Nmap Integration (-n)
- 🌐 CIDR Support

## Compilation

gcc -O3 -pthread -o rustscan rustscan_final.c

## Usage

./rustscan -a 192.168.1.1 -p 80,443,22 -o results.txt
./rustscan -a 192.168.1.0/24 -p 1-1000 -n

## License

GPL-3.0
