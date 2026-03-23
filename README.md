# RustScan Clone - Fast Port Scanner in C

## Features
- Fast multi-threaded port scanning
- Colored output with service detection
- Save results to file (-o option)
- Nmap integration (-n option)
- CIDR and domain support

## Compilation
gcc -O3 -pthread -o rustscan rustscan_final.c

## Usage
./rustscan -a 192.168.1.1 -p 80,443,22 -o results.txt
./rustscan -a 192.168.1.0/24 -p 1-1000 -n

## License
GPL-3.0
