# CodeAlpha_PKT-SNIFF
# sniff.py - Packet Sniffer

`sniff.py` is a Python script that enables network packet sniffing using the Scapy library. It captures and analyzes network traffic by inspecting Ethernet, IP, and transport-layer protocols. The output displays essential details such as source/destination IP, MAC addresses, protocol type, and port numbers for TCP/UDP packets.

## Features
- Network interface packet sniffing with user-defined interface.
- Supports filtering traffic with custom filter expressions.
- Displays packet details such as:
  - Source and destination IP and MAC addresses.
  - Protocol type (TCP, UDP, or others).
  - Source and destination ports for TCP/UDP packets.
  - Flags for TCP packets (if applicable).
- Colorful and dynamic terminal output with real-time packet updates.

## Requirements
Before running the script, ensure that the following libraries are installed:

- `pyfiglet` (for ASCII art text)
- `termcolor` (for colored terminal output)
- `scapy` (for network packet manipulation)

You can install the required dependencies using `pip`:

```bash
pip install pyfiglet termcolor scapy
```
# Usage:
```bash
./sniff.py -i <interface> -f "<filter>"
```
## Arguments:
```text
 -i, --interface (required): The network interface to sniff on (e.g., eth0, wlan0, etc.).
 -f, --filter (optional): A BPF (Berkeley Packet Filter) expression to filter the packets (e.g., tcp, udp, port 80, etc.).
```
