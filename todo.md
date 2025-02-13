# TODO

### Key:
- ✅ (implemented) 
- ❌ (currently working on)

## 1. Implement UDP Scanning ❌
- Modify scan_port() to support UDP. ✅
- Send a UDP packet to the target port. ✅
- Detect responses (ICMP unreachable = closed, no response = open/filtered).❌
- Allow user selection of TCP/UDP or both.✅


## 2. Add Banner Grabbing 
- After detecting an open TCP port, send a basic request (\n, OPTIONS, or HEAD).
- Read and display service banners if available.


## 3. Implement OS Fingerprinting
- Analyze TCP/IP stack behavior (e.g., TTL values, window size, and response patterns).
- Use a database of known OS signatures to compare.


## 4. Add Vulnerability Detection
- Cross-check open ports/services against a local CVE database or online API.
- Provide warnings if known vulnerabilities exist.



## 5. Introduce Scan Profiles
- Allow users to select predefined scanning modes:
- Quick Scan (Top 1000 ports)
- Full Scan (1–65535)
- Aggressive Scan (Fast + Service Detection)
- Stealth Scan (Low-detection methods)
- Implement a --profile flag for command-line use.


## 6. Implement Interactive Mode
Instead of requiring command-line arguments, guide the user through options dynamically.


## 7. Add Config File Support
- Allow users to specify settings in a configuration file (e.g., JSON, YAML).
- Load options dynamically instead of hardcoding values.



## 8. Implement Result Exporting
- Save scan results to a file (JSON, CSV, or HTML).
- Allow users to specify output format via a command-line flag.


## 9. Add Colored Output
- Use ANSI escape codes to colorize results:
- Green for open ports.
- Yellow for filtered ports.
- Red for errors.


## 10. Generate Scan Reports
- Summarize findings in a formatted report.
    - Include:
      - Open ports
      - Detected services
      - Possible vulnerabilities
      - Time taken

## 11. Implement Stealth Scanning (SYN Scan)
- Use raw sockets to send SYN packets.
- Analyze SYN-ACK (open) and RST (closed) responses.
- Avoid full TCP connections to reduce detection.


## 12. Add Randomized Scanning Order
- Shuffle the port list before scanning.
- Prevent detection by avoiding sequential scans.


## 13. Implement Proxy Support
- Route traffic through SOCKS5/Tor proxies for anonymity.


## 14. Introduce Adaptive Timeout
- Dynamically adjust timeouts based on network latency.
- Prevent excessive waiting for slow responses.


## 15. Convert to Asynchronous Scanning
- Replace ThreadPoolExecutor with asyncio.
- Use non-blocking sockets to improve efficiency.