# Network Blocking Detection Tool

A comprehensive tool for detecting various types of network restrictions and blocking mechanisms. This tool can identify multiple types of network interference including:
- DNS Pollution
- IP Blocking
- ICMP Blocking
- DPI (Deep Packet Inspection)
- TLS Fingerprinting
- SNI Blocking
- HTTP/HTTPS Blocking
- SSL Certificate Issues

## Features

- **Multi-DNS Server Check**: Tests against multiple public DNS servers to detect DNS pollution
- **Port Scanning**: Checks common ports (80, 443, 8080) for accessibility
- **HTTP/HTTPS Testing**: Tests multiple HTTP methods and protocols
- **SSL/TLS Analysis**: Verifies SSL certificates and TLS handshake
- **SNI Testing**: Detects SNI-based blocking
- **Concurrent Testing**: Uses thread pools for faster detection
- **Detailed Reporting**: Generates comprehensive JSON reports
- **Progress Tracking**: Shows real-time progress of each test
- **User-Agent Rotation**: Tests with different user agents to detect DPI

## Installation

1. First, install `just` command:
   - macOS: `brew install just`
   - Linux: Use your package manager
   - Windows: Use scoop or chocolatey

2. Install project dependencies:
   ```bash
   just install
   ```

## Usage

1. Run a test:
   ```bash
   just test example.com
   ```

2. View help:
   ```bash
   just help
   ```

## Detection Methods

The tool performs the following checks:

1. **DNS Pollution Detection**
   - Queries multiple DNS servers
   - Compares results for inconsistencies
   - Detects DNS redirection

2. **IP Blocking Detection**
   - Tests port accessibility
   - Measures connection latency
   - Identifies blocked ports

3. **HTTP/HTTPS Testing**
   - Tests multiple HTTP methods (GET, POST, HEAD)
   - Checks both HTTP and HTTPS
   - Measures response times

4. **SSL/TLS Analysis**
   - Verifies SSL certificate validity
   - Checks TLS handshake
   - Detects certificate issues

5. **SNI Testing**
   - Tests with and without SNI
   - Detects SNI-based blocking

## Output

The tool provides:
- Real-time progress updates
- Color-coded results
- Detailed JSON report
- Summary table of findings

## Requirements

- Python 3.7+
- Required Python packages (see requirements.txt)
- Network connectivity
- Root/Admin privileges for some tests (traceroute)

## Notes

- Some tests (like traceroute) require root/admin privileges
- Results are saved in JSON format for further analysis
- The tool uses multiple DNS servers for redundancy
- Timeouts are configurable in the CONFIG dictionary

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
