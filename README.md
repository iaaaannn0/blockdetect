# blockdetect

**blockdetect** is an open-source tool designed to detect and analyze domain blocking methods. By simulating various network requests and analyzing responses, it identifies blocking techniques such as DNS pollution, IP blocking, Deep Packet Inspection (DPI), fake packets, and HTTP tampering.

## Features

- Detects and analyzes multiple domain blocking methods.
- Provides evidence for each blocking method detected.
- Highlights blocking techniques in a user-friendly table with color-coded outputs.
- Supports DNS queries, HTTP requests, and packet-based inspections.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/iaaaannn0/blockdetect.git
   cd blockdetect
   ```

2. Install dependencies using `pip`:
   ```bash
   pip install rich dnspython requests scapy
   ```

## Usage

Run the tool and enter a domain to test:
```bash
python3 test.py
```

Example:
```
Enter the domain to test: example.com
```

The tool will analyze the domain and display the results in a clear and intuitive table.

## Example Output

Here's an example of the output table:

| Method           | Evidence                                        |
|------------------|------------------------------------------------|
| DNS Pollution    | Resolved IPs: 198.18.13.203 (polluted) |
| IP Blocking      | IP 31.13.72.174 is reachable.   |
| DPI              | Potential DPI blocking detected.    |
| Fake Packets     | No response received; possible filtering. |
| HTTP Tampering   | HTTP returned status code: 503.     |

## Screenshots
<img width="629" alt="image" src="https://github.com/user-attachments/assets/ca6412e2-e0bc-4041-9bf3-4a3561d5ec05" />




## Contributing

Contributions are welcome! If you find issues or have suggestions, feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
