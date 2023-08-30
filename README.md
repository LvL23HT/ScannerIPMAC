# ScanIPMAC: A Simple IP and MAC Scanner

## Introduction

The `ScanIPMAC.py` script is a handy utility for scanning IP and MAC addresses on a network. It makes use of several Python libraries like `colorama` for colorful terminal outputs, `scapy` for packet manipulation, `socket` for low-level network programming, `nmap` for network scanning, and `manuf` for identifying manufacturers based on MAC addresses.

## Features

- Scans local network to identify connected devices.
- Retrieves IP and MAC addresses.
- Identifies device manufacturers.
- Provides colorful terminal outputs for better readability.

## Requirements

- Python 3.x
- colorama
- scapy
- socket
- nmap
- manuf

## Installation

To install the required Python packages, run the following command:

```bash
pip install colorama scapy python-nmap manuf
```

## Usage

1. Clone the repository to your local machine.

    ```bash
    git clone https://github.com/LvL23HT/ScannerIPMAC.git
    ```

2. Navigate to the project directory.

    ```bash
    cd ScannerIPMAC
    ```

3. Run the script.

    ```bash
    python ScanIPMAC.py
    ```

## Sample Output

```
Scanning IP: 192.168.1.1 | MAC: AA:BB:CC:DD:EE:FF | Manufacturer: Cisco   | Hostname: Jon
Scanning IP: 192.168.1.2 | MAC: FF:EE:DD:CC:BB:AA | Manufacturer: Netgear | Hostname: Stven
...
```

## Demo

![Demo ScanIPMAC](https://i.postimg.cc/9MLWT1hg/scanipmac.png)

## Contributing

Feel free to open issues or submit pull requests if you think the script can be improved in any way.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
