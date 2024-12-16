# Advanced Real-Time Intrusion Detection System (IDS)

## Overview
**Advanced Real-Time IDS** is a Python-based Intrusion Detection System (IDS) that monitors and analyzes network traffic in real-time. It captures packets, detects suspicious activities based on signature-based matching, payload anomalies, and DNS query analysis, and logs all details into time-stamped CSV files for further inspection.

This project is designed to help network administrators identify potential security threats and anomalous network behavior effectively.

---

## Features
- **Real-Time Packet Capture**: Continuously monitors and captures packets from the network.
- **Signature-Based Detection**: Matches payload data against suspicious patterns to detect known threats.
- **Payload Size Anomaly Detection**: Flags payloads exceeding configurable size thresholds.
- **DNS Query Monitoring**: Identifies and flags suspicious DNS queries.
- **Hostname Resolution**: Resolves source and destination IP addresses to hostnames for better visibility.
- **Customizable Configuration**: 
  - Load thresholds, patterns, and interface details from `config.json` and `.env` files.
  - Securely manage sensitive configuration data.
- **CSV Logging**: Saves captured packet details in well-structured CSV files.

---

## Project Structure
```
├── test/                  # Source folder
│   ├── test_preprocess.py # Main IDS script
│   ├── config.json        # JSON-based configuration file
│   └── .env               # Environment variables for sensitive data


## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yusufdalbudak/advanced-real-time-ids.git
   cd advanced-real-time-ids
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configuration**:
   - Update the **`config.json`** file with your network settings (e.g., `TARGET_IP`, `INTERFACE`, `SUS_PATTERNS`).
   - Store sensitive configurations like interface details in the **`.env`** file.
   - Add your `.env` and log files to `.gitignore` for security.

5. **Run the IDS**:
   ```bash
   python test_preprocess.py
   ```

---


## Usage
1. **Start the IDS**:
   The script will capture network packets in real-time and log any suspicious activity.
   ```bash
   Starting IDS... Logging to traffic_log_<timestamp>.csv
   ```
2. **CSV Logs**:
   All packet details are logged to CSV files in the root directory with unique timestamps, e.g., `traffic_log_20241216_033258.csv`.

3. **Fields Logged**:
   - Timestamp
   - Source IP & Hostname
   - Destination IP & Hostname
   - Source & Destination Ports
   - Protocol (TCP/UDP/ICMP)
   - Payload Size
   - Details (Suspicious patterns, DNS queries, etc.)
   - Status (Normal/Suspicious)

---


## Example Output
**Real-Time Terminal Log**:
```
[2024-12-16 03:33:07] Src: 192.168.*.*** (R3V3R53) -> Dst: 34.***.**.*** (210.**.***.**.*********tent.com),
Protocol: TCP, Status: Normal, Details: Normal Traffic

[2024-12-16 03:33:09] Src: 192.168.*.*** (R3V3R53) -> Dst: 172.***.**.*** (************e100.net),
Protocol: UDP, Status: Suspicious, Details: Large Payload Detected: 1250 bytes
```

**CSV Log Example**:
```csv
Timestamp,Source IP,Source Hostname,Destination IP,Destination Hostname,Source Port,Destination Port,Protocol,Payload Size,Details,Status
2024-12-16 03:33:09,192.168.*.***,R3V3R53,172.***.**.***,**********.1e100.net,443,443,TCP,0,Normal Traffic,Normal
2024-12-16 03:33:12,192.168.*.***,R3V3R53,34.***.**.***,************.com,58034,443,UDP,1250,LARGE PAYLOAD DETECTED,Suspicious
```

---


## Customization
- Modify **`SUS_PATTERNS`** in `config.json` or `.env` to detect additional suspicious keywords or domains.
- Adjust **`PAYLOAD_SIZE_THRESHOLD`** and **`TRAFFIC_THRESHOLD`** as per your environment.
- Extend the logic in `packet_callback()` to add more detection layers.

---

## Dependencies
- **Python 3.8+**
- **Scapy** - Packet manipulation library
- **python-dotenv** - Environment variable management

Install them using:
```bash
pip install scapy python-dotenv
```

---


## Contributing
Contributions are welcome! Feel free to open an issue or submit a pull request.

### To Contribute:
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add your feature here"
   ```
4. Push your branch and create a pull request.

---

## License
This project is licensed under the **MIT License**.

---

## Author
- **Yusuf Dalbudak**
- GitHub: [yusufdalbudak](https://github.com/yusufdalbudak)

---

## Acknowledgments
Special thanks to:
- **Scapy Community** for the powerful packet manipulation library.
- All contributors and testers for enhancing the project.

---

Happy Monitoring 🚀!
