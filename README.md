# Network Traffic Analysis Tool

## Overview

The **Network Traffic Analysis Tool** is designed to capture, analyze, and visualize network traffic data in real-time or from pre-captured PCAP files. The tool leverages heuristic-based detection and machine-learning models to identify anomalies, suspicious behavior, and traffic spikes. It also provides detailed insights into network protocols, and potential Command-and-Control (C2) servers, and identifies potentially infected clients.

## Features

### Core Functionality

1. **PCAP Parsing**: This process extracts detailed packet data (IP addresses, MAC addresses, protocols, etc.) from PCAP files and converts them to CSV format for analysis.
2. **Live Capture**: Captures network traffic in real-time using a specified network interface and processes it for anomalies.
3. **Anomaly Detection**:
   - Heuristic-based rules (e.g., large packets, suspicious protocols).
   - Machine Learning (ML)-based detection using a trained model.
4. **Traffic Visualization**:
   - Protocol distribution pie charts.
   - Suspicious traffic over time.
   - Top suspicious IPs.
   - Geolocation maps for suspicious IPs.

### Analysis Outputs

- **Incident Summary**:
  - Infected client IP, MAC, and hostname.
  - Detected C2 server IPs.
- **CSV Reports**:
  - Parsed packet data.
  - Detected anomalies.
- **Visualizations**:
  - Protocol distribution charts.
  - Suspicious traffic trends.
  - Geolocation maps of suspicious IPs.

### Machine Learning Integration

- Uses a pre-trained Random Forest model to predict anomalies based on network packet features.
- Flexible model retraining using labeled datasets.

---

## Installation

### Prerequisites

1. Python 3.8+
2. Libraries:
   - `pyshark`
   - `pandas`
   - `matplotlib`
   - `folium`
   - `scikit-learn`
   - `joblib`
   - `requests`
3. Install Wireshark and ensure `tshark` is available in your system PATH.
4. A network interface for live capture.

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/kaycee1771/Network_Traffic_Tool.git
   cd Network_Traffic_Tool
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # For Linux/Mac
   venv\Scripts\activate   # For Windows
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Ensure the following directory structure exists:
   ```
   Network_Traffic_Tool/
   |-- src/
   |-- models/
   |-- reports/
   |-- data/
   ```
5. Add the trained machine-learning model to the `models/` directory as `anomaly_detector.pkl`.

---

## Usage

### Parsing PCAP Files

Parse a PCAP file and save the extracted packet details as a CSV file:

```bash
python src/parser.py --input_pcap data/sample.pcap --output_csv reports/parsed_packets.csv
```

### Running Detection on Parsed Data

Detect anomalies and generate visualizations from a pre-parsed CSV file:

```bash
python src/detection.py --input_file reports/parsed_packets.csv --output_report reports/suspicious_traffic.csv
```

### Live Capture and Detection

Capture live network traffic and detect anomalies in real time:

```bash
python src/live_capture.py --interface WiFi
```

---

## File Descriptions

### Scripts

- `src/parser.py`: Parses PCAP files into structured CSV format.
- `src/detection.py`: Analyzes parsed network data for anomalies and generates reports/visualizations.
- `src/live_capture.py`: Captures live network traffic and analyzes it in real time.
- `src/trainer.py`: Trains a machine learning model using labeled network traffic data.
- `src/visualizer.py`: Generates traffic visualizations and geolocation maps.

### Folders

- `models/`: Contains the pre-trained anomaly detection model (`anomaly_detector.pkl`).
- `reports/`: Stores parsed data, analysis reports, and visualizations.
- `data/`: Contains input PCAP files or other raw data.

---

## Examples

### 1. Parsing PCAP and Running Detection

```bash
python src/parser.py --input_pcap data/sample.pcap --output_csv reports/parsed_packets.csv
python src/detection.py --input_file reports/parsed_packets.csv --output_report reports/suspicious_traffic.csv
```

### 2. Live Capture with Machine Learning

```bash
python src/live_capture.py --interface WiFi
```

---

## Contributions

Contributions are welcome! Please open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License.&#x20;

---

## Acknowledgments

Thanks to the open-source community for providing tools and resources like Pyshark, Scikit-learn, and Matplotlib.

---

## Contact

For any questions or feedback, reach out at [kelechi.okpala13@yahoo.com].

