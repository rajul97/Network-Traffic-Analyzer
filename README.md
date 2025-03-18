# Network Traffic Analyzer

## Overview
The **Network Traffic Analyzer** is a Python-based tool designed to monitor network traffic and detect suspicious activities such as **SYN Flood attacks** and **Port Scanning**.

## Features
- **Real-time packet sniffing** using `scapy`
- **SYN flood attack detection**
- **Port scanning detection**
- **Logging of suspicious activities**

## Project Structure
```
Network-Traffic-Analyzer/
│── logs/
│   └── suspicious_activity.log      # Log file for detected threats
│── src/
│   ├── analyzer.py                  # Main script to monitor network traffic
│   ├── logger.py                    # Handles logging of suspicious activities
│   ├── config.py                     # Configuration file (thresholds, settings)
│── tests/
│   ├── test_analyzer.py              # Unit tests for traffic detection
│── README.md                         # Project documentation
│── requirements.txt                   # Required Python dependencies
│── .gitignore                         # Ignore unnecessary files (logs, cache, etc.)
```

## Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/Network-Traffic-Analyzer.git
   cd Network-Traffic-Analyzer
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage
To start monitoring network traffic, run:
```bash
python src/analyzer.py
```

## Running Tests
To run unit tests:
```bash
python -m unittest tests/test_analyzer.py
```

## License
This project is licensed under the MIT License.

