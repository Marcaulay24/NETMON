# 🛡️ NETMON PRO v2.2 - Enterprise Security & Compliance Suite

**NETMON PRO v2.2** is a high-performance, multi-threaded network security and asset management platform. Designed for enterprise-level visibility, it offers real-time monitoring, security auditing, and compliance reporting in a single dashboard.

## 🚀 Features

- **🌐 Asset Discovery:** Real-time inventory of all network-connected devices using multi-threaded ICMP and ARP scans.
- **🚨 Alert Engine:** Structured severity scoring (Critical, High, Medium, Low) for security events with unique correlation IDs.
- **🧬 File Integrity Monitoring (FIM):** Cryptographic tracking of sensitive system files to detect unauthorized changes.
- **🎯 Threat Hunting:** Behavioral mapping to the MITRE ATT&CK framework with risk scoring for every endpoint.
- **📘 Compliance Auditing:** Automated reports for major regulatory frameworks like **PCI-DSS**, **HIPAA**, and **GDPR**.
- **🏦 Financial Security:** Specialized modules for bank-level security audits, focusing on legacy protocol exposure (Telnet/FTP).
- **📊 Comprehensive Reporting:** Export results in multiple formats: **PDF**, **DOCX**, **CSV**, and **Plain Text**.
- **🎨 Dynamic UI:** Customizable panel layouts and high-density performance metrics (CPU/RAM/Disk/Network).

## 🛠️ Installation

### 1. System Requirements
- **OS:** Linux (Ubuntu/Debian recommended) or Windows 10/11.
- **Python:** Version 3.13 or higher.

### 2. Install System Dependencies

#### **🐧 Linux (Debian/Ubuntu)**
Ensure the following tools are installed via your package manager:
```bash
sudo apt update
sudo apt install -y nmap python3-scapy
```

#### **🪟 Windows**
For full functionality (packet sniffing and deep scanning) on Windows, follow these steps:
1.  **Install Nmap:** Download and run the [Nmap Windows Installer](https://nmap.org/download.html#windows).
2.  **Install Npcap:** During the Nmap installation, ensure **Npcap** is selected. Npcap is required for the Scapy engine to capture raw packets.
3.  **Python Path:** Ensure Python 3.13+ is added to your system **PATH**.

---

### 3. Setup Virtual Environment (Recommended)
```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 4. Install Python Packages
```bash
pip install -r requirements.txt
```

## 📖 How to Run

### 🖥️ GUI Launcher (Desktop)
1. **Enable the Desktop Icon:** Double-click the `NetMonPro.desktop` icon on your desktop.
   - *Note: On Linux, you may need to right-click and select "Allow Launching" the first time.*
2. **Launch with Root Privileges:** The application will prompt for your **sudo** password automatically to enable network monitoring features.

### ⌨️ Terminal Launch
1. **Launch the Application:**
   ```bash
   python netmonv2.2.py
   ```
   *Note: On Linux, running as `sudo` may be required for certain features like raw packet sniffing (ARP monitoring).*

2. **Core Workflow:**
   - **Discover:** Click "Scan Local /24" to populate your device inventory.
   - **Audit:** Select an asset and run a "Deep Scan" or "Security Audit".
   - **Monitor:** Enable the "Activity Monitor" or "FIM Monitor" for live threat detection.
   - **Report:** Export findings via the "Export Reports" tab for stakeholder review.

## 🛡️ Security Disclaimer
This tool is provided for **authorized** security auditing and educational purposes only. Unauthorized use on networks without explicit permission is illegal and unethical. The developer assumes no liability for misuse of this tool.

---

**Developed with ❤️ by Cyberlord**
