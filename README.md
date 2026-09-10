# Corporate Network SOC Lab with AI-Powered Threat Analysis

A fully segmented corporate network simulation with firewall, IDS, vulnerable services, and an AI-powered SOC dashboard for real-time threat detection and analysis. Built as a personal cybersecurity portfolio project.

![Network Topology](diagrams/topología_de_red.png)

## Overview

This project simulates a realistic enterprise network environment with multiple security zones, an intrusion detection system monitoring all traffic, intentionally vulnerable services for attack simulation, and a custom-built SOC dashboard that leverages a local LLM to analyze threats in real time.

The entire lab runs on VMware Workstation Pro 17 with 16 GB of RAM, demonstrating that a professional-grade security lab is achievable on consumer hardware.

## Architecture

```
                         INTERNET
                            │
                    ┌───────┴───────┐
                    │   OPNsense    │
                    │  Firewall +   │
                    │  Suricata IDS │
                    └───────┬───────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
     ┌──────┴──────┐ ┌─────┴─────┐ ┌───────┴──────┐
     │     DMZ     │ │    LAN    │ │     MGMT     │
     │ 10.0.1.0/24 │ │10.0.2.0/24│ │ 10.0.3.0/24 │
     └──────┬──────┘ └─────┬─────┘ └───────┬──────┘
            │              │               │
       Debian 12      Alpine Linux    Alpine Linux
       10.0.1.10      10.0.2.50       10.0.3.10
       DVWA :80       Workstation     SOC Dashboard
       Juice Shop              │         :5000
         :3000                 │            │
       WebGoat            Win Server   Ollama (host)
         :8080            10.0.2.37    10.0.3.100
                                         :11434
```

### Network segments

| VMnet | Zone | Subnet | Purpose |
|-------|------|--------|---------|
| VMnet8 / Bridged | WAN | 192.168.68.0/24 | Internet gateway |
| VMnet2 | DMZ | 10.0.1.0/24 | Exposed vulnerable services |
| VMnet3 | LAN | 10.0.2.0/24 | Corporate workstations |
| VMnet4 | MGMT | 10.0.3.0/24 | Security monitoring |

### Machines

| Host | OS | IP | Role |
|------|----|----|------|
| OPNsense Firewall | FreeBSD | em0: DHCP, em1: 10.0.1.1, em2: 10.0.2.1, em3: 10.0.3.1 | Gateway, firewall, Suricata IDS |
| DMZ-Vulnerable | Debian 12 | 10.0.1.10 | DVWA, Juice Shop, WebGoat via Docker |
| LAN Workstation | Alpine Linux | 10.0.2.50 | Test station, attack simulation |
| SOC Dashboard | Alpine Linux | 10.0.3.10 | Flask dashboard with AI analysis |
| Windows Host | Windows 10/11 | 10.0.3.100 | VMware host, Ollama LLM |

## Components

### OPNsense Firewall
- Four network interfaces (WAN, DMZ, LAN, MGMT)
- Firewall rules per zone with inter-zone traffic control
- Outbound NAT in hybrid mode for DMZ and MGMT
- SSH enabled for automated alert retrieval

### Suricata IDS
- Running in PCAP mode across all four interfaces (em0–em3)
- 175,000+ rules from Emerging Threats Open
- Categories include: scan detection, exploit signatures, web server attacks, malware, shellcode, SQL injection, and more
- Alerts written to `/var/log/suricata/eve.json` in EVE JSON format

**Note:** Suricata runs in IDS (detection) mode rather than IPS (prevention) because VMware's virtual network adapters are incompatible with Netmap mode. This mirrors a common enterprise deployment pattern where detection and manual response is preferred over automatic blocking to avoid disrupting legitimate traffic.

### Vulnerable Services (Docker)
Three intentionally vulnerable web applications running on Debian 12:

| Service | Port | Vulnerabilities |
|---------|------|-----------------|
| DVWA | 80 | SQL Injection, XSS (Reflected/Stored), Command Injection, File Upload, File Inclusion (LFI/RFI), CSRF, Brute Force |
| Juice Shop | 3000 | Broken Authentication, Sensitive Data Exposure, XXE, Broken Access Control, Security Misconfiguration, Insecure Deserialization |
| WebGoat | 8080 | Path Traversal, IDOR, JWT Manipulation, Advanced SQL Injection, XXE, SSRF, Cryptographic Failures |

### SOC Dashboard with AI
A custom Flask application in the MGMT zone that:
1. Connects to OPNsense via SSH to retrieve Suricata alerts
2. Sends alerts to a local Ollama instance (Llama 3.2 3B) for analysis
3. Displays results in a professional web dashboard with:
   - Real-time severity counters
   - Alert volume trend charts
   - Severity distribution visualization
   - Weekly threat activity heatmap
   - Categorized threat list
   - Expandable alert cards with MITRE ATT&CK mapping, impact assessment, and mitigation steps

## Detection flow

```
1. Attacker (LAN)  ──attack──▶  Vulnerable Service (DMZ)
                                        │
2. Traffic passes through OPNsense  ◀───┘
                │
3. Suricata inspects packets against 175K rules
                │
4. Alert written to eve.json
                │
5. SOC Dashboard reads alert via SSH
                │
6. Ollama (LLM) analyzes:
   • Classifies severity
   • Maps to MITRE ATT&CK
   • Assesses impact
   • Suggests mitigation steps
   • Proposes custom Suricata rules
                │
7. Results displayed in real-time dashboard
```

## Installation

### Prerequisites
- VMware Workstation Pro 17 (free for personal use)
- 16 GB RAM minimum
- Intel or AMD processor with virtualization support (VT-x/VT-d)
- ~100 GB free disk space
- Ollama installed on the host machine

### Step-by-step guides
- [OPNsense Firewall Setup](docs/instalacion-opnsense.md)
- [Suricata IDS Configuration](docs/instalacion-suricata.md)
- [Vulnerable Services Deployment](docs/servicios-vulnerables.md)
- [SOC Dashboard Installation](docs/dashboard-soc.md)
- [Attack Simulation and Detection](docs/pruebas-deteccion.md)

### Quick start

**1. Configure VMware virtual networks**

Create three host-only networks in the Virtual Network Editor (DHCP disabled):
- VMnet2: 10.0.1.0/24 (DMZ)
- VMnet3: 10.0.2.0/24 (LAN)
- VMnet4: 10.0.3.0/24 (MGMT)

**2. Deploy OPNsense**

Install OPNsense with four network adapters mapped to VMnet8 (WAN), VMnet2 (DMZ), VMnet3 (LAN), and VMnet4 (MGMT). Configure interface IPs, firewall rules, and outbound NAT.

**3. Start Suricata in PCAP mode**

```bash
cat /usr/local/etc/suricata/opnsense.rules/*.rules > /usr/local/etc/suricata/rules/OPNsense.rules
suricata -c /usr/local/etc/suricata/suricata.yaml -i em0 -i em1 -i em2 -i em3 -D
```

**4. Deploy vulnerable services**

```bash
cd /opt/lab
docker-compose up -d
```

**5. Start the SOC Dashboard**

```bash
cd /opt/soc
python3 app.py
```

Access at `http://10.0.3.10:5000`

**6. Start Ollama on the Windows host**

```powershell
$env:OLLAMA_HOST="0.0.0.0"
ollama serve
```

## Key learnings

Throughout this project, several real-world challenges were encountered and resolved:

- **VMware Netmap incompatibility:** Suricata's Netmap IPS mode doesn't work with VMware virtual adapters. Running in PCAP IDS mode is the solution, which is a valid and common enterprise deployment pattern.
- **OPNsense rule regeneration:** OPNsense clears the Suricata rules file on every restart. The workaround is manually concatenating rules from the opnsense.rules directory before starting Suricata.
- **ARP conflicts:** VMware host-only adapter IPs can collide with OPNsense interface IPs, breaking routing. Solution: disable host adapter connectivity in the Virtual Network Editor or assign non-conflicting IPs.
- **Firewall protocol handling:** Setting protocol to "any" in OPNsense causes it to add TCP flags (S/SA), blocking ICMP and UDP. Creating separate ICMP, TCP, and UDP rules per interface resolves this.
- **LLM output reliability:** Small local models (3B parameters) struggle with structured JSON output. Using low temperature (0.1), English prompts, and including a concrete JSON example in the prompt significantly improves format consistency.
- **Sensitive configuration:** API keys and credentials are managed via environment variables (python-dotenv) rather than hardcoded values.

## Technologies

- **Virtualization:** VMware Workstation Pro 17
- **Firewall/Router:** OPNsense 26.7
- **IDS Engine:** Suricata 8.0.6 with Emerging Threats Open rules
- **Vulnerable Services:** DVWA, OWASP Juice Shop, WebGoat (Docker)
- **SOC Dashboard:** Python 3, Flask
- **AI/LLM:** Ollama with Llama 3.2 3B
- **Visualization:** Chart.js
- **Operating Systems:** FreeBSD (OPNsense), Debian 12, Alpine Linux

## Screenshots

| Dashboard | Alert Analysis |
|-----------|---------------|
| ![Dashboard](screenshots/dashboard.png) | ![Analysis](screenshots/analisis-ia.png) |

| Suricata Alerts | Network Topology |
|----------------|-----------------|
| ![Alerts](screenshots/alertas-suricata.png) | ![Topology](diagrams/topologia-red.png) |

## Project structure

```
├── README.md
├── docs/
│   ├── instalacion-opnsense.md
│   ├── instalacion-suricata.md
│   ├── servicios-vulnerables.md
│   ├── dashboard-soc.md
│   └── pruebas-deteccion.md
├── diagrams/
│   └── topologia-red.png
├── soc-dashboard/
│   ├── app.py
│   ├── templates/
│   │   └── index.html
│   ├── requirements.txt
│   └── .env.example
├── docker/
│   └── docker-compose.yml
├── suricata/
│   └── custom-rules.rules
└── screenshots/
```

## License

This project is for educational and portfolio purposes only. The vulnerable services (DVWA, Juice Shop, WebGoat) should never be exposed to public networks.

## Author

Eduardo — Cybersecurity enthusiast building hands-on security operations experience.
