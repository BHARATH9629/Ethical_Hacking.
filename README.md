# 🛰️ Cloud Sentinel — Real-Time Cloud Attack & Defense Emulation

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![LocalStack](https://img.shields.io/badge/LocalStack-AWS%20Emulation-orange.svg)](https://localstack.cloud/)
[![Docker](https://img.shields.io/badge/Docker-compose-2496ED.svg)](https://www.docker.com/)
[![WebSockets](https://img.shields.io/badge/Live-WebSockets-4E5D6C.svg)](#live-interactive-dashboard)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An end-to-end, locally hosted **Cloud Attack and Defense Simulation Lab** simulating an authentic AWS compromise lifecycle paired with a real-time reactive SIEM defender and visual WebSocket dashboard.

---

## 🌟 What Makes This Project Unique?

Unlike static CTFs or theoretical slides, **Cloud Sentinel** offers a complete, synchronized purple-team experience:
- 🛡️ **100% Local & Risk-Free**: Emulates full AWS services (`S3`, `IAM`, `STS`, `DynamoDB`) via LocalStack containerization. Zero cloud bills, zero credentials exposure risk.
- 🎯 **Realistic MITRE ATT&CK Kill Chain**: Walks through the exact techniques threat actors use to breach cloud infrastructures (anonymous recon, credential leak discovery, lateral discovery, and unthrottled exfiltration).
- ⚡ **Dynamic Real-Time Defender SIEM**: Ingests and normalizes live Docker container request logs through rolling-window rate-limiting and rule-based heuristics.
- 🪤 **Canary Trap Architecture**: Injects honeypot credentials at provisioning time for instant, zero-false-positive intrusion alerts upon misuse.
- 📊 **Live Animated SOC Dashboard**: Visualizes the attack flow graph and streams high-severity security alerts via WebSockets with micro-animations.

---

## 🗺️ Attack Flow & Detection Architecture

```mermaid
flowchart LR
    A["👤 Attacker (Anonymous)"] -->|Stage 1: Wordlist Recon| B["🪣 Public S3 Bucket\n(public-conf-bucket-demo)"]
    B -->|Stage 2: Harvest Credentials| C["🔑 Leaked Backup Config\n(db_config.yaml.bak)"]
    C -->|Stage 3: Authenticated Probe| D["⚡ Over-Privileged IAM Role\n(leaked-service-user)"]
    D -->|Stage 4: Bulk Exfiltration| E["🗄️ DynamoDB (Customer PII)\n& Internal S3 Bucket"]

    subgraph SIEM ["🛡️ Real-Time Defender (Port 8000)"]
        S1["S3 ACL Poller (3s)"] -.->|Detects Public Read| B
        S2["Canary Token Registry"] -.->|CRITICAL Alert on Usage| C
        S3["Container Log Stream Tailer"] -.->|Event Rate Evaluator (15s Window)| D
        S4["Burst & Volume Heuristics"] -.->|CRITICAL Alert on Scan/Get| E
        S1 & S2 & S3 & S4 ==> WS["📡 WebSocket Broadcast"]
    end

    WS ==> DASH["🖥️ Live Web Dashboard (app.js / HTML5)"]
```

---

## 📁 Project Structure

```text
├── attacker/                        # 4-Stage Automated Adversary Scripts
│   ├── 1_recon_bucket_enum.py       # Anonymous S3 wordlist discovery & download
│   ├── 2_find_leaked_creds.py       # Regex parsing of leaked AWS access keys
│   ├── 3_privesc_explore.py         # IAM policy & resource privilege enumeration
│   └── 4_exfiltrate.py              # Rapid dump of DynamoDB PII table & S3 objects
│
├── defender/                        # SIEM & Detection Engine
│   ├── main.py                      # FastAPI server & WebSocket connection manager
│   ├── log_tailer.py                # Live Docker log streamer and request parser
│   ├── rules.py                     # Detection logic (Rate-limits, Canaries, Exfil)
│   ├── state.py                     # In-memory sliding window & deduplication engine
│   └── requirements.txt             # Python runtime dependencies
│
├── dashboard/                       # SOC Front-end
│   ├── index.html                   # Interactive graph & live alert feed layout
│   ├── app.js                       # WebSocket client with alert flashing effects
│   └── style.css                    # Dark-mode terminal-inspired theme
│
├── seed/                            # Infrastructure Provisioning
│   └── seed_environment.py          # Seeds buckets, DynamoDB, canary IAM credentials
│
├── docker-compose.yml               # LocalStack multi-service container orchestration
├── reset.ps1                        # One-click environment teardown & reseed script
├── .env.example                     # Environment configuration template
└── README.md                        # Documentation
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- [Docker Desktop](https://www.docker.com/) installed and running.
- [Python 3.9+](https://www.python.org/) installed.

### 2. Environment Setup
Install the defender and attacker dependencies:
```bash
# Install defender requirements
pip install -r defender/requirements.txt

# Install attacker / seed requirements
pip install boto3 requests
```

*(Optional)* Configure local ports or endpoint parameters:
```bash
cp .env.example .env
```

---

## 🎭 Run-of-Show (4 Terminals)

For the best live demonstration experience, open **4 terminal windows** side-by-side:

### 🖥️ Terminal 1 — Spin Up LocalStack
```bash
docker-compose up
```
*Wait until LocalStack reports ready. Verify at `http://localhost:4566/_localstack/health`.*

---

### 🖥️ Terminal 2 — Start the Defender SIEM & Dashboard
```bash
python defender/main.py
```
*Open [http://localhost:8000](http://localhost:8000) in your web browser to display the live SOC dashboard.*

---

### 🖥️ Terminal 3 — Seed the Environment
```bash
python seed/seed_environment.py
```
*Creates the public bucket with the leaked config, the over-privileged IAM user, the internal bucket, 25 synthetic customer PII records in DynamoDB, and registers the honeypot canary key.*

---

### 🖥️ Terminal 4 — Execute the Attack Kill Chain (One by One)

Run each step sequentially and observe the live dashboard react in real time:

#### **Stage 1: Recon & Bucket Discovery**
```bash
python attacker/1_recon_bucket_enum.py
```
> **What happens**: Scans common bucket names anonymously, discovers `public-conf-bucket-demo`, and downloads `backup/db_config.yaml.bak`.
>
> 🚨 **Detection**: S3 ACL poller flags public bucket exposure (**HIGH**).

#### **Stage 2: Credential Extraction**
```bash
python attacker/2_find_leaked_creds.py
```
> **What happens**: Extracts the leaked IAM credentials from the backup configuration file into `.leaked_creds`.

#### **Stage 3: Privilege Enumeration & Lateral Movement**
```bash
python attacker/3_privesc_explore.py
```
> **What happens**: Uses the compromised credentials to query `sts:GetCallerIdentity`, `iam:ListUserPolicies`, `s3:ListBuckets`, and `dynamodb:ListTables`.
>
> 🚨 **Detection**: Triggers instant **CRITICAL** alert for canary key usage and **HIGH** alert for rapid IAM privilege enumeration.

#### **Stage 4: Bulk Data Exfiltration**
```bash
python attacker/4_exfiltrate.py
```
> **What happens**: Scans and dumps all records from the `CustomerPII` table and downloads all internal confidential files in rapid succession.
>
> 🚨 **Detection**: Triggers **CRITICAL** volume-burst exfiltration alert on the SIEM.

---

## 🔄 Resetting Between Runs

To quickly restore everything back to clean state for another run:
```powershell
./reset.ps1
```
This script resets in-memory defender alerts, restarts LocalStack (`PERSISTENCE=0`), re-seeds the vulnerable cloud resources, and removes attacker artifacts.

---

## 🛡️ Detection Heuristics Explained

| Detection Rule | Threshold / Mechanism | Severity |
| :--- | :--- | :--- |
| **`PUBLIC_BUCKET`** | Periodic ACL evaluation for `AllUsers` grant | `HIGH` |
| **`LEAKED_CRED_USED`** | Exact match against registered canary token set | `CRITICAL` |
| **`PRIVILEGE_ENUMERATION`** | ≥ 3 IAM/STS discovery API calls within 15s window | `HIGH` |
| **`EXFILTRATION`** | ≥ 8 bulk read calls or ≥ 200 KB transferred within 15s | `CRITICAL` |

---

## ⚖️ Disclaimer & Educational Use

This laboratory is created solely for **educational, defensive, and authorized security training purposes**. All attacks are performed inside an isolated local emulation environment (LocalStack) with synthetic mock data. Do not execute enumeration or exfiltration techniques on unauthorized cloud infrastructure.
