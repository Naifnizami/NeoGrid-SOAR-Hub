# NeoGrid SOAR Hub: OCSF-Native Autonomous SOC  
### Advanced Hierarchical Multi-Agent Swarm & Intelligent Schema Normalization

![Status](https://img.shields.io/badge/Status-FINAL%20PRODUCTION%20MASTER-green)
![Standard](https://img.shields.io/badge/Standard-OCSF%201.7.0-blue)
![Architecture](https://img.shields.io/badge/Architecture-Hierarchical%20Agent%20Swarm-purple)
![AI](https://img.shields.io/badge/LLM-Llama--3.3%20(Groq)-orange)

**NeoGrid SOAR Hub** is a production-maturity security operations platform engineered for **high-fidelity, context-aware triage**. Moving beyond traditional rule-based automation, the platform utilizes an **OCSF 1.7.0 telemetry pipeline** and a **hierarchical AI agent swarm** to mimic a Tier-3 SOC team's investigative reasoning.

---

## 🧠 Architecture Philosophy — Think Before Act

The platform is designed as a **modular microservice ecosystem**, decoupling raw log collection from forensic reasoning.

### Core Principles

1. **Normalization Engine (OCSF 1.7.0)**  
   Disparate telemetry (Linux Auditd, Windows Events, Splunk logs) is standardized into vendor-neutral format.

2. **Hierarchical Multi-Agent Swarm**

   Lead L3 Orchestrator delegates to:

   - Threat Intelligence Agent  
   - Detection Engineering Agent  
   - Compliance Agent  

3. **Autonomous Orchestration (n8n)**

   Storm Mode bundles alert floods into single case.

---

## 📊 Automation & Orchestration Logic Breakdown

---

### 1. Webhook Intake Node

**Purpose:** Entry point

Receives alerts from Splunk

---

### 2. Shield / Hygiene Layer

**Purpose:** Clean data

Removes:

- duplicates
- malformed JSON
- hex encoding

Extracts:

- host
- user
- process
- IP

---

### 3. Storm Guard Logic

**Purpose:** Prevent ticket flooding

| Alert Count | Action |
|------------|--------|
| < 10 | Normal investigation |
| ≥ 10 | Storm Mode |

Storm Mode:

- Bundles alerts
- Creates Super Case

---

### 4. The Bridge — OCSF Normalization

Converts Raw Log → OCSF

Example Output:

    {
      "class_name": "Process Activity",
      "category_name": "System Activity",
      "severity": "High",
      "actor": {},
      "device": {},
      "process": {}
    }

---

### 5. Agno AI Swarm Analysis

**Purpose:** Cognitive SOC reasoning

Model:

Llama-3.3-70B via Groq

Hierarchy:

Lead Orchestrator

Delegates to:

- Threat Intel Agent
- Detection Agent
- Compliance Agent

Example Verdict:

    Verdict: CONFIRMED MALICIOUS
    Technique: T1059 Command Execution
    Confidence: 94%
    Action: Host Isolation Recommended

---

### 6. Response Layer

Creates:

- Jira Incident
- Forensic Report
- Slack Alert

---

## 🛠 Technology Stack

| Layer | Tech |
|------|------|
| Language | Python 3.11 |
| Framework | FastAPI |
| AI | Agno |
| LLM | Llama-3.3-70B |
| Workflow | n8n |
| Container | Docker |
| Standard | OCSF |

---

## 📁 Project Structure

    SOC-INTEGRATED-PLATFORM/

    ├── services/

    │   ├── ai-analyst/

    │   ├── soar-bridge/

    │   └── telemetry-gen/

    ├── n8n_storage/

    ├── .env.example

    ├── docker-compose.yml

    └── NeoGrid_SOAR_v10.json

---

# 🚀 Deployment

Clone:

    git clone https://github.com/YOUR_USERNAME/NeoGrid-SOAR-Hub.git

Configure:

    cp .env.example .env

Run:

    docker-compose up -d --build

---

# Deploy Workflow

Open:

    http://localhost:5678

Import:

    NeoGrid_SOAR_v10.json

Activate

---

# 🧪 Testing

Normal test:

    python services/telemetry-gen/src/sender.py 1

Storm test:

    python services/telemetry-gen/src/batch_sender.py 25

---

# 🎯 Capabilities

✔ Autonomous SOC  
✔ AI Investigation  
✔ OCSF Native  
✔ SOAR Automation  
✔ Jira Integration  

---

# 👨‍💻 Author

Naif Nizami

LinkedIn:

    https://linkedin.com/in/YOUR_LINK

GitHub:

    https://github.com/YOUR_USERNAME

---

# ⚠ Disclaimer

Educational use only

---

# 🏁 Result

Fully autonomous AI SOC platform
