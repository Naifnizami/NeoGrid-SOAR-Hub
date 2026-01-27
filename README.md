# NeoGrid SOAR Hub  
### Autonomous AI-Driven Security Orchestration Platform

![Status](https://img.shields.io/badge/Status-VERIFIED%20COMPLETE-green)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![Architecture](https://img.shields.io/badge/Architecture-Microservices-yellow)
![AI](https://img.shields.io/badge/AI-Agentic%20Security%20Analyst-purple)

**NeoGrid SOAR Hub** is an enterprise-grade platform demonstrating how **Agentic AI (Llama-3)** and robust orchestration eliminate Tier-1 alert noise, enforce policy-aware triage, and execute autonomous defense actions.

The goal is to shift human analyst focus from repetitive investigation to **Threat Hunting** and **Detection Engineering**.

---

## 💡 The Challenge & The Solution

| SOC Challenge | NeoGrid SOAR Hub Solution |
|--------------|---------------------------|
| Alert fatigue & high false positives | **Context-Aware Triage:** AI reasons against Asset Inventory (CMDB) and Business Hours to auto-resolve benign activity |
| Data governance risk when sending logs to external LLMs | **PII Redaction Layer:** Privacy Engine scrubs emails, names, and internal IPs before logs reach the model |
| Slow MTTC (Mean Time To Contain) | **Active Defense:** Automated host isolation (RTR Listener) for verified malicious activity |
| Inconsistent Jira case management | **Stateful Deduplication & ADF Sync:** Recurring incidents update a single Jira case with structured forensic reports |

---

## 🧠 Enterprise Architecture Overview

The platform uses a **containerized, decoupled microservices architecture** built with **Docker Compose** and **FastAPI**, centered around the **SOAR Bridge**.

| Service | Primary Role | Key Features |
|--------|--------------|--------------|
| **AI Analyst Agent** | Cognitive reasoning engine | Llama-3 (Groq), Policy RAG, MITRE mapping, behavioral scoring |
| **SOAR Bridge** | Orchestration & governance | PII redaction, asset context lookup, deduplication, Jira/Slack/Containment I/O |
| **Telemetry Generator** | Simulation & execution | EDR/XDR alert simulation and mock host isolation agent |

---

## 🚀 Key Features (Interview Wins)

### 1️⃣ PII Redaction & Compliance
`privacy_engine.py` intercepts logs and redacts sensitive data (emails, internal IPs, names) before external LLM processing.

### 2️⃣ Context-Aware Behavioral Analysis
The AI detects account misuse by correlating:
- Asset criticality (`asset_inventory.csv`)
- Time of day (`is_business_hours`)
- Policy violations (RAG from `security_policy_maintenance.md`)

### 3️⃣ Resilient Intelligence
Even if external threat intel fails, the AI prioritizes **internal policy and asset context**.

### 4️⃣ Structured Case Management (Jira ADF)
The SOAR Bridge pushes structured forensic reports using **Jira v3 ADF format** for rich, machine-parsable incident records.

---

## ⚙️ Installation & Demo

### 1. Configure Environment
Create a `.env` file from `.env.example` and add:
- Jira API token  
- Slack webhook  

### 2. Launch the Platform
```bash
docker-compose up --build -d
```

---

## 🧪 Execution Scenarios

| Scenario | Command | Validates | Expected Jira Outcome |
|---------|---------|-----------|------------------------|
| Malicious Threat | `docker-compose exec telemetry-gen python src/sender.py 1` | Full pipeline & active defense | **[TP ALERT]** Highest priority, host isolation triggered |
| False Positive | `docker-compose exec telemetry-gen python src/sender.py 2` | Policy triage & auto-resolution | **[AUTO-RESOLVED]** Low priority, archived |
| Stress Test | `docker-compose exec telemetry-gen python src/batch_sender.py 10` | Deduplication & state management | Few new tickets, recurring activity appended |

---

## 📊 Architecture Diagram

**Sense → Think → Act**

```mermaid
graph TD
    subgraph Services
        B[SOAR Bridge / Orchestrator | FastAPI]
        C[AI Analyst Agent | Llama-3 / Groq]
    end

    subgraph Intelligence & State
        F[Policy RAG Store | (Policy/MITRE/Assets)]
        G[State Manager | (Deduplication History)]
        H[Privacy Engine | (PII Redaction)]
    end

    A[EDR Telemetry | (Simulation)] --> H
    H --> B
    B -->|Context/Log| C
    C -->|Verdict| B
    B -->|Jira v3/Slack API| I[Jira / Slack]
    B -->|Block Host| D[Mock EDR Agent | (Containment)]

    B -->|Query| F
    B -->|Update| G
```

---

### 🛡️ Outcome

NeoGrid SOAR Hub demonstrates how **AI-driven orchestration + policy intelligence + automated containment** can reduce SOC workload while improving response consistency and speed.