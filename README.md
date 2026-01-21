# NeoGrid SOAR Hub  
### Autonomous AI-Driven SOC Orchestration Platform

NeoGrid SOAR Hub is a **production-style autonomous security operations platform** that demonstrates how **Agentic AI** can eliminate Tier-1 alert noise, enforce policy-aware triage, and execute active defense — allowing human analysts to focus on **architecture, detection engineering, and threat modeling** instead of repetitive investigation.

---

## 🧩 The Problem

Modern SOC teams face three persistent challenges:

- **Alert Fatigue**: High-volume, low-context alerts overwhelm Tier-1 analysts  
- **Manual Triage Bottlenecks**: Human analysts repeatedly validate known-good activity  
- **Duplicate Incidents**: Recurrent attacker behavior generates redundant cases  
- **Slow Response**: Containment often requires manual approval and execution  

Traditional SOAR platforms automate workflows — but **not reasoning**.

---

## 💡 The Solution

NeoGrid SOAR Hub introduces an **Agentic AI Security Analyst** that performs:

- Context-aware triage using **Retrieval-Augmented Generation (RAG)**
- Stateful memory for incident correlation and deduplication
- Autonomous **active defense** for confirmed threats
- Seamless orchestration across **EDR telemetry, Jira, and Slack**

The result: **AI handles the noise. Humans design the system.**

---

## 🧠 Architecture Overview

The platform is implemented as a **containerized microservice architecture** using Docker.

### Core Components

#### 1️⃣ Telemetry Generator (Sensor Layer)
- Simulates **EDR/XDR telemetry** via REST API
- Emits malicious, authorized, and suspicious events
- Accepts **containment commands** to simulate host isolation
- Mimics real-world EDR behavior (e.g., CrowdStrike RTR)

#### 2️⃣ SOAR Bridge (Control Plane)
- Built with **FastAPI**
- Performs:
  - Context enrichment using local CSV intelligence
  - Case lifecycle management via **Jira Cloud**
  - Real-time alerts via **Slack**
- Orchestrates decisions made by the AI Analyst

#### 3️⃣ AI Analyst Agent (Reasoning Engine)
- Powered by **Agno (Phidata)** and **Llama-3-70B (Groq)**
- Executes forensic reasoning on every alert
- Uses **local RAG policies** to:
  - Validate authorized administrative actions
  - Identify maintenance and backup jobs
  - Distinguish human attackers from automation

---

## 🚀 System Capabilities

### 1️⃣ Contextual AI Triage (RAG)
- AI reads **internal company policies**
- Matches alerts against:
  - Infrastructure backups
  - Approved scripts
  - Admin maintenance windows
- **Authorized behavior**
  - Automatically moved to **Jira → ARCHIVED**
  - Zero analyst involvement

---

### 2️⃣ Active Defense (Host Containment)
- For confirmed malicious activity on critical assets:
  - SOAR Bridge sends containment signal
  - Telemetry Generator disables host network interface
- Simulates **real EDR isolation workflows**

---

### 3️⃣ Stateful Incident Deduplication
- Persistent memory tracks:
  - Attacker IP addresses
  - Recurrent behaviors
- Repeat activity:
  - Evidence appended to existing Jira case
  - Eliminates duplicate tickets and alert noise

---

## 🧰 Technology Stack

- **Python 3.11**
  - FastAPI
  - Pandas
  - PyYAML
- **Containerization**
  - Docker
  - Docker Compose
- **AI & LLM**
  - Agno (Phidata)
  - Groq (Llama-3)
- **Integrations**
  - Jira Cloud REST API
  - Slack Webhooks

---

## ⚙️ Installation & Demo

### 1️⃣ Configure Environment

Create a `.env` file in the project root:

~~~bash
cp .env.example .env
~~~

Populate it with your Jira, Slack, and Groq API credentials.

---

### 2️⃣ Launch the Platform

~~~bash
docker-compose up --build
~~~

---

### 3️⃣ Execute Test Scenarios

#### Scenario 1: Malicious Activity
- Jira ticket created → **To Do**
- Slack alert sent
- **Host containment executed**

#### Scenario 2: Authorized Activity
- Policy match via RAG
- Automatically moved to **Jira → Archived**

#### Scenario 3: Suspicious Activity
- Intent unknown
- Routed to **Jira → To Do** for **L2 analyst review**

---

### ▶️ Run Simulation Command

~~~bash
docker-compose exec nif_telemetry_sim python src/sender.py 1|2|3
~~~

Where:
- `1` → Malicious  
- `2` → Authorized  
- `3` → Suspicious  

---

## 📊 Architecture Diagram (Mermaid)

~~~mermaid
graph TD
    A[Telemetry Generator<br/>EDR / XDR Simulation]
    B[SOAR Bridge<br/>FastAPI Orchestrator]
    C[AI Analyst Agent<br/>Agno + Llama-3]
    D[Jira Cloud<br/>Case Management]
    E[Slack<br/>Alerts & Notifications]
    F[Policy Store<br/>RAG Knowledge Base]

    A -->|Security Events| B
    B -->|Context| C
    C -->|Decision| B
    C -->|Policy Lookup| F
    B -->|Create / Update| D
    B -->|Notify| E
    B -->|Containment Command| A
~~~

---

## 🎯 Why This Project Matters (For Recruiters)

This project demonstrates:

- **SOC-level thinking**, not just scripting
- Real understanding of:
  - Alert fatigue
  - SOAR limitations
  - AI-assisted decision systems
- Hands-on experience with:
  - Distributed systems
  - AI reasoning pipelines
  - Security automation at scale

This is **not a demo toy** — it’s a blueprint for the **next-generation SOC**.

---

## 📜 License

Open-source development for advancing  
**AI-driven cybersecurity operations and autonomous SOC architectures**.
