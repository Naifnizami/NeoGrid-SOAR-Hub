# NeoGrid SOAR Hub  
## Autonomous AI-Driven SOC Orchestration Platform

![Docker](https://img.shields.io/badge/Docker-Containerized-blue)
![Python](https://img.shields.io/badge/Python-3.11-yellow)
![License](https://img.shields.io/badge/License-Open%20Source-green)
![AI](https://img.shields.io/badge/AI-Agentic%20LLM-purple)

NeoGrid SOAR Hub is a production-style autonomous security operations platform that demonstrates how **Agentic AI** can eliminate Tier-1 alert noise, enforce policy-aware triage, and execute active defense — allowing human analysts to focus on **architecture, detection engineering, and threat modeling** instead of repetitive investigation.

---

## 🧩 The Problem

Modern SOC teams face three persistent challenges:

- **Alert Fatigue**: High-volume, low-context alerts overwhelm Tier-1 analysts.
- **Manual Triage Bottlenecks**: Human analysts repeatedly validate known-good activity.
- **Duplicate Incidents**: Recurrent attacker behavior generates redundant cases.
- **Slow Response**: Containment often requires manual approval and execution.

Traditional SOAR platforms automate workflows — **but not reasoning**.

---

## 💡 The Solution

NeoGrid SOAR Hub introduces an **Agentic AI Security Analyst** that performs:

- Context-aware triage using **Retrieval-Augmented Generation (RAG)**.
- Stateful memory for **incident correlation and deduplication**.
- Autonomous **active defense** for confirmed threats.
- Seamless orchestration across **EDR telemetry, Jira, and Slack**.

---

## 🧠 Architecture Overview

The platform is implemented as a **containerized microservice architecture** using Docker.

### 1. Telemetry Generator (Sensor Layer)
- Simulates **EDR/XDR telemetry** via REST API.
- Emits **malicious, authorized, and suspicious events**.
- **RTR Listener**: Runs a live agent listener (`src/listener.py`) to accept containment commands.

### 2. SOAR Bridge (Control Plane)
- Built with **FastAPI**.
- Handles context enrichment (CSV) and stateful deduplication (JSON memory).
- Orchestrates **Jira ticket lifecycles** and **Slack notifications**.

### 3. AI Analyst Agent (Reasoning Engine)
- Powered by **Agno (Phidata)** and **Llama-3-70B (Groq)**.
- Executes **forensic reasoning** against local RAG policies.

---

## 🚀 System Capabilities

### 1️⃣ Contextual AI Triage (RAG)
AI reads internal company policies to match alerts against infrastructure backups and admin maintenance windows.  
Authorized behavior is automatically moved to **Jira → ARCHIVED**.

### 2️⃣ Active Defense (Host Containment)
For confirmed malicious activity on critical assets, the SOAR Bridge sends a signal to the Telemetry Generator, which simulates real EDR isolation (**Host Blocking**).

### 3️⃣ Stateful Incident Deduplication
Persistent memory tracks attacker IP addresses and recurrent behaviors.  
Repeat activity is appended as evidence to **existing cases**, eliminating duplicate noise.

---

## 🧰 Technology Stack

- **Languages**: Python 3.11 (FastAPI, Pandas, PyYAML)
- **Containerization**: Docker & Docker Compose
- **AI & LLM**: Agno Framework + Llama-3 (Groq Cloud)
- **Integrations**: Jira Cloud REST API + Slack Webhooks

---

## ⚙️ Installation & Demo

### 1. Configure Environment
Create a `.env` file in the project root based on the `.env.example` provided.

---

### 2. Launch the Platform

~~~bash
docker-compose up --build
~~~

---

### 3. Execution & Stress Testing

#### A. Unit Testing (Single Scenarios)

~~~bash
docker-compose exec nif_telemetry_sim python src/sender.py 1
~~~
*(Malicious)*

~~~bash
docker-compose exec nif_telemetry_sim python src/sender.py 2
~~~
*(Authorized)*

~~~bash
docker-compose exec nif_telemetry_sim python src/sender.py 3
~~~
*(Suspicious)*

---

#### B. SOC Stress Test (Batch Simulation)

~~~bash
docker-compose exec nif_telemetry_sim python src/batch_sender.py 10
~~~

---

#### C. Monitoring Active Defense (RTR)

Watch real-time isolation logs in the telemetry container:

~~~text
[🛡️] ACTIVE DEFENSE TRIGGERED: ISOLATING HOST
~~~

---

## 📊 Expected Demo Results

| Scenario | Input | AI Verdict | SOAR Action | Jira Outcome |
|--------|------|-----------|------------|-------------|
| 1. Malicious | Encoded PowerShell | MALICIOUS | BLOCK + Slack | To Do (Highest) |
| 2. Authorized | Gateway Backup | AUTHORIZED | Self-Heal | ARCHIVED |
| 3. Suspicious | HR Process List | SUSPICIOUS | Escalate | To Do (Medium) |
| 4. Recurring | Duplicate IP Hit | DEDUPLICATE | Log Comment | Existing Ticket Updated |

---

## 🎯 Why This Project Matters

This project demonstrates **Architecture over Scripting** and proves proficiency in:

- **Distributed Systems**: Microservices communicating via REST APIs.
- **Cognitive Automation**: Using LLMs as logic gates.
- **State Management**: Solving alert fatigue with persistent memory.
- **Cloud-Native Deployment**: Full containerization with Docker Compose.

---

## 📊 Architecture Diagram (Mermaid)

~~~mermaid
graph TD
    A[Telemetry Generator<br/>EDR/XDR Simulation]
    B[SOAR Bridge<br/>FastAPI Control Plane]
    C[AI Analyst Agent<br/>Agno + Llama-3]
    D[Jira Cloud<br/>Case Management]
    E[Slack<br/>Alerts]
    F[RAG Policy Store]

    A -->|Events| B
    B -->|Context| C
    C -->|Verdict| B
    C -->|Policy Lookup| F
    B -->|Create / Update| D
    B -->|Notify| E
    B -->|Containment| A
~~~

---

## 📜 License

Open-source development for advancing **AI-driven cybersecurity operations**.
