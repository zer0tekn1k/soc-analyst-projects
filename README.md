# 🛡️ SOC Analyst & Blue Team Projects

Hands-on security projects simulating real-world SOC, detection engineering, and investigation workflows.

This repository showcases how I think through alerts, logs, and incidents — focusing on **practical detection logic**, **clear investigation narratives**, and **automation-friendly outputs**.

---

**Projects**

**1️⃣ Suspicious Login Story Builder**

**Focus:** Authentication anomaly detection & SOC investigation  

**Skills demonstrated:**  
Behavioral baselining, risk scoring, alert storytelling, JSON automation

**What it does:**  
- Establishes baseline login behavior from historical authentication data  
- Detects anomalous login activity using:
  - New geography  
  - New device  
  - Unusual login time  
  - Short suspicious sequences (success → failure)  
- Outputs:
  - Analyst-readable incident narratives  
  - JSON output for automation or SIEM ingestion  

📁 Project folder: `01-login-story-builder/`

---

**What this repository demonstrates**

- SOC Tier 1–2 alert triage thinking  
- Blue Team detection logic (behavior-based, not signature-only)  
- Clear documentation and investigation reasoning  
- Clean Git workflow with incremental, meaningful commits  

---

**Tools & Technologies**

- Python  
- CSV log analysis  
- Git & GitHub  
- Command-line tooling  

---

**Notes**

These projects are intentionally scoped to mirror **on-the-job SOC and Blue Team tasks**, not academic exercises.

