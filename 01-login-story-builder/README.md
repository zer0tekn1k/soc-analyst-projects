# 🔍 Suspicious Login Story Builder

## 🧠 Problem
SOC analysts often receive raw authentication logs without sufficient context, making investigations slow and error-prone.

## 🎯 Objective
Build a tool that reconstructs suspicious login activity into a clear, analyst-readable incident story.

## 🧩 Analyst Logic
- Establish baseline login behavior for users
- Detect anomalies (new locations, unusual times, unfamiliar devices)
- Correlate related events into a single investigation timeline

## 🛠 Tools & Technologies
- Python
- Sample authentication logs (CSV format)

## 📈 Outcome
Produces a concise incident narrative that can be used for alert escalation, reporting, or case documentation.

## 🚀 Future Improvements
- Risk scoring for login anomalies
- MITRE ATT&CK technique mapping
- Integration with SIEM exports (Splunk, Elastic)
