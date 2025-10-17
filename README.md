<!-- Badges -->
[![SECURITY](https://img.shields.io/badge/SECURITY-critical?style=flat-square&color=ff2d55&labelColor=2f2f2f)](https://example.com)
[![AWARENESS](https://img.shields.io/badge/AWARENESS-important?style=flat-square&color=ff6f3c&labelColor=2f2f2f)](https://example.com)
[![PYTHON](https://img.shields.io/badge/PYTHON-3.x?style=flat-square&color=3776ab&labelColor=2f2f2f)](https://www.python.org/)
[![GUI](https://img.shields.io/badge/GUI-Tkinter?style=flat-square&color=6c757d&labelColor=2f2f2f)](https://docs.python.org/3/library/tkinter.html)
[![EDUCATIONAL](https://img.shields.io/badge/EDUCATIONAL-yes?style=flat-square&color=4caf50&labelColor=2f2f2f)](https://example.com)
[![VM_ONLY](https://img.shields.io/badge/VM--ONLY-lab_only?style=flat-square&color=f4c542&labelColor=2f2f2f)](https://example.com)
[![NETWORK](https://img.shields.io/badge/NETWORK-isolated?style=flat-square&color=bd6b1e&labelColor=2f2f2f)](https://example.com)
[![DEMO](https://img.shields.io/badge/DEMO-mode?style=flat-square&color=8b5cf6&labelColor=2f2f2f)](https://example.com)

# Dragon C2 — Educational C2 Framework (VM-only)

**Security Awareness • Python 3.x • Tkinter • Educational • VM Only • Network Isolated • Demo Mode**

---

> ⚠️ **Important — Read Before Running**  
> This project is strictly for educational, defensive, and research purposes only. **Do NOT** run this software against any system you do not own or do not have explicit written permission to test. Test **only** inside an isolated virtual machine (VM) or a dedicated lab environment that is not connected to production networks or the public Internet. The author/maintainer is not responsible for any misuse.

---

## Overview

Dragon C2 is a graphical (Tkinter) educational Command & Control (C2) framework designed to demonstrate C2 concepts in a safe lab environment. It is intended for students and security researchers to study session handling, remote commands, and basic file interactions — strictly in isolated VMs.

This repository and documentation focus on education, detection, and defensive understanding. Offensive deployment details and any use outside authorized lab environments are explicitly disallowed.

---

## Features (Educational Only)

- Start/stop a listener on a chosen port (GUI-controlled).  
- Manage multiple sessions (identified by source IP) and select an active session.  
- Send simple shell-like commands and receive simulated responses.  
- Browse remote file listings (demo/simulation mode).  
- Receive file-like payloads (screenshots, logs) and store them locally in a designated folder (e.g., `c2_loot/`).  

---

## Usage — High-level (VM only)

> **IMPORTANT:** Follow the guidance below **only** inside isolated VMs configured for testing and learning.

### 1) Start the listener (Attacker VM)
- Open the project inside your attacker VM.  
- Run the main GUI controller (adjust to the actual script name you have):
```bash
python3 "Dragon C2.py"
In the GUI set the listening port (for example 4444) and click Start.

The GUI should indicate Listening when ready.

2) Configure the agent (Victim VM)

Edit the provided sample agent template (e.g., templates/agent_template.py) and set the attacker VM IP and port:

ATTACKER_IP = "192.168.56.101"  # lab-only attacker VM IP
ATTACKER_PORT = 4444            # port chosen in the GUI


For safe demos, use the included sim_agent.py which echoes commands rather than executing them:

python3 sim_agent.py


After the agent connects, the attacker GUI will show a new session entry.

3) Send commands from the GUI

Select the active session (the connected IP).

Type a simple command (safe, non-destructive), e.g.:

echo Hello from Dragon C2


Responses will appear in the output/log panel (simulated/echoed in demo mode).

4) File browser & receiving files

Use the File Browser pane to request directory listings from the simulated agent.

Downloaded or received files (screenshots, logs) are saved to c2_loot/ on the attacker VM for inspection.

Examples

Run the listener on port 5555

python3 "Dragon C2.py"


In GUI: set Port = 5555 → Click Start

Configure and run the agent (victim)
Edit templates/agent_template.py:

ATTACKER_IP = "192.168.56.101"
ATTACKER_PORT = 5555


Run on victim VM (use sim_agent.py for safe demo):

python3 sim_agent.py


Send a safe command from the GUI

Type echo ping-test and press Enter (or click Send). The simulated agent will echo back a response to the GUI output.

Storage & Output

Files and simulated artifacts received from agents are stored under:

c2_loot/


Logs and session metadata are kept locally in the attacker VM. Ensure this storage is inside your isolated lab and not backed up to production systems.

Security & Lab Guidance

Isolate the lab: Keep attacker and victim VMs inside an isolated virtual network that has no route to production or the public Internet.

Least privilege: Run all demos with minimal privileges required by the simulation.

Monitoring: Use an observer VM (SIEM/EDR) in the lab to capture telemetry and practice detection.

Rollback plan: Keep VM snapshots/backups to restore known-good states after exercises.

Legal compliance: Always obtain documented, explicit authorization for anything beyond local lab demos.

Recommended Lab Exercises (Educational)

Beacon Detection: Simulate periodic outbound beacons and create SIEM alerts to detect them.

Behavior Detection: Generate benign file I/O and network activity; adjust EDR behavioral rules to flag suspicious patterns.

Forensics Drill: Capture disk and memory artifacts from a simulated session and perform forensic analysis.

Detection Rule Authoring: Write Sigma / Suricata / Snort signatures to detect demo C2 patterns in the lab.
