# Mesh Provisioning Parser

A Python-based parser for analyzing **Bluetooth Mesh Provisioning packets** captured with Wireshark.  
The tool decodes provisioning PDUs, reconstructs the provisioning process step by step, and detects security issues such as **Reflection Attacks** and potential **Man-in-the-Middle (MitM) Attacks**.

---

##  Features
-  **Packet Parsing**: Uses `pyshark` to parse provisioning packets from `.pcapng` traces.  
-  **Provisioning Step Analysis**: Decodes and prints details for each PDU type:
  - Invite
  - Capabilities
  - Start
  - Public Keys
  - Confirmation
  - Random
  - Data
  - Complete
-  **Security Checks**:
  - Detects **Reflection Attacks** during the confirmation and nonce exchange phases.
  - Logs suspicious behavior for further analysis.
- 🧩 **Extensible Design**: Each PDU type is represented by its own class, making it easy to extend for additional analysis.

---

##  Tech Stack
- **Language**: Python 3.9+  
- **Libraries**:
  - [`pyshark`](https://github.com/KimiNewt/pyshark) – Python wrapper for tshark
  - [`nest_asyncio`](https://github.com/erdewit/nest_asyncio) – To allow asyncio re-entry in interactive sessions

---
