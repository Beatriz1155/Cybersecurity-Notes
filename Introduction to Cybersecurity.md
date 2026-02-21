# Definition of cybersecurity
- **Cybersecurity** is the discipline concerned with the protection of information systems, networks, devices, and data against unauthorized access, misuse, disruption, modification, or destruction.

# CIA Triad (Confidentiality, Integrity, Availability)

- **Confidentiality**: Prevent unauthorizes access to data.
- **Integrity**: Ensuring data is not altered.
- **Availability**: Ensuring data/services are accessible when needed.

# Threat vs Vulnerability vs Risk

- **Threat**: A **threat** is any potential cause of harm to a system, network or data, something that could exploit a weakness.
  It can be:
    - **Malicious** (hackers, malware, insider attacks);
    - **Accidental** (human error);
    - **Environmental** (fire, flood, power outage).
 
- **Vulnerability**: A **vulnerability** is a weakness or flaw in a system that can be exploited by a threat.
  Vulnerabilities may exist in:
    - **Software** (unpatched systems);
    - **Hardware**;
    - **Network configurations**;
    - **Human behavior** (weak passwords);
    - **Policies and procedures**.
  
- **Risk**: A **risk** is the potential for loss or damage when a threat exploits a vulnerability.
  Risk considers:
    - The likelihood of exploitation;
    - The potential impact on confidentiality, integrity, and availability;
 
### Simple Comparison

| Term  | What it Represents | Key Question |
| ------------- |:-------------:|:-------------:
| Threat    | Potential cause of harm | What could attack us? |
| Vulnerability | Weakness     | Where are we exposed? |
| Risk     | Potential damage     | What happens if it succeeds? |

# Attack Surface
- The **attack surface** is the aggregate of all accessible attack vectors across hardware, software, network, and human components of an information system.

### Types of Attack Surface
**1. Digital Attack Surface**
    - Public-facing web applications;
    - Open ports and services;
    - APIs;
    - Cloud storage buckets;
    - Email servers;
    - VPN gateways;
    - Misconfigured DNS records.

**2. Physical Attack Surface**
    - Unlocked server rooms;
    - Exposed USB ports;
    - Stolen laptops;
    - Access badges;

**3. Human Attack Surface**
    - Employees vulnerable to phishing;
    - Weak password practices;
    - Insider threats.
  
### Why Attack Surface Matters
The larger the attack surface:
  - The more opportunities attackers have;
  - The harder it becomes to monitor and secure;
  - The greater the overall risk exposure.

Security strategy often focuses on:
  - **Attack Surface Reduction (ASR)**
    - Closing unused ports;
    - Removing unnecessary services;
    - Enforcing MFA;
    - Applying patches;
    - Disabling legacy protocols.

# Types of Threat Actors
- A **threat actor** is any individual, group, or entity that has the capability and intent to carry out malicious cyber activity against a target.

**1. Cybercriminals**

Primary Motivation: Financial gain.

**They conduct:**
  - Ransomware attacks;
  - Phishing campaigns;
  - Identity theft;
  - Financial fraud.

**2. Nation-State Actors (APT Groups)**

Primary Motivation: Espionage, geopolitical advantage, sabotage.
Often referred to as Advanced Persistent Threats (APTs).

**Characteristics:**
  - Long-term campaigns;
  - Custom malware;
  - Zero-day exploitation;
  - Sophisticated persistence techniques.

**3. Hacktivists**

Primary Motivation: Political or ideological causes.

**Activities include:**
  - Website defacement;
  - DDoS attacks;
  - Data leaks.

**4. Insider Threats**

Primary Motivation: Revenge, financial gain, negligence.

**Types:**
  - Malicious insiders;
  - Negligent employees;
  - Compromised insiders.

**5. Script Kiddies**

Primary Motivation: Curiosity, reputation, boredom.

**They:**
- Use publicly available exploit tools;
- Lack deep technical understanding;
- Target easily exploitable systems.

**6. Terrorist Organizations**

Primary Motivation: Fear, disruption, ideological warfare.

**Activities may include:**
  - Targeting critical infrastructure;
  - Cyber-propaganda;
  - Disruption campaigns.

# Cyber Kill Chain (by Lockheed Martin)
- The **Cyber Kill Chain** is a framework developed by Lockheed Martin to describe the stages of a cyberattack, from initial reconnaissance to achieving the attacker’s objective. It helps organizations **understand, detect, and prevent** attacks by breaking them down into discrete steps.

### 7 Stages of the Cyber Kill Chain

**1. Reconnaissance**
- Attacker gathers information about the target.
- Techniques: Social media research, network scanning, footprinting.
- Goal: Identify vulnerabilities and attack vectors.

**2. Weaponization**
- Attacker creates a deliverable (malware, exploit) tailored to the target.
- Combines exploit with a payload (ransomware or remote access tool).

**3. Delivery**
- The weaponized payload is transmitted to the target.
- Methods: Phishing email, malicious USB, drive-by download, or compromised website.

**4. Exploitation**
- Triggering the payload to exploit a vulnerability in the target system.
- Example: Exploiting an unpatched application or weak authentication.

**5. Installation**
- Attacker installs malware or backdoor to maintain persistent access.
- Often designed to evade detection and survive system reboots.

**6. Command and Control (C2)**
- The attacker establishes a remote communication channel with the compromised system.
- Enables remote manipulation, data exfiltration, or lateral movement.

**7. Actions on Objectives**
- Attacker achieves their ultimate goal:
    - Data theft;
    - Ransomware encryption;
    - System disruption;
    - Espionage.

# MITRE ATT&CK Framework (by MITRE Corporation)
- The **MITRE ATT&CK Framework** is a globally recognized knowledge base of adversary **tactics, techniques, and procedures (TTPs)**. Developed by **MITRE Corporation**, it provides a structured way to understand how attackers operate and how organizations can **detect, respond to, and mitigate threats**.

### Core Concepts

**1. Tactics**
- Represent the attacker’s goals or objectives during an attack.
- Example: Initial Access, Persistence, Privilege Escalation.

**2. Techniques**
- Specific methods used to achieve a tactic.
- Example: Spear-phishing attachments (Initial Access), Credential Dumping (Credential Access).

**3. Sub-Techniques**
- More granular breakdowns of techniques for detailed analysis.

**4. Procedures**
- Real-world examples of how threat actors implement techniques.

### MITRE ATT&CK Matrices
- The framework organizes tactics and techniques into matrices:
    - Enterprise Matrix: Focused on attacks against Windows, macOS, Linux, cloud, and network environments.
    - Mobile Matrix: Focused on iOS and Android platforms.
    - PRE-ATT&CK (Deprecated, now integrated): Covered pre-attack reconnaissance activities.

### Key Benefits
- **Threat Intelligence Integration**: Maps real-world attack data to a standard reference.
- **Security Assessment**: Identifies gaps in defenses and prioritizes mitigation.
- **SOC Operations**: Helps analysts detect, respond, and hunt threats using known TTPs.
- **Adversary Emulation**: Supports red team exercises and penetration testing.
