## Phishing & Spear Phishing
- Phishing is a social engineering attack in which an attacker impersonates a trusted entity to deceive victims into revealing sensitive information such as credentials or financial data. Spear phishing is a targeted version of phishing directed at specific individuals or organizations.

### How It Works
- Attackers send fraudulent emails, messages, or websites that mimic legitimate services. Victims are prompted to:
   - Click malicious links;
   - Download infected attachments;
   - Enter credentials into fake login pages.

Spear phishing typically uses personal or organizational information to increase credibility.

### Indicators of Compromise (IoCs)
- Suspicious sender domains;
- Unexpected password reset emails;
- Lookalike domains (e.g., micros0ft.com);
- Email headers showing spoofed origin;
- Multiple failed login attempts following email receipt.

### Detection Methods
- Email gateway filtering;
- SPF, DKIM, and DMARC validation;
- User-reported suspicious emails;
- SIEM correlation of login anomalies.

### Mitigation Techniques
- Security awareness training;
- Multi-Factor Authentication (MFA);
- Email filtering solutions;
- Domain monitoring.

## Ransomware
- Ransomware is a type of malware that encrypts a victim’s files and demands payment (usually cryptocurrency) for decryption.

### How It Works
- Initial access via phishing or exploit;
- Execution of malicious payload;
- File encryption using strong cryptography; 
- Ransom note deployment.

Some variants also perform data exfiltration before encryption (double extortion).

### Indicators of Compromise (IoCs)
- Sudden file extension changes;
- Presence of ransom notes;
- Unusual file encryption processes;
- High disk activity;
- Shadow copies deletion.

### Detection Methods
- Endpoint Detection & Response (EDR);
- File integrity monitoring;
- Behavioral analysis;
- Monitoring abnormal encryption activity.

### Mitigation Techniques
- Regular offline backups;
- Network segmentation;
- Patch management;
- Application whitelisting.

## Malware (Trojan, Worm, Spyware)
- Malware is malicious software designed to disrupt, damage, or gain unauthorized access to systems.

### Types:
- Trojan: Disguised as legitimate software
- Worm: Self-propagating across networks
- Spyware: Collects user information covertly

### How It Works
- Execution occurs after user interaction or exploitation. Worms propagate automatically through network vulnerabilities.

### Indicators of Compromise (IoCs)
- Unknown processes;
- Unusual outbound connections;
- Registry modifications;
- Unexpected system slowdowns.

### Detection Methods
- Antivirus and EDR;
- Network traffic analysis;
- Behavioral monitoring;
- Sandbox analysis.

### Mitigation Techniques
- Updated antivirus software;
- Patch management;
- Principle of least privilege;
- Network firewall rules.

## SQL Injection
- SQL Injection is a web application vulnerability that allows attackers to manipulate database queries.

### How It Works
- The attacker injects malicious SQL code into input fields (e.g., login forms).
- If inputs are not sanitized, the database executes unintended commands.

Example:
' OR 1=1 --

### Indicators of Compromise (IoCs)
- Unexpected database errors;
- Suspicious query logs;
- Unusual database responses;
- Large data exports.

### Detection Methods
- Web Application Firewall (WAF);
- Log analysis;
- Input validation testing;
- Database query monitoring.

### Mitigation Techniques
- Prepared statements (parameterized queries);
- Input validation;
- Stored procedures;
- Principle of least privilege for DB accounts.

## Cross-Site Scripting (XSS)
- XSS is a client-side attack where malicious scripts are injected into web pages viewed by other users.

### How It Works
- Attackers inject JavaScript into input fields.
- When rendered by the browser, the script executes within the victim’s session.

### Types:
- Reflected;
- Stored;
- DOM-based.

### Indicators of Compromise (IoCs)
- Unexpected pop-ups;
- Session hijacking;
- Unauthorized actions under user accounts.

### Detection Methods
- Code review;
- Web application scanning;
- Content Security Policy (CSP) violations.

### Mitigation Techniques
- Output encoding;
- Input validation;
- Content Security Policy (CSP);
- HTTPOnly cookies.

## Denial of Service (DoS / DDoS)
- DoS attacks aim to make services unavailable. DDoS attacks originate from multiple compromised systems.

### How It Works
- Attackers flood a server with traffic or exploit resource exhaustion vulnerabilities.

### Indicators of Compromise (IoCs)
- Sudden traffic spikes;
- Service unavailability; 
- Increased latency;
- High CPU/memory usage.

### Detection Methods
- Traffic monitoring;
- IDS/IPS alerts;
- Network flow analysis.

### Mitigation Techniques
- Rate limiting;
- Load balancing;
- DDoS protection services;
- CDN usage.

## Man-in-the-Middle (MitM)
- MitM attacks occur when an attacker intercepts communication between two parties without their knowledge.

### How It Works
- The attacker positions themselves between client and server, often via:
   - ARP spoofing;
   - Rogue Wi-Fi hotspots;
   - SSL stripping.

### Indicators of Compromise (IoCs)
- Certificate warnings;
- Unexpected session logouts;
- Suspicious ARP traffic.

### Detection Methods
- Network monitoring;
- TLS certificate validation;
- ARP inspection.

### Mitigation Techniques
- HTTPS enforcement;
- VPN usage;
- Certificate pinning;
- Secure Wi-Fi configurations.

## Brute Force Attacks
- A brute force attack attempts to guess passwords through repeated login attempts.

### How It Works
- Automated scripts systematically test combinations of usernames and passwords.

### Indicators of Compromise (IoCs)
- Multiple failed login attempts;
- Login attempts from unusual IPs;
- Account lockouts.

### Detection Methods
- SIEM alerting on login anomalies;
- Failed authentication log monitoring.

### Mitigation Techniques
- Account lockout policies;
- MFA;
- Strong password policies;
- Rate limiting.

## Credential Stuffing
- Credential stuffing uses stolen username/password combinations from data breaches to gain unauthorized access.

### How It Works
- Attackers automate login attempts across multiple platforms using breached credential databases.

### Indicators of Compromise (IoCs)
- Login attempts from multiple IPs;
- High login failure rates;
- Account takeover reports.

### Detection Methods
- Behavioral analytics;
- Anomaly detection;
- Monitoring leaked credential databases. 

### Mitigation Techniques
- MFA;
- CAPTCHA;
- Password hashing (bcrypt, Argon2);
- Monitoring breach databases.


| Term  | What it Represents | 
| ------------- |:-------------:|
| SPF (Sender Policy Framework) | An email authentication protocol that allows domain owners to specify which mail servers are authorized to send emails on behalf of their domain. |
| DKIM (DomainKeys Identified Mail) | An email authentication mechanism that uses cryptographic signatures to verify that an email message has not been altered during transit and that it was sent by an authorized domain. |
| DMARC (Domain-based Message Authentication, Reporting, and Conformance) | An email authentication protocol that builds on SPF and DKIM.
It allows domain owners to define how receiving servers should handle emails that fail authentication checks (e.g., reject, quarantine, or monitor). | 
| SIEM (Security Information and Event Management) | A centralized security solution that collects, aggregates, correlates, and analyzes log data from multiple systems in real time to detect threats and generate alerts. |
| MFA (Multi-Factor Authentication) | An authentication mechanism that requires two or more independent factors (something you know, have, or are) to verify identity. |
| EDR (Endpoint Detection and Response) | A security solution that continuously monitors endpoint devices to detect, investigate, and respond to suspicious activities. |
| WAF (Web Application Firewall) | A security solution that filters and monitors HTTP traffic between a web application and the Internet to protect against web-based attacks. |
| CSP (Content Security Policy) | A browser security mechanism that helps prevent client-side attacks such as Cross-Site Scripting (XSS).
CSP allows web administrators to define which content sources (scripts, styles, images, etc.) are permitted to load and execute in the browser via HTTP response headers. |
| HTTPOnly Cookies | A security attribute applied to cookies that prevents client-side scripts (e.g., JavaScript) from accessing them.
This mitigates the risk of session theft through XSS attacks by restricting cookie access to HTTP(S) requests only. |
| IDS (Intrusion Detection System) | A monitoring system that detects suspicious network or system activity and generates alerts. |
| IPS (Intrusion Prevention System) | A security system that not only detects malicious activity but also blocks or prevents it. |
| CDN (Content Delivery Network) | A distributed network of geographically dispersed servers that deliver web content closer to end users.
CDNs improve performance, reduce latency, and can provide additional protection against Distributed Denial-of-Service (DDoS) attacks through traffic distribution and filtering. |
| ARP Spoofing | A network attack in which an attacker sends forged Address Resolution Protocol (ARP) messages to associate their MAC address with the IP address of another device on the network.
This enables interception, modification, or redirection of traffic (often used in Man-in-the-Middle attacks). |
| TLS (Transport Layer Security) | A cryptographic protocol that ensures confidentiality, integrity, and authentication of data transmitted over a network.
TLS encrypts communication between client and server, preventing eavesdropping and tampering. |
| HTTPS (Hypertext Transfer Protocol Secure) | The secure version of HTTP that uses TLS encryption to protect data in transit between a client (browser) and a web server. HTTPS ensures encrypted communication and verifies server authenticity via digital certificates. |
| VPN (Virtual Private Network) | A secure communication channel that encrypts network traffic between a user and a remote network. |
| Hashing | A cryptographic process that converts data into a fixed-length value (hash) used for integrity verification or password storage. |
| Encryption | The process of converting plaintext into ciphertext using cryptographic algorithms to protect confidentiality. |
| CAPTCHA (Completely Automated Public Turing test to tell Computers and Humans Apart) | A challenge-response test designed to differentiate human users from automated bots. |
| IoC (Indicator of Compromise) | A forensic artifact or observable evidence indicating that a system may have been breached. |
