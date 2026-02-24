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
