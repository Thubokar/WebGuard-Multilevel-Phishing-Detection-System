<div align="center">

# 🛡️ WebGuard
### Multi-Level Phishing Detection System

A Java-based web application that detects phishing emails and malicious URLs using multiple layers of analysis, trusted sender verification, and VirusTotal threat intelligence.

---

[![Java](https://img.shields.io/badge/Java-17-orange?style=for-the-badge&logo=openjdk)](https://www.java.com/)
[![Servlet](https://img.shields.io/badge/Servlet-Jakarta-blue?style=for-the-badge)](https://jakarta.ee/)
[![JSP](https://img.shields.io/badge/JSP-Java_Server_Pages-red?style=for-the-badge)]
[![Tomcat](https://img.shields.io/badge/Apache-Tomcat-yellow?style=for-the-badge&logo=apachetomcat)]
[![Supabase](https://img.shields.io/badge/Database-Supabase-3ECF8E?style=for-the-badge&logo=supabase)]
[![VirusTotal](https://img.shields.io/badge/API-VirusTotal-blue?style=for-the-badge)]
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)]
[![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)]

---

### 🎓 Final Year Engineering Project

Designed and developed to detect phishing emails using **multiple independent security layers** instead of relying on a single detection technique.

</div>

---

# 📑 Table of Contents

- [About](#-about)
- [Why WebGuard?](#-why-webguard)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Project Highlights](#-project-highlights)
- [System Workflow](#-system-workflow)

---

# 📖 About

Phishing remains one of the most common cyberattacks used to steal passwords, banking credentials, and personal information. Modern phishing emails are carefully designed to imitate trusted organizations, making them difficult to detect using traditional keyword-based filters.

**WebGuard** is a Java web application that approaches this problem differently.

Instead of depending on a single detection method, it combines several independent security layers including keyword detection, pattern analysis, URL inspection, sender verification, and VirusTotal integration to determine the legitimacy of an email.

The application provides detailed explanations for every decision it makes, allowing users to understand **why** an email has been classified as Safe, Suspicious, or Dangerous.

This project was developed as my **Final Year Computer Science Engineering Project**, with the goal of applying cybersecurity concepts to solve a real-world problem while gaining hands-on experience with Java web technologies.

---

# ❓ Why WebGuard?

Most phishing detection systems rely on one technique:

- Keyword matching
- Blacklists
- Machine Learning

Each method has limitations.

WebGuard combines multiple techniques into a layered architecture so that weaknesses in one layer are compensated by another.

This approach significantly improves detection reliability while keeping the system modular and easy to extend.

---

# ✨ Features

<table>

<tr>

<td width="50%">

### 🔍 Email Analysis

- Keyword Detection
- Pattern Analysis
- URL Extraction
- Sender Verification
- Attachment Analysis
- Risk Score Calculation

</td>

<td width="50%">

### 🌐 URL Security

- URL Scanner
- Entropy Detection
- Homoglyph Detection
- Suspicious TLD Detection
- VirusTotal Verification
- Brand Mismatch Detection

</td>

</tr>

<tr>

<td>

### ⚡ Performance

- Smart Caching
- API Rate Limiting
- Fast Pattern Matching
- Optimized URL Parsing

</td>

<td>

### 🛡️ Security

- HTML Sanitization
- Input Validation
- URL Normalization
- XSS Prevention
- Trusted Sender Verification

</td>

</tr>

</table>

---

# 🚀 Project Highlights

✅ Multi-layer phishing detection

✅ Upload and analyze `.eml` email files

✅ Manual email inspection

✅ Standalone URL Scanner

✅ VirusTotal API Integration

✅ Trusted Sender Verification using Supabase

✅ Dynamic Risk Scoring

✅ Safe / Suspicious / Dangerous Classification

✅ Detailed Detection Report

✅ Modular Java Architecture

---

# ⚙️ How It Works

```text
                     USER

                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼

 Manual Email Input          Upload .EML File

          │                         │
          └────────────┬────────────┘
                       │
                       ▼

             Email Preprocessing

                       │
                       ▼

        Layer 1 - Keyword Detection

                       │
                       ▼

        Layer 2 - Pattern Analysis

                       │
                       ▼

          Layer 3 - URL Analysis

                       │
                       ▼

      Layer 4 - Sender Verification

                       │
                       ▼

    VirusTotal Verification (Conditional)

                       │
                       ▼

        Final Risk Score Calculation

                       │
                       ▼

          Detection Report Generated
```

---

# 🎯 Risk Classification

| Score | Classification |
|--------|----------------|
| 🟢 Low | SAFE |
| 🟡 Medium | SUSPICIOUS |
| 🔴 High | DANGEROUS |

---

# 💡 Key Design Goals

- High detection accuracy
- Modular architecture
- Easy to maintain
- Fast execution
- Explainable results
- Low API usage
- Production-style code organization
- Beginner-friendly interface

---

# 📌 Core Capabilities

| Capability | Description |
|------------|-------------|
| Keyword Detection | Detects phishing-related keywords using the Aho-Corasick algorithm |
| Pattern Analysis | Identifies urgency, credential requests, payment fraud, and social engineering patterns |
| URL Analysis | Examines URL structure for phishing indicators |
| Sender Verification | Validates sender identity using trusted records |
| VirusTotal Integration | Confirms suspicious URLs using multiple antivirus engines |
| Risk Score | Generates a combined phishing score |
| Detailed Report | Explains every suspicious indicator detected |

---

---

# 🏗️ System Architecture

WebGuard follows a layered architecture where each component has a single responsibility. This makes the application modular, maintainable, and easy to extend with new detection techniques.

```text
                       +----------------------+
                       |      User Input      |
                       |----------------------|
                       | Manual Email         |
                       | Upload .EML File     |
                       | URL Scanner          |
                       +----------+-----------+
                                  |
                                  v
                    +----------------------------+
                    |      DetectServlet         |
                    +-------------+--------------+
                                  |
                                  v
               +---------------------------------------+
               |  PhishingDetectionService             |
               +----------------+----------------------+
                                |
        +-----------+-----------+-----------+-----------+
        |           |                       |           |
        v           v                       v           v
 Layer 1        Layer 2               Layer 3     Layer 4
 Keywords       Patterns              URLs        Sender
 Detection      Analysis              Analysis    Verification
        |           |                       |           |
        +-----------+-----------+-----------+-----------+
                                |
                                v
                     VirusTotal API (Conditional)
                                |
                                v
                     EmailAnalysisResult DTO
                                |
                                v
                          Results.jsp
```

---

# 🧠 Detection Layers

Unlike traditional email filters that depend on only one detection technique, WebGuard evaluates every email using multiple independent security layers. Each layer focuses on a different phishing characteristic and contributes to the final risk score.

---

## Layer 1 — Keyword Detection

The first layer quickly scans the email body using the **Aho-Corasick string matching algorithm**, allowing hundreds of phishing keywords to be detected in a single pass.

### Why Aho-Corasick?

Unlike repeatedly searching for each keyword one by one, Aho-Corasick builds a finite state machine that searches all keywords simultaneously.

Benefits:

- Very fast searching
- Scalable
- Low memory usage
- Suitable for large keyword lists

### Detects

- Verify Account
- Login Required
- Confirm Password
- Bank Details
- Payment Failed
- Update Information
- Click Here
- Urgent Action Required
- Security Alert

### Additional Checks

- Brand Detection
- Keyword Scoring
- Brand-Domain Verification

---

## Layer 2 — Pattern Analysis

Attackers often avoid common phishing keywords.

Instead, they rely on writing patterns that pressure users into taking immediate action.

Layer 2 identifies these behavioural patterns using regular expressions.

### Detected Patterns

✅ Urgency

Examples:

- Immediately
- Act Now
- Within 24 Hours
- Final Warning

---

✅ Credential Requests

Examples

- Enter Password
- Login Again
- Verify Credentials
- OTP Verification

---

✅ Financial Requests

Examples

- Bank Transfer
- Credit Card
- Payment Failed
- Refund Pending

---

✅ Authority Impersonation

Examples

- IT Department
- HR Team
- Government
- Tax Department

---

### Other Checks

- Excessive CAPITAL LETTERS
- Multiple Exclamation Marks
- Suspicious Formatting
- Social Engineering Language
- Sender Spoofing Indicators

---

## Layer 3 — URL Analysis

Most phishing attacks eventually redirect users to malicious websites.

Layer 3 performs structural analysis on every extracted URL before deciding whether an external VirusTotal scan is necessary.

### URL Extraction

WebGuard automatically extracts URLs from:

- Plain Text Emails
- HTML Emails
- Hyperlinks
- Embedded Sources

---

### URL Security Checks

| Detection | Purpose |
|-----------|---------|
| URL Entropy | Detect randomly generated domains |
| Homoglyph Detection | Detect visually similar characters |
| Brand Mismatch | Detect fake brand domains |
| URL Shorteners | Reveal hidden destinations |
| Suspicious TLD | Identify risky domain extensions |
| HTTP Usage | Warn about insecure protocols |
| IP Address URLs | Detect raw IP-based phishing |
| Long URLs | Detect URL obfuscation |
| Multiple Subdomains | Detect misleading domain structures |
| URL Encoding | Detect hidden malicious paths |
| Non-standard Ports | Identify suspicious services |

---

### Example

Instead of

```
paypal.com
```

A phishing email may contain

```
paypaI-security-login.com
```

Notice the uppercase **I** replacing the lowercase **l**.

Layer 3 detects these tricks before the user clicks.

---

## Layer 4 — Sender Verification

Even if an email looks legitimate, the sender address may be forged.

This layer verifies whether the sender is trusted.

### Verification Process

```
Extract Sender Email

        │
        ▼

Compare with Supabase Trusted Database

        │
        ▼

Brand Verification

        │
        ▼

Trusted / Unknown / Spoofed
```

---

### Trusted Sender Database

Supabase stores records such as

| Service | Trusted Sender |
|----------|----------------|
| Google | support@google.com |
| Microsoft | support@microsoft.com |
| PayPal | service@paypal.com |

If the sender claims to represent PayPal but uses

```
support@paypal-security.xyz
```

the email receives additional phishing points.

---

# 🔗 VirusTotal Integration

WebGuard integrates with the **VirusTotal v3 API** to strengthen phishing detection.

However, calling VirusTotal for every URL would quickly exhaust the free API quota.

Instead, WebGuard performs intelligent local analysis first.

Only suspicious URLs are submitted.

---

## Workflow

```text
URL Extracted

      │
      ▼

Local Heuristic Analysis

      │
      ▼

Is URL Suspicious?

      │
   Yes │ No
      │
      ▼

VirusTotal Scan

      │
      ▼

Existing Report Lookup

      │
      ▼

Verdict Added To Final Report
```

---

## Why Conditional Scanning?

Advantages

- Saves API quota
- Faster response
- Lower latency
- Better scalability
- Reduced unnecessary requests

---

## Rate Limiting

The VirusTotal client includes request throttling to avoid exceeding API limits.

Features include:

- Intelligent delays
- Existing report lookup
- Cached responses
- Retry handling
- Reduced duplicate scans

---

# ☁️ Supabase Integration

Supabase serves as the cloud database for dynamic configuration.

Instead of hardcoding phishing keywords and trusted senders, WebGuard retrieves them from Supabase.

### Tables Used

### Keywords

Stores phishing-related keywords.

Example

| Keyword |
|----------|
| Verify Account |
| Login |
| OTP |
| Password |

---

### Sender

Stores trusted email addresses.

Example

| Trusted Sender | Service |
|----------------|----------|
| support@paypal.com | PayPal |
| support@google.com | Google |

Benefits

- No code changes required
- Easy updates
- Centralized management
- Cloud-hosted configuration

---

# 🛠️ Technology Stack

| Category | Technology |
|-----------|------------|
| Language | Java |
| Frontend | HTML5, CSS3, JavaScript, JSP |
| Backend | Java Servlets |
| Database | Supabase |
| API | VirusTotal v3 |
| Email Parsing | JavaMail API |
| JSON Library | Jackson |
| Build Tool | Maven |
| Web Server | Apache Tomcat |
| IDE | Eclipse IDE |
| Version Control | Git |
| Repository | GitHub |

---

# 📂 Project Structure

```text
WebGuard/
│
├── src/
│   ├── config/
│   ├── filters/
│   ├── integrations/
│   │      ├── VirusTotalClient.java
│   │      └── VirusTotalUrlReport.java
│   │
│   ├── layers/
│   │      ├── Layer1KeywordDetection.java
│   │      ├── Layer2PatternAnalysis.java
│   │      └── Layer3UrlAnalysis.java
│   │
│   ├── models/
│   │      └── EmailAnalysisResult.java
│   │
│   ├── service/
│   │      ├── PhishingDetectionService.java
│   │      └── SenderVerificationService.java
│   │
│   ├── servlet/
│   │      ├── DetectServlet.java
│   │      ├── UrlScanServlet.java
│   │      └── IndexServlet.java
│   │
│   └── utils/
│          ├── UrlExtractor.java
│          └── SecurityUtils.java
│
├── WebContent/
│   ├── css/
│   ├── js/
│   ├── images/
│   ├── index.jsp
│   ├── results.jsp
│   ├── urlscan.jsp
│   └── WEB-INF/
│
├── pom.xml
└── README.md
```

---

# 🚀 Getting Started

Follow the steps below to set up **WebGuard** on your local machine.

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

| Software | Version |
|-----------|---------|
| Java JDK | 17 or above |
| Eclipse IDE | Latest |
| Apache Tomcat | 9.x or above |
| Maven | 3.8+ |
| Git | Latest |
| Supabase Account | Required |
| VirusTotal API Key | Required |

---

# ⚙️ Installation

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/WebGuard.git
```

```bash
cd WebGuard
```

---

## 2️⃣ Import into Eclipse

- Open Eclipse IDE
- File → Import
- Existing Maven Project
- Select the cloned project
- Finish

---

## 3️⃣ Configure Apache Tomcat

1. Open Servers View
2. Add Apache Tomcat
3. Right Click → Add and Remove
4. Add WebGuard
5. Start Server

---

## 4️⃣ Configure Supabase

Create a new project.

### Table 1 : Keywords

| Column | Type |
|----------|------|
| keyword | Text |

Example

| keyword |
|----------|
| Verify Account |
| Update Payment |
| Login |
| OTP |
| Password |

---

### Table 2 : Sender

| Column | Type |
|----------|------|
| trusted_senders | Text |
| Services | Text |

Example

| trusted_senders | Services |
|----------------|-----------|
| support@paypal.com | PayPal |
| support@google.com | Google |
| security@microsoft.com | Microsoft |

---

## 5️⃣ Configure API Keys

Update your configuration file.

```properties
SUPABASE_URL=

SUPABASE_API_KEY=

VIRUSTOTAL_API_KEY=
```

---

## 6️⃣ Build Project

```bash
mvn clean install
```

---

## 7️⃣ Deploy

Run using Tomcat.

Open

```
http://localhost:8080/WebGuard
```

---

# ⚙️ Configuration

The project supports configurable phishing keywords and trusted senders.

| Configuration | Description |
|---------------|-------------|
| VirusTotal API | URL reputation scanning |
| Supabase URL | Cloud Database |
| API Key | Authentication |
| Keywords Table | Dynamic phishing keywords |
| Sender Table | Trusted senders |

---

# 📸 Screenshots

> Replace these placeholders with actual screenshots after uploading images.

## Home Page

```markdown
![Home Page](images/home-page.png)
```

---

## Email Analysis

```markdown
![Email Analysis](images/email-analysis.png)
```

---

## Detection Report

```markdown
![Detection Report](images/report.png)
```

---

## URL Scanner

```markdown
![URL Scanner](images/url-scanner.png)
```

---

## Risk Analysis

```markdown
![Risk Analysis](images/risk-analysis.png)
```

---

# 🎥 Demo

You can also include a GIF showing the application in action.

```markdown
![Demo](images/demo.gif)
```

---

# 🧪 Sample Email Analysis

## Sample Email

```
From:
support@paypal-security.xyz

Subject:
Verify your account immediately

Body:

Dear Customer,

Your PayPal account has been temporarily suspended.

Click below to verify your account.

https://paypal-login-security.xyz/login

Failure to verify within 24 hours will permanently suspend your account.
```

---

## Detection Result

| Layer | Result |
|---------|---------|
| Keyword Detection | ✅ Triggered |
| Pattern Analysis | ✅ Triggered |
| URL Analysis | ✅ Suspicious |
| Sender Verification | ✅ Spoofed |
| VirusTotal | ✅ Malicious |
| Final Risk | 🔴 Dangerous |

---

# 🌐 Sample URL Scan

Input

```
https://paypal-login-security.xyz/login
```

Output

| Check | Result |
|---------|----------|
| HTTPS | Yes |
| Brand Mismatch | Detected |
| Homoglyph | No |
| Suspicious TLD | Yes |
| URL Shortener | No |
| VirusTotal | Malicious |
| Final Score | High Risk |

---

# 📊 Performance Highlights

| Feature | Status |
|-----------|---------|
| Multi-layer Detection | ✅ |
| URL Extraction | ✅ |
| VirusTotal Integration | ✅ |
| Sender Verification | ✅ |
| EML File Support | ✅ |
| URL Scanner | ✅ |
| Dynamic Keywords | ✅ |
| Dynamic Trusted Senders | ✅ |

---

# 🛣️ Roadmap

### Version 1.0

- Email Analysis
- URL Scanner
- VirusTotal Integration
- Supabase Integration

✅ Completed

---

### Version 2.0

- User Authentication
- Scan History
- Dashboard
- Better UI
- Analytics

🚧 Planned

---

### Version 3.0

- Machine Learning Detection
- Browser Extension
- OCR Analysis
- QR Code Detection
- Threat Intelligence Feeds

📌 Future

---

# 🔮 Future Improvements

The current implementation provides a strong rule-based phishing detection system, but there are several enhancements planned for future versions.

### Artificial Intelligence

- Machine Learning phishing classifier
- NLP-based email analysis
- AI-generated phishing detection

---

### Email Authentication

- SPF Validation
- DKIM Verification
- DMARC Checking

---

### Browser Protection

- Chrome Extension
- Firefox Extension
- Edge Extension

---

### Threat Intelligence

- OpenPhish
- PhishTank
- AbuseIPDB
- Google Safe Browsing

---

### Dashboard

- User Login
- Scan History
- Analytics
- Export Reports
- Threat Statistics

---

# 📈 Project Statistics

| Metric | Value |
|---------|--------|
| Language | Java |
| Architecture | Layered |
| Detection Layers | 4 |
| External APIs | 2 |
| Database | Supabase |
| Risk Levels | 3 |
| Supported Input Types | 3 |
| URL Detection | Yes |
| Attachment Analysis | Yes |

---

# ⭐ If You Like This Project

If you found this project useful:

⭐ Star this repository

🍴 Fork it

🛠️ Contribute

📢 Share it with others
---

# 🚧 Challenges Faced

Building WebGuard was much more than implementing phishing detection algorithms. Throughout development, I encountered several real-world software engineering challenges that required research, experimentation, and multiple iterations to solve.

<details>
<summary><b>⚡ VirusTotal API Rate Limits</b></summary>

The free VirusTotal API has strict request limits. Scanning every URL would quickly exhaust the available quota.

**Solution**

- Implemented conditional scanning.
- Only suspicious URLs are sent to VirusTotal.
- Added response caching to avoid duplicate requests.
- Reused existing reports whenever possible.

</details>

---

<details>
<summary><b>📧 Parsing Different Email Formats</b></summary>

Emails can contain:

- Plain text
- HTML
- Embedded images
- Attachments
- MIME multipart content

Handling each format consistently while preserving useful information was one of the biggest technical challenges.

**Solution**

- Used JavaMail API
- Extracted plain text from HTML
- Supported MIME multipart emails
- Added attachment analysis

</details>

---

<details>
<summary><b>🌐 URL Normalization</b></summary>

Attackers often disguise malicious URLs using:

- URL Encoding
- Shorteners
- Multiple redirects
- Long URLs
- IP addresses
- Homoglyph attacks

Normalizing URLs before analysis significantly improved detection accuracy.

</details>

---

<details>
<summary><b>🎯 Reducing False Positives</b></summary>

Initially, relying only on keyword detection caused legitimate emails to be incorrectly flagged.

To solve this:

- Multiple detection layers were introduced.
- Every layer contributes independently.
- Final classification depends on cumulative evidence instead of a single rule.

</details>

---

<details>
<summary><b>⚡ Performance Optimization</b></summary>

Adding more detection logic increased processing time.

Performance improvements included:

- Aho-Corasick keyword matching
- Smart caching
- Conditional VirusTotal scanning
- Efficient URL extraction
- Modular service architecture

</details>

---

# 🎓 Learning Outcomes

Developing WebGuard was one of the most rewarding learning experiences of my engineering journey.

Throughout this project, I gained practical experience in designing and developing a complete Java web application while applying cybersecurity concepts to solve a real-world problem.

Some of the key skills I developed include:

### Java Web Development

- Java Servlets
- JSP
- MVC Architecture
- Apache Tomcat
- Maven

---

### Cybersecurity

- Phishing Detection
- Social Engineering
- URL Security
- Sender Spoofing
- Threat Intelligence
- Email Analysis

---

### Software Engineering

- Layered Architecture
- Clean Code
- Object-Oriented Design
- Exception Handling
- API Integration
- Configuration Management

---

### Tools & Technologies

- Git
- GitHub
- Eclipse
- Supabase
- VirusTotal API
- JavaMail API
- Jackson

---

### Personal Growth

This project also taught me how to:

- Break large problems into smaller components.
- Research unfamiliar technologies.
- Debug complex issues.
- Read technical documentation.
- Build software with maintainability in mind.
- Think from both a developer's and a user's perspective.

---

# 🤝 Contributing

Contributions are welcome!

If you would like to improve WebGuard, please follow these steps:

```bash
# Fork the repository

# Create a new branch

git checkout -b feature/your-feature

# Commit your changes

git commit -m "Add new feature"

# Push your branch

git push origin feature/your-feature

# Open a Pull Request
```

Please ensure that:

- Your code follows the existing project structure.
- New features are documented.
- Existing functionality is not broken.
- Commit messages are meaningful.

---

# 📝 License

This project is licensed under the **MIT License**.

Feel free to use, modify, and extend this project for educational or research purposes.

---

# 🙏 Acknowledgements

I would like to thank everyone who contributed, directly or indirectly, to this project.

Special thanks to:

- My project guide and faculty members for their continuous guidance.
- The open-source community for providing excellent libraries and documentation.
- VirusTotal for offering public threat intelligence APIs.
- Supabase for providing a simple and powerful backend service.
- Oracle for Java and the Java ecosystem.
- Apache Software Foundation for Tomcat.

---

# 👨‍💻 Author

<div align="center">

## **Yash Thubokar**

**Computer Science Engineering Student**

Passionate about Java Development, Cybersecurity, and Backend Engineering.

---

### Connect with Me

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Profile-blue?style=for-the-badge&logo=linkedin)](www.linkedin.com/in/yash037)

[![Email](https://img.shields.io/badge/Email-Contact-red?style=for-the-badge&logo=gmail)](mailto:yashthubokar037@gmail.com)

</div>

---

# 📬 Feedback

If you have suggestions, bug reports, or feature requests, feel free to open an issue or start a discussion.

Your feedback is always appreciated and helps improve the project.

---

# ⭐ Support the Project

If you found this project useful or interesting:

- ⭐ Star this repository
- 🍴 Fork the project
- 🐞 Report issues
- 💡 Suggest new features
- 🤝 Contribute improvements

Every contribution, no matter how small, is appreciated.

---

# 📌 Repository Topics

```text
java
jsp
servlets
cybersecurity
phishing
email-security
virustotal
supabase
url-analysis
java-web
apache-tomcat
maven
engineering-project
network-security
information-security
```

> Add these as GitHub repository topics to improve discoverability.

---

<div align="center">

## 🛡️ WebGuard

### Multi-Level Phishing Detection System

*"Security is not just about detecting threats—it's about understanding them."*

**Developed with Java, curiosity, and a passion for building secure software.**

⭐ **If this project helped you or inspired you, consider giving it a star!** ⭐

---

**© 2026 Yash Thubokar. All Rights Reserved.**

</div>
