# 🛡️ WebGuard – Multi-Level Phishing Detection System

A Java-based web application that detects phishing emails and malicious URLs using multiple independent detection layers instead of relying on a single detection technique.

Built as a Final Year B.E. Computer Science Engineering project using Java Web Technologies.

![Java](https://img.shields.io/badge/Java-17-orange)
![JSP](https://img.shields.io/badge/JSP-Web_App-blue)
![Servlets](https://img.shields.io/badge/Servlets-Jakarta-red)
![Tomcat](https://img.shields.io/badge/Apache_Tomcat-9-yellow)
![Supabase](https://img.shields.io/badge/Supabase-Database-green)
![VirusTotal](https://img.shields.io/badge/VirusTotal-v3-blue)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📖 About

Phishing attacks often bypass traditional filters by avoiding obvious keywords. WebGuard improves detection by combining multiple independent analysis layers, including keyword detection, pattern analysis, URL inspection, sender verification, and VirusTotal integration.

The application analyzes uploaded `.eml` email files and manually entered URLs, then generates an explainable phishing risk score with a final classification of **Safe**, **Suspicious**, or **Dangerous**.

---

## ✨ Features

- Upload and analyze `.eml` email files
- Manual URL Scanner
- Multi-layer phishing detection
- Keyword Detection (Aho-Corasick)
- Pattern Analysis using Regular Expressions
- URL Analysis
- Trusted Sender Verification
- VirusTotal API Integration
- Dynamic phishing keywords using Supabase
- Dynamic risk score calculation
- Detailed detection reports
- Safe / Suspicious / Dangerous classification

---

## 🛠️ Technology Stack

| Category | Technology |
|----------|------------|
| Language | Java |
| Frontend | HTML, CSS, JavaScript, JSP |
| Backend | Java Servlets, JDBC |
| Database | MySQL, Supabase |
| Libraries | JavaMail API, Jackson |
| API | VirusTotal API v3 |
| Server | Apache Tomcat |
| IDE | Eclipse IDE |
| Project Type | Eclipse Dynamic Web Project |
| Version Control | Git, GitHub |

---

## 🏗️ Detection Workflow

```text
User Input
      │
      ▼
Email Processing
      │
      ▼
Keyword Detection
      │
      ▼
Pattern Analysis
      │
      ▼
URL Analysis
      │
      ▼
Sender Verification
      │
      ▼
VirusTotal Verification (If Required)
      │
      ▼
Risk Score Calculation
      │
      ▼
Detection Report
```

---

## 📂 Project Structure

```text
WebGuard/
│
├── src/
│   ├── servlet/
│   ├── service/
│   ├── layers/
│   ├── integrations/
│   ├── utils/
│   └── models/
│
├── WebContent/
│   ├── css/
│   ├── js/
│   ├── images/
│   ├── index.jsp
│   ├── results.jsp
│   └── WEB-INF/
│
└── README.md
```

---

## 🚀 Getting Started

1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/WebGuard.git
```

2. Import the project into Eclipse as an **Existing Project**.

3. Configure **Apache Tomcat**.

4. Configure **MySQL**, **Supabase**, and **VirusTotal API** credentials.

5. Deploy the project and run it using Tomcat.

---

## 🎯 Sample Detection

**Input**

```
From: support@paypal-security.xyz

Subject: Verify Your Account

https://paypal-login-security.xyz
```

**Result**

| Layer | Status |
|------|---------|
| Keyword Detection | ✅ |
| Pattern Analysis | ✅ |
| URL Analysis | ✅ |
| Sender Verification | ✅ |
| VirusTotal | ✅ |

**Final Classification**

🔴 **Dangerous**

---

## 🚧 Challenges Faced

- Parsing different email formats using JavaMail API
- Integrating VirusTotal API
- Managing API rate limits
- URL normalization
- Reducing false positives
- Designing a modular layered architecture
- Backend debugging
- Database integration using MySQL and Supabase

---

## 📚 Learning Outcomes

Through this project I gained practical experience with:

- Java Web Development
- Servlets and JSP
- JDBC
- REST API Integration
- JavaMail API
- Backend Architecture
- Cybersecurity Concepts
- Modular Software Design
- Git & GitHub
- Debugging and Documentation

---

## 🔮 Future Improvements

- Machine Learning based phishing detection
- Browser Extension
- Scan History Dashboard
- User Authentication
- Threat Analytics
- SPF, DKIM, and DMARC validation

---

## 👨‍💻 Author

## 👨‍💻 Team

**Core Java Development Team**

Final Year B.E. Computer Science Engineering Students  

Focused on **Java Development**, **Backend Engineering**, and **Collaborative Software Projects**.  

### Members
- **Yash Thubokar**
- **Abhijeet Kisharsagar**
-  **Vivek Ingole**
-  **Ayush Bhagat**
  
---

