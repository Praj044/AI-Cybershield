# 🛡️ AI CyberShield

### 🚀 AI-Powered Real-Time Cybersecurity System

AI CyberShield is a **hybrid AI-based cybersecurity platform** that detects, analyzes, and prevents cyber threats such as phishing attacks, malicious URLs, and weak passwords using Machine Learning, NLP, Generative AI, and threat intelligence APIs.

---
## 🎥 Demo

🔗 [Click to Watch Demo Video](https://drive.google.com/file/d/1WKN7hKyOXHBFVC2OlNT4OnJekIhvUHKs/view?usp=sharing)

## 📌 Problem Statement

Cyber attacks like phishing, malicious links, and credential theft are increasing rapidly.
Traditional security systems are often **reactive, slow, and limited to single-layer detection**.

👉 There is a need for a **real-time, intelligent, and multi-layer cybersecurity solution**.

---

## 💡 Solution

AI CyberShield provides a **multi-layer AI defense system** that:

* 🔍 Detects phishing emails using ML models
* 🧠 Analyzes social engineering patterns using NLP
* 🤖 Uses Generative AI for contextual reasoning
* 🔗 Scans URLs using global threat intelligence APIs
* 🔐 Evaluates password strength using probabilistic models
* 📊 Generates a unified cybersecurity risk score (0–100)

---

## 🧠 AI Architecture

AI CyberShield uses a **Hybrid AI Approach**:

* **Supervised Machine Learning** → Phishing detection (TF-IDF + Logistic Regression)
* **Rule-Based NLP** → Behavioral & linguistic threat analysis
* **Generative AI (Gemini API)** → Context-aware reasoning
* **Threat Intelligence APIs** → Real-world security validation

---

## ⚡ Key Features

* ✅ Real-time threat detection
* ✅ Multi-layer security analysis
* ✅ Parallel processing using ThreadPoolExecutor
* ✅ AI-powered phishing detection
* ✅ URL safety analysis (VirusTotal + URLhaus)
* ✅ Password strength evaluation (zxcvbn)
* ✅ Unified risk scoring engine
* ✅ Interactive Streamlit dashboard

---

## 🏗️ Architecture Overview

* **Frontend:** Streamlit Dashboard
* **Processing:** Parallel execution (5 workers)
* **Core Modules:** ML, NLP, AI Engine, URL Analyzer, Password Checker
* **Output:** Risk Score + Security Insights

---

## ⚙️ Tech Stack

### 🖥️ Language

* Python 3.x

### 🤖 Machine Learning & AI

* Scikit-learn (TF-IDF, Logistic Regression, FeatureUnion)
* Google Gemini API (gemini-2.0-flash / gemini-1.5-flash)

### 🌐 Backend & Framework

* Streamlit
* ThreadPoolExecutor

### 📊 Data Processing & Security

* zxcvbn
* Custom NLP Engine
* URLhaus API
* VirusTotal API
* validators

### 🔐 Utilities

* python-dotenv
* requests

---

## 📁 Project Structure

```bash
AI-CyberShield/
│
├── app.py
├── ai_engine.py
├── link_analyzer.py
├── ml_phishing.py
├── phishing_nlp.py
├── password_checker.py
├── score_calculator.py
├── requirements.txt
├── .env.example
└── README.md
```

---

## ▶️ How to Run

### 1. Clone Repository

```bash
git clone https://github.com/Praj044/AI-Cybershield.git
cd AI-Cybershield
```

### 2. Create Virtual Environment

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Setup Environment Variables

Create `.env` file:

```env
GEMINI_API_KEY=your_key_here
VT_API_KEY=your_key_here
```

### 5. Run Application

```bash
streamlit run app.py
```

---

## 🔐 Security

* API keys are stored securely using **environment variables**
* `.env` file is excluded via `.gitignore`
* No sensitive credentials are exposed in the repository

---

## 📊 Use Cases

* 🏦 Banking & Financial Security
* 🏢 Enterprise Cybersecurity
* 🌐 Web Application Security
* 👤 Personal Security Tools

---

## ⚡ Innovation / USP

* 🔥 Hybrid AI (ML + NLP + Generative AI)
* 🔥 Multi-layer cybersecurity architecture
* 🔥 Parallel processing for real-time performance
* 🔥 Unified risk scoring system
* 🔥 Scalable and modular design

---

## 🔮 Future Scope

* Integration with IoT security
* Advanced deep learning models
* Real-time monitoring dashboard
* Cloud deployment (AWS / GCP)

---

## 👥 Team

**Prajjwal Gupta**
**Aarohi Patel**
**Alok Kumar**

---

## ⭐ Support

If you like this project, consider giving it a ⭐ on GitHub!

---
