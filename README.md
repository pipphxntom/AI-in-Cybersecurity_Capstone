# XShield-Enterprise

**A Hybrid Explainable Ensemble AI System for Threat Detection and Prevention in Mid-Sized Enterprises**

Capstone Project – AI in Cybersecurity  
Author: Shwetank Pandey  
Date: November 2026

## Overview

This repository contains the design and prototype implementation of **XShield-Enterprise**, a comprehensive AI-based threat detection system designed for mid-sized organizations.

The system combines:
- Unsupervised anomaly detection (Isolation Forest) for novel threats
- Supervised stacked ensemble (Random Forest + XGBoost + Logistic Regression meta-learner) for multi-class classification
- SHAP-based explainability for both technical analysts and non-technical stakeholders
- Defenses against adversarial evasion attacks

## Key Deliverables

- **Design Report**: Full PDF available separately (covers Executive Summary, Threat Model, System Architecture, Feature Engineering, Adversarial Robustness, XAI demonstration, and Ethics).
- **Prototype Code**: `xshield_demo.py` – working demonstration with synthetic data
- This README

## Top-5 Threats Addressed

1. Phishing-induced credential theft & anomalous logins
2. Ransomware / Malware C2 beaconing
3. DDoS / volumetric attacks
4. Insider threats & data exfiltration
5. Lateral movement & privilege escalation

## How to Run the Prototype

```bash
pip install -r requirements.txt
python xshield_demo.py
```

The script generates synthetic network flow data, trains the hybrid models, prints classification metrics, shows a SHAP explanation for a high-risk sample, and demonstrates a simple adversarial perturbation.

## Research Inspiration

The design draws from recent literature on:
- Hybrid ensemble models with SHAP/LIME for intrusion detection
- Adversarial robustness evaluations of NIDS on datasets such as UNSW-NB15 and CICIDS
- Frameworks that combine explainability with adversarial defense (e.g., X-AdvIDS style approaches)

## Ethical Note

Continuous behavioral monitoring raises legitimate privacy concerns. The design explicitly addresses purpose limitation, transparency, and human oversight requirements.

---

*This is an academic capstone project. The prototype uses synthetic data for demonstration purposes.*
