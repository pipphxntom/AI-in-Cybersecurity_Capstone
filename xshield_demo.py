"""
XShield-Enterprise Prototype Demo
Hybrid Explainable Ensemble Threat Detection System

This script demonstrates:
1. Synthetic network flow feature generation
2. Isolation Forest anomaly detection + Stacked Ensemble classification
3. SHAP-based explanations
4. Simple adversarial perturbation simulation

Author: Shwetank Pandey
Capstone: AI in Cybersecurity (2026)
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
import shap
import warnings
warnings.filterwarnings('ignore')

np.random.seed(42)

# -----------------------------
# 1. Synthetic Data Generation
# -----------------------------
def generate_synthetic_flows(n_samples=5000):
    """Generate synthetic network flow features mimicking enterprise traffic."""
    n_normal = int(n_samples * 0.7)
    n_ddos = int(n_samples * 0.08)
    n_portscan = int(n_samples * 0.07)
    n_malware = int(n_samples * 0.08)
    n_exfil = int(n_samples * 0.07)
    
    features = []
    labels = []
    
    # Normal traffic
    for _ in range(n_normal):
        features.append([
            np.random.normal(50, 15),      # packet_rate
            np.random.normal(2000, 500),   # byte_rate
            np.random.exponential(10),     # flow_duration
            np.random.normal(5, 2),        # unique_dst_ports
            np.random.uniform(0.1, 0.4),   # bytes_out_ratio
            np.random.normal(0.05, 0.02),  # failed_login_ratio
            np.random.randint(8, 20),      # hour_of_day
            np.random.normal(0.3, 0.1),    # inter_arrival_var
        ])
        labels.append(0)  # Normal
    
    # DDoS
    for _ in range(n_ddos):
        features.append([
            np.random.normal(500, 100),
            np.random.normal(50000, 10000),
            np.random.exponential(2),
            np.random.normal(1, 0.5),
            np.random.uniform(0.8, 0.99),
            0.0,
            np.random.randint(0, 24),
            np.random.normal(0.05, 0.02),
        ])
        labels.append(1)  # DDoS
    
    # Port Scan
    for _ in range(n_portscan):
        features.append([
            np.random.normal(80, 20),
            np.random.normal(500, 100),
            np.random.exponential(5),
            np.random.normal(40, 10),
            np.random.uniform(0.2, 0.5),
            np.random.uniform(0.3, 0.7),
            np.random.randint(0, 24),
            np.random.normal(0.8, 0.2),
        ])
        labels.append(2)  # PortScan
    
    # Malware C2 / Beaconing
    for _ in range(n_malware):
        features.append([
            np.random.normal(30, 8),
            np.random.normal(800, 200),
            np.random.exponential(30),
            np.random.normal(1.5, 0.5),
            np.random.uniform(0.4, 0.7),
            0.0,
            np.random.randint(0, 24),
            np.random.normal(0.02, 0.01),  # low variance = periodic
        ])
        labels.append(3)  # Malware C2
    
    # Data Exfiltration
    for _ in range(n_exfil):
        features.append([
            np.random.normal(40, 10),
            np.random.normal(15000, 5000),
            np.random.exponential(20),
            np.random.normal(2, 1),
            np.random.uniform(0.85, 0.98),  # high outbound
            np.random.uniform(0.1, 0.4),
            np.random.choice([0, 1, 2, 3, 22, 23]),  # odd hours
            np.random.normal(0.4, 0.15),
        ])
        labels.append(4)  # Exfiltration
    
    feature_names = [
        'packet_rate', 'byte_rate', 'flow_duration', 'unique_dst_ports',
        'bytes_out_ratio', 'failed_login_ratio', 'hour_of_day', 'inter_arrival_var'
    ]
    
    df = pd.DataFrame(features, columns=feature_names)
    df['label'] = labels
    return df, feature_names

# -----------------------------
# 2. Train Models
# -----------------------------
print("Generating synthetic enterprise network flow data...")
df, feature_names = generate_synthetic_flows(4000)
X = df[feature_names]
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Stage 1: Anomaly Detection (Isolation Forest on normal traffic)
print("\nTraining Isolation Forest (anomaly detection)...")
normal_mask = y_train == 0
iso_forest = IsolationForest(contamination=0.1, random_state=42)
iso_forest.fit(X_train_scaled[normal_mask])

# Stage 2: Stacked Ensemble
print("Training Stacked Ensemble Classifier...")
estimators = [
    ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
    ('xgb', xgb.XGBClassifier(n_estimators=100, use_label_encoder=False, eval_metric='mlogloss', random_state=42))
]
stack = StackingClassifier(
    estimators=estimators,
    final_estimator=LogisticRegression(max_iter=500),
    cv=3
)
stack.fit(X_train_scaled, y_train)

# Evaluation
y_pred = stack.predict(X_test_scaled)
print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred, target_names=['Normal', 'DDoS', 'PortScan', 'MalwareC2', 'Exfil']))
print(f"Overall Accuracy: {accuracy_score(y_test, y_pred):.3f}")

# -----------------------------
# 3. SHAP Explanations
# -----------------------------
print("\n=== Generating SHAP Explanations ===")
explainer = shap.TreeExplainer(stack.estimators_[0])  # Use RF for tree explainer
# For a sample high-risk prediction
sample_idx = np.where(y_test == 4)[0][0]  # first exfil sample
sample = X_test_scaled[sample_idx:sample_idx+1]
shap_values = explainer.shap_values(sample)

print(f"\nExample Alert Explanation (sample index {sample_idx}):")
print(f"True label: Exfiltration | Predicted: {['Normal','DDoS','PortScan','MalwareC2','Exfil'][y_pred[sample_idx]]}")
print("\nTop contributing features (SHAP):")
feature_importance = list(zip(feature_names, shap_values[0] if isinstance(shap_values, list) else shap_values[0]))
feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)
for feat, val in feature_importance[:5]:
    direction = "increases risk" if val > 0 else "decreases risk"
    print(f"  • {feat}: {val:.3f} ({direction})")

# -----------------------------
# 4. Simple Adversarial Simulation
# -----------------------------
print("\n=== Adversarial Perturbation Simulation ===")
# Perturb packet_rate and byte_rate slightly on a malicious sample
adv_sample = sample.copy()
adv_sample[0, 0] *= 0.7   # reduce packet_rate
adv_sample[0, 1] *= 0.6   # reduce byte_rate
adv_pred = stack.predict(adv_sample)
print(f"Original prediction: {['Normal','DDoS','PortScan','MalwareC2','Exfil'][y_pred[sample_idx]]}")
print(f"After small perturbation: {['Normal','DDoS','PortScan','MalwareC2','Exfil'][adv_pred[0]]}")
print("Note: In a real system, adversarial training + feature clipping would reduce this vulnerability.")

print("\n=== Demo Complete ===")
print("This prototype illustrates the core ideas of XShield-Enterprise.")
print("In production: replace synthetic data with real NetFlow/Zeek logs,")
print("add more features, adversarial training, and a proper alerting UI.")
