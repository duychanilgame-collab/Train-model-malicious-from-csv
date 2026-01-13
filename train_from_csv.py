#!/usr/bin/env python3
"""
Train ML model using pre-extracted features from CSV
"""
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import os

# Load data
csv_path = os.path.expanduser('~/malware_detection/dataset/data_with_features.csv')
print(f"[*] Loading data from: {csv_path}")

df = pd.read_csv(csv_path)
print(f"[✓] Loaded {len(df)} samples")
print(f"[*] Columns: {len(df.columns)}")
print(f"[*] Target column: 'target'")

# Check for missing values
print(f"\n[*] Missing values: {df.isnull().sum().sum()}")

# Prepare features and labels
# Exclude non-numeric columns and target
exclude_cols = ['protocol', 'remote_ip', 'local_ip', 'md5_hash', 'sha512_hash', 'data_hex', 'class', 'target']
feature_cols = [col for col in df.columns if col not in exclude_cols and col not in ['target']]

X = df[feature_cols].copy()
y = df['target'].copy()

print(f"\n[*] Features: {len(feature_cols)}")
print(f"[*] Samples: {len(X)}")
print(f"[*] Class distribution: {y.value_counts().to_dict()}")

# Handle any remaining NaN values
X = X.fillna(0)

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\n[*] Training set: {len(X_train)} samples")
print(f"[*] Test set: {len(X_test)} samples")

# Scale features
print(f"\n[*] Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train Random Forest
print(f"\n[*] Training Random Forest Classifier...")
rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    class_weight='balanced',
    n_jobs=-1
)

rf_model.fit(X_train_scaled, y_train)
print(f"[✓] Model trained")

# Evaluation
print(f"\n[*] Evaluating model...")
y_pred = rf_model.predict(X_test_scaled)
y_pred_proba = rf_model.predict_proba(X_test_scaled)[:, 1]

accuracy = accuracy_score(y_test, y_pred)
auc_score = roc_auc_score(y_test, y_pred_proba)

print(f"\n[✓] Accuracy: {accuracy:.4f}")
print(f"[✓] AUC Score: {auc_score:.4f}")
print(f"\n[*] Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Benign', 'Malware']))

print(f"\n[*] Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# Cross-validation
cv_scores = cross_val_score(rf_model, X_train_scaled, y_train, cv=5, scoring='accuracy')
print(f"\n[*] Cross-validation scores: {cv_scores}")
print(f"[*] Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

# Save model and scaler
model_dir = os.path.expanduser('~/malware_detection')
model_path = os.path.join(model_dir, 'model_rf.pkl')
scaler_path = os.path.join(model_dir, 'scaler.pkl')

joblib.dump(rf_model, model_path)
joblib.dump(scaler, scaler_path)

print(f"\n[✓] Model saved to: {model_path}")
print(f"[✓] Scaler saved to: {scaler_path}")

# Feature importance
print(f"\n[*] Top 10 important features:")
feature_importance = pd.DataFrame({
    'feature': feature_cols,
    'importance': rf_model.feature_importances_
}).sort_values('importance', ascending=False)

for idx, row in feature_importance.head(10).iterrows():
    print(f"  {row['feature']}: {row['importance']:.4f}")

print(f"\n[✓] Training completed!")
