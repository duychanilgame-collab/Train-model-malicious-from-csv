import os
import json
import joblib
from static_analyzer import StaticAnalyzer
from ml_classifier import MLMalwareClassifier

# Load config
config_path = os.path.expanduser('~/malware_detection/config.json')
with open(config_path) as f:
    config = json.load(f)

analyzer = StaticAnalyzer(config)
classifier = MLMalwareClassifier(config)

model_path = os.path.expanduser('~/malware_detection/model.pkl')
if not os.path.exists(model_path):
    raise FileNotFoundError(f"❌ Model not found: {model_path}. Please run train_ml.py first.")
    
classifier.classifier = joblib.load(model_path)

dataset_dir = os.path.expanduser('~/malware_detection/dataset')
results = []

print("[*] Starting batch analysis...")

# Scan directories
for category in ['malware', 'benign', 'pups']:
    folder = os.path.join(dataset_dir, category)
    if not os.path.exists(folder):
        print(f"[!] Skipping missing folder: {folder}")
        continue
        
    for fname in os.listdir(folder):
        file_path = os.path.join(folder, fname)
        if not os.path.isfile(file_path):
            continue
        try:
            analysis = analyzer.analyze_file(file_path)
            # Risk is now part of ML prediction context usually, 
            # but we can keep basic risk info if needed
            prediction = classifier.predict(analysis)
            
            results.append({
                'file': fname,
                'category': category,
                'ml_prediction': prediction
            })
        except Exception as e:
            print(f"[!] Error processing {file_path}: {e}")

# Save results
output_path = os.path.expanduser('~/malware_detection/results.json')
with open(output_path, 'w') as f:
    json.dump(results, f, indent=2)

print(f"[✓] Analysis complete. Results saved to {output_path}")