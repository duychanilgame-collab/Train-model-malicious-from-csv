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

dataset_dir = os.path.expanduser('~/malware_detection/dataset')
training_data = []
labels = []

print("[*] Starting data scanning...")
for category, label in [('malware', 1), ('benign', 0), ('pups', 1)]:
    folder = os.path.join(dataset_dir, category)
    if not os.path.exists(folder): continue
    
    files = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
    for fname in files:
        try:
            analysis = analyzer.analyze_file(os.path.join(folder, fname))
            training_data.append(analysis)
            labels.append(label)
        except Exception as e:
            print(f"[!] Error {fname}: {e}")

if not training_data:
    print("[❌] No training data found!")
    exit()

# Run comprehensive Training & Evaluation pipeline
classifier.train_and_evaluate(training_data, labels)

# Save entire classifier (including Vectorizer + Model)
model_path = os.path.expanduser('~/malware_detection/model_full.pkl')
joblib.dump(classifier, model_path)
print(f"[✓] Model pipeline saved at: {model_path}")