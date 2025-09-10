import os
import json
from static_analyzer import StaticAnalyzer
from ml_classifier import MLMalwareClassifier

# Load config
config_path = os.path.expanduser('~/malware_detection/config.json')
with open(config_path) as f:
    config = json.load(f)

analyzer = StaticAnalyzer(config)
classifier = MLMalwareClassifier(config)

import joblib
model_path = os.path.expanduser('~/malware_detection/model.pkl')
if not os.path.exists(model_path):
    raise FileNotFoundError(f"❌ Không tìm thấy mô hình: {model_path}. Hãy chạy train_ml.py trước.")
classifier.classifier = joblib.load(model_path)

dataset_dir = os.path.expanduser('~/malware_detection/dataset')
results = []

# Quét 3 thư mục
for category in ['malware', 'benign', 'pups']:
    folder = os.path.join(dataset_dir, category)
    if not os.path.exists(folder):
        print(f"[!] Bỏ qua thư mục không tồn tại: {folder}")
        continue
    for fname in os.listdir(folder):
        file_path = os.path.join(folder, fname)
        if not os.path.isfile(file_path):
            continue
        try:
            analysis = analyzer.analyze_file(file_path)
            risk = analysis['risk_assessment']
            prediction = classifier.predict(analysis)
            results.append({
                'file': fname,
                'category': category,
                'risk': risk,
                'ml_prediction': prediction
            })
        except Exception as e:
            print(f"[!] Lỗi khi xử lý {file_path}: {e}")

# Ghi file kết quả
output_path = os.path.expanduser('~/malware_detection/results.json')
with open(output_path, 'w') as f:
    json.dump(results, f, indent=2)

print(f"[✓] Phân tích hoàn tất. Đã lưu vào {output_path}")

