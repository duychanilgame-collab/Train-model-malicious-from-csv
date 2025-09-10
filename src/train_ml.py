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

dataset_dir = os.path.expanduser('~/malware_detection/dataset')

training_data = []
labels = []

# Đọc các file từ 3 thư mục
for category, label in [('malware', 1), ('benign', 0), ('pups', 1)]:
    folder = os.path.join(dataset_dir, category)
    for fname in os.listdir(folder):
        file_path = os.path.join(folder, fname)
        if not os.path.isfile(file_path):
            continue
        try:
            analysis = analyzer.analyze_file(file_path)
            training_data.append(analysis)
            labels.append(label)
        except Exception as e:
            print(f"[!] Lỗi khi xử lý {file_path}: {e}")

# Huấn luyện
classifier.train(training_data, labels)
print("[✓] Huấn luyện hoàn tất.")

import joblib
joblib.dump(classifier.classifier, os.path.expanduser('~/malware_detection/model.pkl'))


