from sklearn.ensemble import RandomForestClassifier
import numpy as np

class MLMalwareClassifier:
    def __init__(self, config):
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.feature_names = ['entropy', 'is_pe', 'yara_matches']

    def extract_features(self, analysis_results):
        return np.array([
            analysis_results['entropy_analysis']['overall_entropy'],
            1 if analysis_results['pe_analysis'].get('is_pe', False) else 0,
            analysis_results['yara_analysis']['match_count']
        ]).reshape(1, -1)

    def train(self, training_data, labels):
        X = np.vstack([self.extract_features(data) for data in training_data])
        self.classifier.fit(X, labels)

    def predict(self, analysis_results):
        features = self.extract_features(analysis_results)
        return {'prediction': int(self.classifier.predict(features)[0])}
