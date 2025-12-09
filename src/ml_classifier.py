import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.ensemble import RandomForestClassifier

# Try importing XGBoost (Requirement)
try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("[WARN] XGBoost not installed. Using Random Forest instead.")

class MLMalwareClassifier:
    def __init__(self, config):
        # 1. Feature Vectorization: TF-IDF for API Calls
        self.vectorizer = TfidfVectorizer(max_features=1000, token_pattern=r'(?u)\b\w+\b')
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # 2. Model Selection: XGBoost or Random Forest
        if HAS_XGBOOST:
            self.model = XGBClassifier(
                n_estimators=100, 
                eval_metric='logloss',
                use_label_encoder=False,
                random_state=42
                # scale_pos_weight can be added here for data balancing
            )
            self.model_name = "XGBoost"
        else:
            self.model = RandomForestClassifier(
                n_estimators=100, 
                random_state=42, 
                class_weight='balanced' # 3. Data Balancing
            )
            self.model_name = "Random Forest"

    def _extract_features(self, analysis_list, fit=False):
        """Combine Numerical features and Text (API) features"""
        # A. Numerical Features (Entropy, PE info, YARA)
        X_num = []
        # B. Text Features (API Calls)
        X_text = []

        for res in analysis_list:
            # Get numerical info
            entropy = res.get('entropy_analysis', {}).get('overall_entropy', 0)
            is_pe = 1 if res.get('pe_analysis', {}).get('is_pe', False) else 0
            susp_imports = res.get('pe_analysis', {}).get('suspicious_import_count', 0)
            yara_matches = res.get('yara_analysis', {}).get('match_count', 0)
            X_num.append([entropy, is_pe, susp_imports, yara_matches])
            
            # Get text info
            X_text.append(res.get('api_call_text', ""))

        X_num = np.array(X_num)
        
        # Process Vectorization (TF-IDF)
        if fit:
            X_text_vec = self.vectorizer.fit_transform(X_text).toarray()
            X_num = self.scaler.fit_transform(X_num)
        else:
            X_text_vec = self.vectorizer.transform(X_text).toarray()
            X_num = self.scaler.transform(X_num)
            
        # Combine into complete feature vector
        return np.hstack((X_num, X_text_vec))

    def train_and_evaluate(self, training_data, labels):
        print(f"[*] Extracting features and Vectorizing (TF-IDF + Scaling)...")
        X = self._extract_features(training_data, fit=True)
        y = np.array(labels)

        # Split Data (Train/Test Split)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        print(f"[*] Training model {self.model_name}...")
        self.model.fit(X_train, y_train)
        self.is_trained = True

        # 4. Model Evaluation (Evaluation Metrics)
        y_pred = self.model.predict(X_test)
        
        print("\n" + "="*50)
        print(f"PERFORMANCE EVALUATION REPORT ({self.model_name})")
        print("="*50)
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print("-" * 30)
        print("Detailed Metrics (Precision, Recall, F1-score):")
        print(classification_report(y_test, y_pred, target_names=['Benign', 'Malware']))
        print("-" * 30)
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        print("="*50 + "\n")

    def predict(self, analysis_result):
        if not self.is_trained:
            raise Exception("Model not trained!")
        
        X = self._extract_features([analysis_result], fit=False)
        pred = self.model.predict(X)[0]
        prob = np.max(self.model.predict_proba(X)[0]) * 100
        
        return {'prediction': int(pred), 'confidence': round(prob, 2), 'model': self.model_name}