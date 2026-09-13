import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report
import joblib

from feature_extractor import extract_url_features

# Relative file paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, 'dataset', 'url_dataset.csv')
MODEL_SAVE_PATH = os.path.join(BASE_DIR, 'saved_models', 'phishing_model.pkl')

FEATURE_NAMES = [
    "1. Uses IP Address", "2. URL Length", "3. Has '@' Symbol", "4. Double Slash Path",
    "5. Hyphen Count in Domain", "6. Subdomain Depth", "7. Is HTTPS", "8. Deceptive SSL Keyword",
    "9. Is URL Shortener", "10. Suspicious Keyword Count", "11. Brand Spoofed", "12. High Risk TLD",
    "13. Shannon Entropy", "14. Special Char Count", "15. Non-Standard Port", "16. Has Punycode (xn--)",
    "17. Query Parameter Count", "18. Suspicious File Extension"
]

print("1. Loading dataset...")
df = pd.read_csv(DATASET_PATH)

# Convert labels: legitimate = 0, phishing = 1
df['label'] = df['type'].map({'legitimate': 0, 'phishing': 1})

# Sample 10,000 URLs for training (5,000 legitimate, 5,000 phishing)
phish_sample = df[df['label'] == 1].sample(n=5000, random_state=42)
legit_sample = df[df['label'] == 0].sample(n=5000, random_state=42)
df_sample = pd.concat([phish_sample, legit_sample]).sample(frac=1, random_state=42).reset_index(drop=True)

print("2. Extracting features from 10,000 URLs...")
X_raw = np.array([extract_url_features(url) for url in df_sample['url']])
y = df_sample['label'].values

print("3. Splitting dataset into Train (70%), Validation (15%), and Test (15%)...")
X_temp, X_test, y_temp, y_test = train_test_split(X_raw, y, test_size=0.15, random_state=42, stratify=y)
X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.1765, random_state=42, stratify=y_temp)

print("4. Running feature selection (SelectFromModel)...")
base_rf = RandomForestClassifier(n_estimators=100, random_state=42)
base_rf.fit(X_train, y_train)

selector = SelectFromModel(base_rf, threshold="mean", prefit=True)
selected_mask = selector.get_support()

print("\n--- Feature Selection Results ---")
for name, is_kept, importance in zip(FEATURE_NAMES, selected_mask, base_rf.feature_importances_):
    status = "KEPT" if is_kept else "DROPPED"
    print(f"  {name:<32} | Importance: {importance*100:5.2f}% | Status: {status}")

print(f"\nRetained {sum(selected_mask)} of 18 features based on importance threshold.\n")

# Create pipeline with feature selector and classifier
final_pipeline = Pipeline([
    ('feature_selector', selector),
    ('classifier', RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42))
])

print("5. Training Random Forest model on selected features...")
final_pipeline.fit(X_train, y_train)

print("\n--- Validation Accuracy ---")
val_preds = final_pipeline.predict(X_val)
print(f"Validation Score: {accuracy_score(y_val, val_preds) * 100:.2f}%")

print("\n--- Final Test Set Performance ---")
test_preds = final_pipeline.predict(X_test)
test_acc = accuracy_score(y_test, test_preds)
print(f"Test Accuracy: {test_acc * 100:.2f}%\n")

print("Classification Report:")
print(classification_report(y_test, test_preds, target_names=['Legitimate (0)', 'Phishing (1)']))

# Ensure output directory exists before saving
os.makedirs(os.path.dirname(MODEL_SAVE_PATH), exist_ok=True)

print("6. Saving trained model file...")
joblib.dump(final_pipeline, MODEL_SAVE_PATH)
print(f"Successfully saved model to: {MODEL_SAVE_PATH}")
