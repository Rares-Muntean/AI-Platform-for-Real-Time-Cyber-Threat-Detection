import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

print("Loading hybrid dataset...")
df = pd.read_csv("../datasets/classifier_data.csv")
df.dropna(inplace=True)

features =[
    'dest_port', 'protocol', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean',
    'pkt_len_mean', 'flow_iat_mean', 'down_up_ratio',
    'fin_flag', 'syn_flag', 'rst_flag', 'psh_flag', 'ack_flag'
]

X = df[features].values
y = df['Label'].values

print("Splitting data...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("Training Random Forest Classifier (This takes ~1 minute)...")
clf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

print("Evaluating Model...")
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

print("Saving Classifier...")
os.makedirs("../models", exist_ok=True)
joblib.dump(clf, "../models/classifier.pkl")
print("Classifier successfully saved to models/classifier.pkl!")