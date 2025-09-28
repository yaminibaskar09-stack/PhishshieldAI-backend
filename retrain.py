import pandas as pd
import joblib
import sqlite3
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from model.feature_extractor import extract_url_features

# Paths
DATASET_PATH = "data/master_urls.csv"
DB_PATH = "data/app.db"
MODEL_PATH = "model/url_model.pkl"
COLS_PATH = "model/model_columns.pkl"

print("🔄 Starting retraining process...")

# ================================
# 1. Load base dataset
# ================================
try:
    df_main = pd.read_csv(DATASET_PATH).dropna(subset=["url", "label"])
    print(f"✅ Loaded {len(df_main)} rows from {DATASET_PATH}")
except FileNotFoundError:
    print("⚠️ No master_urls.csv found, starting with empty dataset")
    df_main = pd.DataFrame(columns=["url", "label"])

# ================================
# 2. Load new data from SQLite DB
# ================================
conn = sqlite3.connect(DB_PATH)

# Load history table
try:
    df_hist = pd.read_sql_query("SELECT url, verdict FROM history", conn)
    df_hist["label"] = df_hist["verdict"].map({
        "Legitimate": 0,
        "Phishing": 1,
        "Suspicious": 1  # treat suspicious as risky
    })
    df_hist = df_hist.dropna(subset=["label"])[["url", "label"]]
    print(f"✅ Loaded {len(df_hist)} rows from history")
except Exception as e:
    print("⚠️ Could not load from history:", e)
    df_hist = pd.DataFrame(columns=["url", "label"])

# Load retrain_data table if exists
try:
    df_retrain = pd.read_sql_query("SELECT url, label FROM retrain_data", conn)
    print(f"✅ Loaded {len(df_retrain)} rows from retrain_data")
except Exception as e:
    print("⚠️ Could not load from retrain_data:", e)
    df_retrain = pd.DataFrame(columns=["url", "label"])

conn.close()

# ================================
# 3. Merge datasets
# ================================
df_all = pd.concat([df_main, df_hist, df_retrain]).drop_duplicates(subset=["url"])

# 🔑 Ensure labels are only 0 or 1
df_all = df_all.dropna(subset=["label"])
df_all["label"] = df_all["label"].astype(int)

print(f"📊 Total combined dataset size: {len(df_all)}")

# Save updated master dataset
df_all.to_csv(DATASET_PATH, index=False)

# ================================
# 4. Feature extraction
# ================================
features = [extract_url_features(u) for u in df_all["url"]]
X = pd.DataFrame(features)
X = pd.get_dummies(X, columns=["suffix"])
y = df_all["label"]

# ================================
# 5. Train/test split
# ================================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ================================
# 6. Train model
# ================================
model = RandomForestClassifier(n_estimators=150, random_state=42)
model.fit(X_train, y_train)

# ================================
# 7. Save model + columns
# ================================
joblib.dump(model, MODEL_PATH)
joblib.dump(list(X.columns), COLS_PATH)

print("✅ Model retrained and saved successfully.")
print("🎯 Training accuracy:", round(model.score(X_train, y_train) * 100, 2), "%")
print("🎯 Test accuracy:", round(model.score(X_test, y_test) * 100, 2), "%")
