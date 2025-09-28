import pandas as pd
from feature_extractor import extract_url_features
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load dataset
df = pd.read_csv("../data/master_urls.csv")
df = df.dropna(subset=["url", "label"])
df['label'] = df['label'].astype(int)

# Extract features
rows = [extract_url_features(u) for u in df['url']]
X = pd.DataFrame(rows)
y = df['label']

# One-hot encode suffix
X = pd.get_dummies(X, columns=["suffix"])

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save model and expected columns
joblib.dump(model, "url_model.pkl")
joblib.dump(list(X.columns), "model_columns.pkl")

print("✅ Model trained and saved as url_model.pkl")
print("📂 Feature columns saved as model_columns.pkl")
print("Test Accuracy:", model.score(X_test, y_test))
