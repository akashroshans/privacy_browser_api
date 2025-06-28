import pandas as pd
import joblib
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, MultiLabelBinarizer

df = pd.read_csv("browser_training_data.csv")

X = df[[
    "obfuscated_code_percentage", "suspicious_api_calls", "eval_usage_count",
    "external_script_loads", "third_party_requests", "tracking_domains_count",
    "data_sent_size_kb", "encrypted_requests_ratio", "hidden_elements_count",
    "fingerprinting_attempts", "auto_redirects", "popup_frequency"
]]

df["primary_threats"] = df["primary_threats"].fillna("").astype(str)
df["primary_threats"] = df["primary_threats"].apply(lambda x: x.split(',') if x else [])

y_privacy_risk = df["privacy_risk_score"]
y_malicious_prob = df["malicious_probability"]
y_confidence = df["confidence_level"]

le_intensity = LabelEncoder()
y_intensity = le_intensity.fit_transform(df["tracking_intensity"])
joblib.dump(le_intensity, "enc_intensity.pkl")

mlb_threats = MultiLabelBinarizer()
y_threats = mlb_threats.fit_transform(df["primary_threats"])
joblib.dump(mlb_threats, "enc_threats.pkl")

X_train, X_test, y_privacy_train, y_privacy_test = train_test_split(
    X, y_privacy_risk, test_size=0.2, random_state=42
)
_, _, y_malicious_train, _ = train_test_split(
    X, y_malicious_prob, test_size=0.2, random_state=42
)
_, _, y_conf_train, _ = train_test_split(
    X, y_confidence, test_size=0.2, random_state=42
)
_, _, y_intensity_train, _ = train_test_split(
    X, y_intensity, test_size=0.2, random_state=42
)
_, _, y_threats_train, _ = train_test_split(
    X, y_threats, test_size=0.2, random_state=42
)

model_privacy = RandomForestRegressor().fit(X_train, y_privacy_train)
model_malicious = RandomForestRegressor().fit(X_train, y_malicious_train)
model_confidence = RandomForestRegressor().fit(X_train, y_conf_train)
model_intensity = RandomForestClassifier().fit(X_train, y_intensity_train)
model_threats = MultiOutputClassifier(RandomForestClassifier()).fit(X_train, y_threats_train)

joblib.dump(model_privacy, "model_privacy.pkl")
joblib.dump(model_malicious, "model_malicious.pkl")
joblib.dump(model_confidence, "model_confidence.pkl")
joblib.dump(model_intensity, "model_intensity.pkl")
joblib.dump(model_threats, "model_threats.pkl")

print(" All models trained and saved successfully.")