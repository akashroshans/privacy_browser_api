from fastapi import FastAPI
from pydantic import BaseModel
import joblib
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"],  
)

class BrowserInput(BaseModel):
    obfuscated_code_percentage: float
    suspicious_api_calls: int
    eval_usage_count: int
    external_script_loads: int
    third_party_requests: int
    tracking_domains_count: int
    data_sent_size_kb: float
    encrypted_requests_ratio: float
    hidden_elements_count: int
    fingerprinting_attempts: int
    auto_redirects: int
    popup_frequency: int

model_privacy = joblib.load("model_privacy.pkl")
model_malicious = joblib.load("model_malicious.pkl")
model_confidence = joblib.load("model_confidence.pkl")
model_intensity = joblib.load("model_intensity.pkl")
model_threats = joblib.load("model_threats.pkl")

le_intensity = joblib.load("enc_intensity.pkl")
mlb_threats = joblib.load("enc_threats.pkl")

@app.post("/predict")
def predict(data: BrowserInput):
    features = [[
        data.obfuscated_code_percentage,
        data.suspicious_api_calls,
        data.eval_usage_count,
        data.external_script_loads,
        data.third_party_requests,
        data.tracking_domains_count,
        data.data_sent_size_kb,
        data.encrypted_requests_ratio,
        data.hidden_elements_count,
        data.fingerprinting_attempts,
        data.auto_redirects,
        data.popup_frequency
    ]]

    return {
        "privacy_risk_score": round(model_privacy.predict(features)[0], 2),
        "malicious_probability": round(model_malicious.predict(features)[0], 2),
        "confidence_level": round(model_confidence.predict(features)[0], 2),
        "tracking_intensity": le_intensity.inverse_transform(model_intensity.predict(features))[0],
        "primary_threats": mlb_threats.inverse_transform(model_threats.predict(features))[0]
    }
