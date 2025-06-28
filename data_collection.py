import random
import json

def generate_browser_input():
    return {
        "obfuscated_code_percentage": round(random.uniform(0, 100), 2),
        "suspicious_api_calls": random.randint(0, 10),
        "eval_usage_count": random.randint(0, 5),
        "external_script_loads": random.randint(0, 8),
        "third_party_requests": random.randint(0, 20),
        "tracking_domains_count": random.randint(0, 10),
        "data_sent_size_kb": round(random.uniform(0, 500), 2),
        "encrypted_requests_ratio": round(random.uniform(0.0, 1.0), 2),
        "hidden_elements_count": random.randint(0, 5),
        "fingerprinting_attempts": random.randint(0, 3),
        "auto_redirects": random.randint(0, 4),
        "popup_frequency": random.randint(0, 5)
    }

def generate_browser_output(input_data):
    risk = (
        input_data["obfuscated_code_percentage"] * 0.3 +
        input_data["suspicious_api_calls"] * 2 +
        input_data["tracking_domains_count"] * 3 +
        input_data["fingerprinting_attempts"] * 5 +
        input_data["popup_frequency"] * 4
    ) / 3
    risk = min(risk, 100)

    tracking_intensity = "low"
    if risk > 70:
        tracking_intensity = "high"
    elif risk > 40:
        tracking_intensity = "medium"

    malicious_prob = min(risk / 120, 1.0)
    confidence = round(random.uniform(0.7, 0.99), 2)

    threats = []
    if input_data["tracking_domains_count"] > 3:
        threats.append("tracking")
    if input_data["fingerprinting_attempts"] > 1:
        threats.append("fingerprinting")
    if malicious_prob > 0.6:
        threats.append("malware")

    return {
        "privacy_risk_score": round(risk, 2),
        "tracking_intensity": tracking_intensity,
        "malicious_probability": round(malicious_prob, 2),
        "confidence_level": confidence,
        "primary_threats": threats
    }


N = 1000
dataset = []

for _ in range(N):
    inp = generate_browser_input()
    out = generate_browser_output(inp)
    entry = {**inp, **out}
    dataset.append(entry)

with open("simulated_browser_data.json", "w") as f:
    json.dump(dataset, f, indent=2)

print(" Simulated data saved to simulated_browser_data.json")
