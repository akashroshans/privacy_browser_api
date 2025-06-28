import pandas as pd
import json

with open("simulated_browser_data.json", "r") as f:
    data = json.load(f)

for d in data:
    d["primary_threats"] = ",".join(d["primary_threats"])

df = pd.DataFrame(data)
df.to_csv("browser_training_data.csv", index=False)

print(" Data organized and saved as browser_training_data.csv")
