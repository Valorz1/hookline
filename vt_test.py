import os

import requests
from dotenv import load_dotenv

# Read .env and make its values available, without the key ever being in the code
load_dotenv()
api_key = os.getenv("VT_API_KEY")

# The fingerprint of the Amazon PDF from sample-1014
sha256 = "73a0e5d5582ec223d1d4216df506c5ce6961948f76d39f73a84e966b607ea1b7"

response = requests.get(
    f"https://www.virustotal.com/api/v3/files/{sha256}",
    headers={"x-apikey": api_key},
    timeout=15,
)

print("Status:", response.status_code)
if response.ok:
    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    print(stats)