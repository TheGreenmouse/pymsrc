import requests
import json
from datetime import datetime, timedelta

def get_vulnerabilities_by_date(year, month):
    # Format the date parameters
    start_date = f"{year}-{month:02d}-01T00:00:00Z"
    end_date = f"{year}-{month:02d}-{(datetime(year, month+1, 1) - timedelta(days=1)).day}T23:59:59Z"

    # Base URL for the MSRC API
    base_url = "https://api.msrc.microsoft.com/sug/v2.0/en-us/vulnerability"

    # Parameters for the API request
    params = {
        "$filter": f"releaseDate ge {start_date} and releaseDate le {end_date}"
    }

    # Headers for the API request
    headers = {
        "Accept": "application/json",
        #"api-key": "YOUR_API_KEY"  # Replace with your actual API key
    }

    # Make the request to the MSRC API
    response = requests.get(base_url, headers=headers, params=params)

    # Check if the request was successful
    if response.status_code == 200:
        vulnerabilities = response.json()
        return vulnerabilities
    else:
        print(f"Error: {response.status_code}")
        return None

# Example usage
year = 2023
month = 5
vulnerabilities = get_vulnerabilities_by_date(year, month)

if vulnerabilities:
    print(json.dumps(vulnerabilities, indent=4))
